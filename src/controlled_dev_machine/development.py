"""Versioned rootless development sandbox with an explicit persistent Home.

Host configuration and application state are separate from this installed code.
Preparing a release never seeds credentials or rewrites existing user settings.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shlex
import subprocess
import sys
import time

import yaml

from .degraded_topology import build_compose
from .exit_monitor import atomic_json, refresh, validate_exit_config


def absolute(value: str, name: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/") or any(c in value for c in "\n\r\0%"):
        raise ValueError(f"{name} must be an unambiguous absolute path")
    if ".." in PurePosixPath(value).parts:
        raise ValueError(f"{name} must not traverse parents")
    return Path(value)


def relative(value: str) -> Path:
    if not isinstance(value, str):
        raise ValueError("relative mount paths must be strings")
    p = PurePosixPath(value)
    if p.is_absolute() or ".." in p.parts or str(p) in ("", ".") or any(c in value for c in "\n\r\0"):
        raise ValueError("mounts must name individual relative paths, never the whole host Home")
    return Path(value)


def load_config(path: Path) -> dict:
    raw = json.loads(path.read_text())
    required = {"schema_version", "release", "release_id", "private_root", "host_home", "target_home",
                "user", "uid", "gid", "project", "docker_context", "python", "uid_tools",
                "target_image", "gateway_image", "mapper_image", "identity_profile", "mounts", "exit"}
    optional = {"node_bin", "conda_root", "conda_env", "gpu", "extra_gpu_libraries", "trust_overlays",
                "ssh_files", "tmp_compat_path", "network_names", "network_addresses", "extra_groups", "retired_units", "interactive_exit_probe_url", "home_aliases", "external_mounts"}
    if not isinstance(raw, dict) or set(raw) - required - optional or required - set(raw):
        raise ValueError("deployment configuration fields are missing or unknown")
    if raw["schema_version"] != 2:
        raise ValueError("development configuration schema_version must be 2")
    for name in ("release", "private_root", "host_home", "target_home", "python", "uid_tools", "identity_profile"):
        absolute(raw[name], name)
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", raw["user"]):
        raise ValueError("invalid target username")
    for name in ("uid", "gid"):
        if type(raw[name]) is not int or raw[name] <= 0:
            raise ValueError("target UID/GID must be positive integers")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", raw["project"]):
        raise ValueError("invalid Compose project name")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", raw["docker_context"]):
        raise ValueError("invalid Docker context")
    if not re.fullmatch(r"[a-f0-9]{7,64}|[a-z0-9][a-z0-9.-]{0,63}", raw["release_id"]):
        raise ValueError("invalid release identifier")
    if raw.get("gpu", "all") not in ("all", "none"):
        raise ValueError("gpu must be all or none")
    if not isinstance(raw["mounts"], list):
        raise ValueError("mounts must be an explicit list")
    seen = set()
    protected = {".claude", ".claude.json", ".ssh", ".docker", ".git", ".local/share/docker",
                 ".config/systemd", ".config/controlled-dev-machine"}
    for item in raw["mounts"]:
        if not isinstance(item, dict) or set(item) - {"path", "source", "read_only", "required"} or "path" not in item:
            raise ValueError("invalid mount entry")
        name = str(relative(item["path"]))
        if name in seen or name in protected or any(name.startswith(p + "/") for p in protected):
            raise ValueError(f"duplicate or protected user mount: {name}")
        if any(name.startswith(p + "/") or p.startswith(name + "/") for p in seen):
            raise ValueError("overlapping data mounts require one explicit parent entry")
        seen.add(name)
        if "source" in item:
            source = absolute(item["source"], "mount source")
            if source != Path(raw["private_root"]) / "data" / name:
                raise ValueError("local data overrides must use private_root/data at the same relative path")
    for name in raw.get("home_aliases", []):
        alias = absolute(name, "home alias")
        if alias.parent != Path('/home') or alias == Path(raw['target_home']):
            raise ValueError("legacy Home aliases must be distinct direct children of /home")
    for item in raw.get("external_mounts", []):
        if set(item) - {"source", "target", "read_only", "required"} or not {"source", "target"} <= set(item):
            raise ValueError("invalid external data mount")
        source, target = absolute(item["source"], "external source"), absolute(item["target"], "external target")
        roots = [Path(x) for x in ("/data", "/local", "/mnt", "/srv", "/home/shared")]
        if source != target or not any(target == root or target.is_relative_to(root) for root in roots):
            raise ValueError("external mounts must preserve an explicit data path")
        protected = [Path(raw[x]) for x in ("private_root", "host_home", "target_home")]
        if any(source == p or source.is_relative_to(p) or p.is_relative_to(source) for p in protected):
            raise ValueError("external data must not expose a Home or control directory")
    for name in ("node_bin", "conda_root"):
        if name in raw:
            relative(raw[name])
    for group in raw.get("extra_groups", []):
        if type(group) is not int or group < 0:
            raise ValueError("extra_groups must contain numeric GIDs")
    for unit in raw.get("retired_units", []):
        if not isinstance(unit, str) or not unit.startswith(raw["project"] + "-") or not unit.endswith(".service") or "/" in unit:
            raise ValueError("only this project's explicitly named old units can be retired")
    if raw.get("interactive_exit_probe_url"):
        from urllib.parse import urlsplit
        url = urlsplit(raw["interactive_exit_probe_url"])
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.fragment:
            raise ValueError("interactive exit probe must be a credential-free HTTP(S) URL")
    raw["exit"] = validate_exit_config(raw["exit"])
    return raw


def bind(source: Path | str, target: Path | str, read_only=True) -> dict:
    return {"type": "bind", "source": str(source), "target": str(target), "read_only": read_only,
            "bind": {"create_host_path": False}}


def write_file(path: Path, content: str, mode=0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError(f"refusing to overwrite a configuration symlink: {path}")
    if path.exists() and path.read_text() == content:
        path.chmod(mode)
        return
    tmp = path.with_name(path.name + ".new")
    if tmp.exists() or tmp.is_symlink():
        tmp.unlink()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)


def install_entry(path: Path, content: str) -> None:
    """Replace the directory entry, never write through a vendor-owned symlink."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".cdm-new")
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    write_file(temporary, content, 0o755)
    os.replace(temporary, path)


class DevelopmentSandbox:
    def __init__(self, config_path: Path):
        self.config_path = config_path.resolve()
        self.config = c = load_config(self.config_path)
        self.release = Path(c["release"])
        self.private = Path(c["private_root"])
        self.state = self.private / "control"
        self.apps = self.private / "apps"
        self.home = Path(c["host_home"])
        self.target_home = Path(c["target_home"])
        self.project = c["project"]
        self.target = self.project + "-target-1"
        self.compose_path = self.state / "compose.yaml"
        self.unit_dir = self.home / ".config/systemd/user"
        self.identity = json.loads(Path(c["identity_profile"]).read_text())
        self.docker = ["docker", "--context", c["docker_context"]]
        self.python = c["python"]
        self.config_sha = hashlib.sha256(self.config_path.read_bytes()).hexdigest()
        self.admitted = False
        for key in ("hostname", "machine_id", "mac_address", "timezone", "lang", "lc_all", "boot_id", "hostid"):
            if not self.identity.get(key):
                raise ValueError(f"missing identity field: {key}")
        if not re.fullmatch(r"[a-f0-9]{32}", self.identity["machine_id"]):
            raise ValueError("invalid persistent machine ID")
        if not re.fullmatch(r"[a-f0-9-]{36}", self.identity["boot_id"]):
            raise ValueError("invalid display boot ID")

    def run(self, args, *, check=True, capture=True, **kwargs):
        environment = dict(os.environ, DOCKER_CONTEXT=self.config["docker_context"],
                           XDG_RUNTIME_DIR=f"/run/user/{os.getuid()}",
                           DBUS_SESSION_BUS_ADDRESS=f"unix:path=/run/user/{os.getuid()}/bus")
        environment.update(kwargs.pop("env", {}))
        return subprocess.run([str(x) for x in args], check=check, capture_output=capture,
                              text=True, env=environment, **kwargs)

    def compose(self, *args, **kwargs):
        return self.run(self.docker + ["compose", "-p", self.project, "-f", str(self.compose_path), *args], **kwargs)

    @contextmanager
    def lock(self):
        self.state.mkdir(parents=True, exist_ok=True)
        with (self.state / "lifecycle.lock").open("a") as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("another sandbox lifecycle operation is already running") from exc
            yield

    def native_host_path(self):
        entry = self.apps / "home/.local/bin/claude"
        if not entry.is_symlink():
            return entry
        target = Path(os.readlink(entry))
        if target.is_absolute():
            try:
                return self.apps / "home" / target.relative_to(self.target_home)
            except ValueError as exc:
                raise RuntimeError("native CLI link points outside the persistent sandbox Home") from exc
        return entry.parent / target

    def validate_host(self):
        account = pwd.getpwuid(os.getuid())
        if Path(account.pw_dir) != self.home:
            raise RuntimeError("configuration does not belong to this host user")
        for p in (self.private, self.apps):
            if p.is_symlink() or (p.exists() and p.stat().st_uid != os.getuid()):
                raise RuntimeError(f"unsafe private state owner or symlink: {p}")
        required = [self.release / "src/controlled_dev_machine/development.py",
                    Path(self.config["uid_tools"]) / "usr/bin/bindfs",
                    self.apps / ".claude", self.apps / ".claude.json",
                    self.native_host_path()]
        for p in required:
            if not p.exists():
                raise RuntimeError(f"required preserved application/tool state is missing: {p}")
        for item in self.config["mounts"]:
            p = Path(item.get("source", self.home / item["path"]))
            if item.get("required", True) and not p.exists():
                raise RuntimeError(f"required data mount is missing: {p}")
        for item in self.config.get("external_mounts", []):
            p = Path(item["source"])
            if not p.exists() and not item.get("required", True):
                continue
            if p.is_symlink() or not p.is_dir() or p.stat().st_uid not in (0, os.getuid()) or not os.access(p, os.R_OK | os.X_OK):
                raise RuntimeError(f"external data root is not an accessible owned/shared directory: {p}")
        if not (self.home / ".ssh/config").is_file():
            raise RuntimeError("host SSH configuration is missing")
        for key, name in self.config.get("network_names", {}).items():
            if key not in ("target_net", "upstream_net"):
                raise RuntimeError("only internal networks can be reused")
            network = json.loads(self.run(self.docker + ["network", "inspect", name]).stdout)[0]
            if not network["Internal"] or network.get("EnableIPv6"):
                raise RuntimeError("configured target/upstream network is not isolated IPv4")
        # Rootless daemon identity must agree with the explicit host context.
        info = json.loads(self.run(self.docker + ["info", "--format", "{{json .SecurityOptions}}"]).stdout)
        if not any("rootless" in value for value in info):
            raise RuntimeError("this controller requires the configured rootless Docker daemon")

    def network_addresses(self):
        return self.config.get("network_addresses", {"dns_target": "172.31.0.22", "gateway_target": "172.31.0.23",
            "target": "172.31.0.24", "dns_upstream": "172.31.1.22", "gateway_upstream": "172.31.1.23", "egress": "172.31.1.30"})

    def shell_content(self):
        c, p = self.config, self.identity
        node = str(self.target_home / c.get("node_bin", ".nvm/versions/node/v22.18.0/bin"))
        conda = str(self.target_home / c.get("conda_root", "miniconda3"))
        env = c.get("conda_env", "base")
        paths = f"/opt/sbc/bin:{node}:{self.target_home}/.local/bin:{conda}/envs/{env}/bin:{conda}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        exports = {"PATH": paths, "LANG": p["lang"], "LC_ALL": p["lc_all"], "TZ": p["timezone"],
                   "CLAUDE_CONFIG_DIR": str(self.target_home / ".claude"), "CODEX_HOME": str(self.target_home / ".codex"),
                   "CLAUDE_CODE_TMPDIR": "/var/tmp/claude-work", "PYTHONNOUSERSITE": "1",
                   "CDM_CONDA_ROOT": conda, "CDM_DEFAULT_CONDA_ENV": env,
                   "NODE_EXTRA_CA_CERTS": "/etc/ssl/certs/ca-certificates.crt",
                   "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt", "REQUESTS_CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt"}
        text = "# Generated configuration; the optional exit display runs only in interactive shells.\n"
        text += "\n".join(f"export {k}={shlex.quote(v)}" for k, v in exports.items()) + "\n"
        text += f'if [ -f {shlex.quote(conda + "/etc/profile.d/conda.sh")} ]; then . {shlex.quote(conda + "/etc/profile.d/conda.sh")}; fi\n'
        text += 'export HISTFILE="$HOME/.bash_history"\ncase $- in *i*) PS1="\\u@\\h:\\w\\$ ";; esac\n'
        text += '''case $- in
*i*)
    HISTCONTROL=ignoreboth
    shopt -s histappend checkwinsize
    if command -v dircolors >/dev/null 2>&1; then
        if [ -r "$HOME/.dircolors" ]; then eval "$(dircolors -b "$HOME/.dircolors")"; else eval "$(dircolors -b)"; fi
    fi
    alias ls='ls --color=auto' dir='dir --color=auto' vdir='vdir --color=auto'
    alias grep='grep --color=auto' fgrep='fgrep --color=auto' egrep='egrep --color=auto'
    alias ll='ls -alF' la='ls -A' l='ls -CF' lh='ls -lFh'
    alias ca='conda activate'
    alias cab="conda activate $CDM_DEFAULT_CONDA_ENV"
    if [ -r /usr/share/bash-completion/bash_completion ]; then
        . /usr/share/bash-completion/bash_completion
    elif [ -r /etc/bash_completion ]; then
        . /etc/bash_completion
    fi
    if [ -r "$HOME/.bash_aliases" ]; then . "$HOME/.bash_aliases"; fi
    ;;
esac
'''
        if c.get("interactive_exit_probe_url"):
            proxy = "http://" + self.network_addresses()["gateway_target"] + ":8080"
            command = shlex.join(["curl", "-4", "--fail", "--silent", "--show-error", "--proxy", proxy,
                                  "--noproxy", "", "--connect-timeout", "2", "--max-time", "5", c["interactive_exit_probe_url"]])
            text += "case $- in *i*) ( " + command + "; printf '\\n' ) & ;; esac\n"

        return text, exports

    def render(self):
        c, p = self.config, self.identity
        policy = self.release / "policies/daily/0001-public-web.yaml"
        document = build_compose(root=self.release, runtime=self.apps, state=self.state,
            target_image=c["target_image"], gateway_image=c["gateway_image"], policy=policy,
            policy_digest="raw:" + hashlib.sha256(policy.read_bytes()).hexdigest(),
            upstream_host=c["exit"]["parent_host"], upstream_port=str(c["exit"]["parent_port"]), allow_public_dns=True)
        a = self.network_addresses()
        mapping = {"172.31.0.2": a["dns_target"], "172.31.0.3": a["gateway_target"], "172.31.0.4": a["target"],
                   "172.31.1.2": a["dns_upstream"], "172.31.1.3": a["gateway_upstream"], "172.31.1.10": a["egress"]}
        encoded = re.sub(r"(?<![0-9.])172\.31\.[01]\.(?:2|3|4|10)(?![0-9.])",
                         lambda m: mapping[m[0]], json.dumps(document))
        document = json.loads(encoded)
        document["name"] = self.project
        names = c.get("network_names", {})
        for key in ("target_net", "upstream_net"):
            if key in names:
                document["networks"][key] = {"external": True, "name": names[key]}
        services = document["services"]
        for service in services.values():
            service["logging"] = {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}}
            service.setdefault("labels", {}).update({"org.controlled-dev-machine.release": c["release_id"],
                "org.controlled-dev-machine.config-sha256": self.config_sha})
        egress = services["egress"]
        egress["environment"].update(CDM_RELAY_EXPECTED_EXIT=c["exit"]["expected_exit"], CDM_RELAY_EXIT_LEASE="/run/cdm-exit/lease.json")
        egress["volumes"].append(bind(self.state / "exit-control", "/run/cdm-exit"))
        target = services["target"]
        target.update(hostname=p["hostname"], user=f'{c["uid"]}:{c["gid"]}', working_dir=str(self.target_home))
        target["networks"]["target_net"]["mac_address"] = p["mac_address"]
        target["group_add"] = [str(x) for x in c.get("extra_groups", [])]
        _, exports = self.shell_content()
        target["environment"].update(exports, USER=c["user"], LOGNAME=c["user"], HOME=str(self.target_home),
            HOSTNAME=p["hostname"], CDM_RELEASE_ID=c["release_id"], LD_LIBRARY_PATH="/run/cdm-nvidia")
        for key in ("DISABLE_UPDATES", "ENABLE_CLAUDEAI_MCP_SERVERS", "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL", "CONDA_DEFAULT_ENV"):
            target["environment"].pop(key, None)
        appview, hostview = self.private / "uid-app/view", self.private / "uid-home/view"
        volumes = [bind(appview / "home", self.target_home, False),
                   bind(appview / ".claude", self.target_home / ".claude", False),
                   bind(appview / ".claude.json", self.target_home / ".claude.json", False),
                   bind(appview / ".bash_history", self.target_home / ".bash_history", False),
                   bind(appview / "ssh", self.target_home / ".ssh"),
                   bind(appview / "claude-work", "/var/tmp/claude-work", False)]
        if c.get("tmp_compat_path"):
            volumes.append(bind(appview / "claude-work", absolute(c["tmp_compat_path"], "tmp_compat_path"), False))
        for item in c["mounts"]:
            source = Path(item.get("source", self.home / item["path"]))
            if source.exists():
                mapped = hostview / item["path"] if "source" not in item else self.private / "uid-data/view" / item["path"]
                volumes.append(bind(mapped, self.target_home / item["path"], item.get("read_only", False)))
        config_files = {"passwd": "/etc/passwd", "group": "/etc/group", "bashrc": str(self.target_home / ".bashrc"),
            "profile": str(self.target_home / ".profile"),
            "bash_profile": str(self.target_home / ".bash_profile"),
            "sandbox.json": "/run/cdm/sandbox.json"}
        volumes += [bind(self.state / "config" / name, dest) for name, dest in config_files.items()]
        volumes += [bind(self.state / "machine-id", "/etc/machine-id"), bind(self.state / "machine-id", "/var/lib/dbus/machine-id"),
                    bind(self.state / "ssh", "/run/cdm-ssh"), bind(self.release / "src", "/opt/cdm-ssh"),
                    bind(self.state / "trust/ca-certificates.crt", "/etc/ssl/certs/ca-certificates.crt")]
        fleet = self.state / "ssh/fleet-identity"
        for name, destinations in {"hostname": ["/etc/hostname"], "hostid": ["/etc/hostid"], "timezone": ["/etc/timezone"],
                "localtime": ["/etc/localtime"], "locale": ["/etc/locale.conf", "/etc/default/locale"]}.items():
            volumes += [bind(fleet / name, dest) for dest in destinations]
        if c.get("gpu", "all") == "all":
            volumes += [v for v in target["volumes"] if str(v["target"]).startswith("/run/cdm-nvidia/") or v["target"] == "/usr/local/bin/nvidia-smi"]
            for name in c.get("extra_gpu_libraries", []):
                source = Path("/usr/lib/x86_64-linux-gnu") / name
                if source.exists():
                    volumes.append(bind(source, "/run/cdm-nvidia/" + name))
        else:
            target["devices"] = []
            target["environment"]["NVIDIA_VISIBLE_DEVICES"] = "void"
        for name in c.get("trust_overlays", []):
            if (self.home / name).is_file():
                volumes.append(bind(self.state / "trust/ca-certificates.crt", self.target_home / name))
        # NVM remains the user's environment, but its Claude entry goes through the image-owned launcher.
        volumes.append(bind(self.release / "bin/claude-in-sandbox", self.target_home / c.get("node_bin", ".nvm/versions/node/v22.18.0/bin") / "claude"))
        for alias in c.get("home_aliases", []):
            for volume in list(volumes):
                destination = Path(volume["target"])
                if destination == self.target_home or destination.is_relative_to(self.target_home):
                    volumes.append(dict(volume, target=str(Path(alias) / destination.relative_to(self.target_home))))
        for index, item in enumerate(c.get("external_mounts", [])):
            if Path(item["source"]).exists():
                volumes.append(bind(self.private / f"uid-extra-{index}/view", item["target"], item.get("read_only", False)))
        for hidden in ("/root", "/home/gzy"):
            if hidden != str(self.target_home) and hidden not in c.get("home_aliases", []):
                volumes.append(bind(self.state / "empty", hidden))
        targets = [v["target"] for v in volumes]
        if len(targets) != len(set(targets)):
            raise RuntimeError("duplicate target mount")
        if any(v["source"] == str(hostview) for v in volumes):
            raise RuntimeError("whole host Home must never be mounted")
        target["volumes"] = volumes
        return document

    def prepare_mountpoints(self):
        """Create empty destinations without hiding pre-existing private Home data."""
        home = self.apps / "home"
        for item in self.config["mounts"]:
            source, destination = Path(item.get("source", self.home / item["path"])), home / item["path"]
            if not source.exists():
                continue
            if destination.is_symlink():
                raise RuntimeError(f"mount destination is a symlink: {destination}")
            if source.is_dir():
                if destination.exists() and any(destination.iterdir()):
                    raise RuntimeError(f"new mount would hide private Home files: {destination}")
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                if not destination.exists():
                    destination.touch(mode=0o600)
        for name in [".claude", ".ssh"]:
            (home / name).mkdir(parents=True, exist_ok=True)
        for name in [".claude.json", ".bash_history", ".bashrc", ".profile", ".bash_profile"]:
            destination = home / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists() and not destination.is_symlink():
                destination.touch(mode=0o600)

    def prepare(self):
        self.validate_host()
        for part in ("config", "config/units", "logs", "ssh", "ssh/fleet-identity", "exit-control", "empty",
                     "audit/review", "audit/plaintext", "audit/dns", "audit/egress", "audit/ssh", "dns-control", "trust"):
            p = self.state / part
            if p.is_symlink():
                raise RuntimeError(f"control directory is a symlink: {p}")
            p.mkdir(parents=True, exist_ok=True)
        (self.state / "empty").chmod(0o555)
        (self.state / "ssh").chmod(0o755)
        for name in ("home", "claude-work"):
            (self.apps / name).mkdir(parents=True, exist_ok=True)
        if not (self.apps / ".bash_history").exists():
            write_file(self.apps / ".bash_history", "")
        c, p = self.config, dict(self.identity, target_address=self.network_addresses()["target"])
        for kind in ("passwd", "group"):
            baseline = self.state / "baseline" / ("etc__" + kind)
            if not baseline.exists():
                raise RuntimeError(f"preserved system baseline is missing: {baseline}")
            lines = baseline.read_text().splitlines()
            number = c["uid"] if kind == "passwd" else c["gid"]
            lines = [l for l in lines if l.split(":")[0] not in (c["user"], "gzy") and l.split(":")[2] != str(number)]
            lines.append(f'{c["user"]}:x:{c["uid"]}:{c["gid"]}:Development user:{self.target_home}:/bin/bash' if kind == "passwd" else f'{c["user"]}:x:{c["gid"]}:')
            if kind == "group":
                group_ids = {int(line.split(":")[2]) for line in lines}
                for group_id in c.get("extra_groups", []):
                    if group_id not in group_ids:
                        name = f"cdm{group_id}"
                        if any(line.split(":")[0] == name for line in lines):
                            raise ValueError("supplementary group name conflicts with preserved baseline")
                        lines.append(f"{name}:x:{group_id}:")
                        group_ids.add(group_id)
            write_file(self.state / "config" / kind, "\n".join(lines) + "\n", 0o644)
        shell, _ = self.shell_content()
        write_file(self.state / "config/bashrc", shell, 0o644)
        for name in ("profile", "bash_profile"):
            write_file(self.state / "config" / name, '. "$HOME/.bashrc"\n', 0o644)
        from .ssh_client_state import SSHClientState
        SSHClientState(self.home / ".ssh", self.apps / "ssh", self.target_home).refresh()
        write_file(self.state / "machine-id", p["machine_id"] + "\n", 0o444)
        fleet = self.state / "ssh/fleet-identity"
        for name, value in {"profile.json": json.dumps(p), "hostname": p["hostname"], "boot-id": p["boot_id"],
                            "timezone": p["timezone"], "locale": f'LANG={p["lang"]}\nLC_ALL={p["lc_all"]}'}.items():
            write_file(fleet / name, value.rstrip() + "\n", 0o444)
        for name, data in {"hostid": int(p["hostid"], 16).to_bytes(4, "little"),
                           "localtime": (Path("/usr/share/zoneinfo") / p["timezone"]).read_bytes()}.items():
            path = fleet / name
            if not path.exists() or path.read_bytes() != data:
                if path.exists():
                    path.chmod(0o600)
                path.write_bytes(data)
            path.chmod(0o444)
        atomic_json(self.state / "config/sandbox.json", {"release": c["release_id"], "config_sha256": self.config_sha}, 0o444)
        exit_config = dict(c["exit"], exit_lease=str(self.state / "exit-control/lease.json"),
            readiness_path=str(self.state / "readiness.json"), required_config_sha256=self.config_sha)
        atomic_json(self.state / "config/exit-monitor.json", exit_config)
        document = self.render()
        write_file(self.compose_path, yaml.safe_dump(document, sort_keys=False))
        atomic_json(self.state / "deployment.json", {"schema_version": 2, "release_id": c["release_id"],
            "release": str(self.release), "config_path": str(self.config_path), "config_sha256": self.config_sha,
            "target": self.target, "expected_exit": c["exit"]["expected_exit"], "home_source": str(self.apps / "home"),
            "audit_boundary": "rootless application DNS/Web/SSH audit; no host nft/eBPF/PCAP"})
        self.prepare_mountpoints()
        self.compose("config", "--quiet")

    def controller_args(self, command):
        return [self.python, "-I", str(self.release / "bin/development-sandbox"), "--config", str(self.config_path), command]

    def install_units(self):
        q = lambda args: shlex.join([str(x) for x in args]).replace("%", "%%")
        ssh = [self.python, "-I", str(self.release / "src/controlled_dev_machine/ssh_alias_bridge.py"), "serve",
               "--socket", str(self.state / "ssh/alias.sock"), "--agent-socket", str(self.state / "ssh/campus-agent.sock"),
               "--config", str(self.home / ".ssh/config"), "--audit", str(self.state / "audit/ssh/aliases.jsonl"),
               "--client-directory", str(self.apps / "ssh"), "--client-home", str(self.target_home)]
        units = {
            self.project + ".service": f'[Unit]\nDescription=Versioned development sandbox\nRequires=docker.service\nWants={self.project}-ssh.service\nAfter=docker.service {self.project}-ssh.service\nPartOf=docker.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart={q(self.controller_args("start"))}\nTimeoutStartSec=240\n\n[Install]\nWantedBy=default.target\n',
            self.project + "-ssh.service": f'[Unit]\nDescription=Configured SSH aliases and fixed agent for sandbox\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={q(ssh)}\nRestart=on-failure\nRestartSec=3\n\n[Install]\nWantedBy=default.target\n',
            self.project + "-exit-monitor.service": f'[Unit]\nDescription=Strict configured-exit lease monitor\nAfter=docker.service\n\n[Service]\nType=simple\nExecStart={q(self.controller_args("exit-monitor"))}\nRestart=on-failure\nRestartSec=1\n\n[Install]\nWantedBy=default.target\n',
            self.project + "-health.service": f'[Unit]\nDescription=Verify sandbox mounts and identity without rewriting user state\nAfter=docker.service\n\n[Service]\nType=oneshot\nExecStart={q(self.controller_args("health"))}\nTimeoutStartSec=60\n',
            self.project + "-health.timer": f'[Unit]\nDescription=Check sandbox lifecycle readiness\nPartOf={self.project}.service\n\n[Timer]\nOnBootSec=10s\nOnUnitInactiveSec=10s\nAccuracySec=1s\nUnit={self.project}-health.service\n\n[Install]\nWantedBy=timers.target\n',
        }
        for name, text in units.items():
            write_file(self.unit_dir / name, text, 0o644)
            write_file(self.state / "config/units" / name, text, 0o644)
        self.run(["systemctl", "--user", "daemon-reload"])
        for unit in self.config.get("retired_units", []):
            self.run(["systemctl", "--user", "disable", "--now", unit], check=False)

    def mapper(self, source: Path, part: str):
        from . import rootless_uid_mount as uid_module
        c = self.config
        directory, name = self.private / part, self.project + "-" + part
        command = [self.python, "-I", str(self.release / "src/controlled_dev_machine/rootless_uid_mount.py")]
        options = ["--source", str(source), "--view", str(directory / "view"), "--state", str(directory),
                   "--tools", c["uid_tools"], "--image", c["mapper_image"], "--name", name, "--uid", str(c["uid"]), "--gid", str(c["gid"])]
        shared_root = source.stat().st_uid != os.getuid()
        if shared_root:
            options.append("--allow-shared-root")
        if self.run(command + ["status"] + options, check=False).returncode == 0:
            return False
        current = self.run(self.docker + ["inspect", name], check=False)
        if current.returncode == 0:
            info = json.loads(current.stdout)[0]
            expected_image = json.loads(self.run(self.docker + ["image", "inspect", c["mapper_image"]]).stdout)[0]["Id"]
            if info["Image"] != expected_image:
                raise RuntimeError("refusing to replace an unrelated UID mapper")
            self.run(self.docker + ["stop", "--time=10", name])
        uid_module.UID, uid_module.GID, uid_module.ALLOW_SHARED_ROOT = c["uid"], c["gid"], shared_root
        pids = self.run(["pgrep", "-u", str(os.getuid()), "-x", "dockerd"]).stdout.split()
        if len(pids) != 1:
            raise RuntimeError("exactly one rootless dockerd is required")
        helper = uid_module.helper_command("mapper", source=source, view=directory / "view", state=directory,
            tools=Path(c["uid_tools"]), daemon_pid=int(pids[0]), image=c["mapper_image"], name=name)
        helper.insert(2, "--detach")
        self.run(helper)
        for _ in range(60):
            if self.run(command + ["status"] + options, check=False).returncode == 0:
                return True
            time.sleep(0.5)
        raise RuntimeError("UID mapper did not become ready")

    def mapper_sources(self):
        result = [(self.home, "uid-home"), (self.apps, "uid-app")]
        if any("source" in item for item in self.config["mounts"]):
            result.append((self.private / "data", "uid-data"))
        for index, item in enumerate(self.config.get("external_mounts", [])):
            if Path(item["source"]).exists():
                result.append((Path(item["source"]), f"uid-extra-{index}"))
        return result

    def apply_identity(self):
        info = json.loads(self.run(self.docker + ["inspect", self.target]).stdout)[0]
        expected = {"container_id": info["Id"], "started_at": info["State"]["StartedAt"],
                    "profile_sha256": hashlib.sha256(Path(self.config["identity_profile"]).read_bytes()).hexdigest()}
        receipt = self.state / "fleet-live-receipt.json"
        if receipt.exists() and json.loads(receipt.read_text()) == expected:
            return
        script = (self.release / "target/apply_identity.py").read_text()
        self.run(["nsenter", "-t", str(info["State"]["Pid"]), "-U", "-m", "-u", "-n", "-p", "--root", "--wd=/", "--", "/usr/bin/python3", "-"], input=script)
        atomic_json(receipt, expected)

    def start(self):
        self.prepare()
        self.admitted = True
        self.install_units()
        # Preparation/admission failures above do not stop or close an existing instance.
        self.run(["systemctl", "--user", "stop", self.project + "-exit-monitor.service"], check=False)
        atomic_json(self.state / "readiness.json", {"ok": False, "config_sha256": self.config_sha})
        (self.state / "exit-control/lease.json").unlink(missing_ok=True)
        self.run(["systemctl", "--user", "enable", self.project + "-ssh.service"])
        self.run(["systemctl", "--user", "restart", self.project + "-ssh.service"])
        changed = False
        for source, part in self.mapper_sources():
            changed = self.mapper(source, part) or changed
        self.compose("up", "-d", "egress", "dns", "gateway")
        atomic_json(self.state / "readiness.json", {"ok": True, "config_sha256": self.config_sha, "phase": "network-ready"})
        lease = self.state / "exit-control/lease.json"
        value = refresh(self.config["exit"], publish=lambda value: atomic_json(lease, value))
        if not value["ok"]:
            raise RuntimeError("configured exit could not be verified; egress remains blocked")
        self.run(["systemctl", "--user", "enable", "--now", self.project + "-exit-monitor.service"])
        for _ in range(45):
            if self.compose("exec", "-T", "gateway", "python3", "-m", "controlled_dev_machine.gateway_health", check=False).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("gateway health gate failed")
        ca = self.compose("exec", "-T", "gateway", "cat", "/ca/mitmproxy-ca-cert.pem").stdout
        original = (self.state / "baseline/ca-certificates.crt").read_text()
        write_file(self.state / "trust/ca-certificates.crt", original.rstrip() + "\n" + ca, 0o644)
        self.compose("up", "-d", *(["--force-recreate"] if changed else []), "target")
        self.apply_identity()
        self.run(["systemctl", "--user", "enable", "--now", self.project + "-health.timer"])
        print(json.dumps(self.status()), flush=True)

    def health(self):
        current = self.run(self.docker + ["inspect", self.target], check=False)
        if current.returncode or not json.loads(current.stdout)[0]["State"]["Running"]:
            return False
        for source, part in self.mapper_sources():
            args = [self.python, "-I", str(self.release / "src/controlled_dev_machine/rootless_uid_mount.py"), "status",
                    "--source", str(source), "--view", str(self.private / part / "view"),
                    "--state", str(self.private / part), "--tools", self.config["uid_tools"], "--image", self.config["mapper_image"], "--name", self.project + "-" + part,
                    "--uid", str(self.config["uid"]), "--gid", str(self.config["gid"])]
            if source.stat().st_uid != os.getuid():
                args.append("--allow-shared-root")
            if self.run(args, check=False).returncode:
                atomic_json(self.state / "readiness.json", {"ok": False, "config_sha256": self.config_sha, "reason": "UID mapper not ready"})
                (self.state / "exit-control/lease.json").unlink(missing_ok=True)
                return False
        self.apply_identity()
        info = json.loads(current.stdout)[0]
        labels = info["Config"].get("Labels") or {}
        if labels.get("org.controlled-dev-machine.config-sha256") != self.config_sha:
            atomic_json(self.state / "readiness.json", {"ok": False, "config_sha256": self.config_sha, "reason": "runtime configuration drift"})
            return False
        atomic_json(self.state / "readiness.json", {"ok": True, "config_sha256": self.config_sha, "phase": "ready"})
        return True

    def status(self):
        c = self.config
        value = {"release": c["release_id"], "controller": str(self.release), "configuration": str(self.config_path),
                 "config_sha256": self.config_sha, "home_source": str(self.apps / "home"), "expected_exit": c["exit"]["expected_exit"],
                 "target": self.target, "audit_capabilities": ["dns", "http", "websocket", "ssh", "egress"], "host_packet_audit": False}
        result = self.run(self.docker + ["inspect", self.target], check=False)
        if result.returncode == 0:
            info = json.loads(result.stdout)[0]
            value.update(running=info["State"]["Running"], image_id=info["Image"], container_id=info["Id"],
                         actual_release=(info["Config"].get("Labels") or {}).get("org.controlled-dev-machine.release"))
        else:
            value["running"] = False
        try:
            lease = json.loads((self.state / "exit-control/lease.json").read_text())
            from .degraded_egress import RelayConfig, exit_lease_valid
            gate = RelayConfig(audit_path=self.state / "audit/egress/events.jsonl",
                expected_exit=c["exit"]["expected_exit"], exit_lease=self.state / "exit-control/lease.json",
                upstream_host=c["exit"]["parent_host"], upstream_port=c["exit"]["parent_port"])
            ready = json.loads((self.state / "readiness.json").read_text())
            value["exit_verified"] = exit_lease_valid(gate) and ready.get("ok") is True and ready.get("config_sha256") == self.config_sha
        except (OSError, ValueError, KeyError, TypeError):
            value["exit_verified"] = False
        return value

    def execute(self, args, root=False):
        tty = ["-it"] if sys.stdin.isatty() and sys.stdout.isatty() else ["-i"]
        work = os.getcwd()
        if self.run(self.docker + ["exec", self.target, "test", "-d", work], check=False).returncode:
            work = str(self.target_home)
        cmd = self.docker + ["exec", *tty, "--user", "0:0" if root else f'{self.config["uid"]}:{self.config["gid"]}',
                            "--workdir", work, self.target, *args]
        os.execvp(cmd[0], cmd)

    def install_entries(self):
        status = self.status()
        if not status.get("running") or status.get("actual_release") != self.config["release_id"] or not status.get("exit_verified"):
            raise RuntimeError("refusing to select an unverified or mismatched running release")
        command = shlex.join(self.controller_args("")[:-1])
        script = '#!/bin/sh\nexec ' + command + ' "$@"\n'
        entry = {"backend": "rootless-development", "uid": os.getuid(), "gid": os.getgid(), "home": str(self.home),
            "python": self.python, "controller": str(self.release / "bin/development-sandbox"),
            "config": str(self.config_path), "release_id": self.config["release_id"]}
        atomic_json(self.home / ".config/controlled-dev-machine/entry.json", entry)
        install_entry(self.home / ".local/bin/sbc", script)
        host_guard = '#!/bin/sh\n# Enter the configured sandbox; never run the vendor binary on the host.\nexec ' + shlex.quote(str(self.home / ".local/bin/sbc")) + ' claude "$@"\n'
        install_entry(self.home / ".local/bin/claude", host_guard)
        install_entry(self.home / self.config.get("node_bin", ".nvm/versions/node/v22.18.0/bin") / "claude", host_guard)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("command", nargs="?", default="shell")
    parser.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    app = DevelopmentSandbox(args.config)
    if args.command in ("prepare", "start", "recover", "install-entries", "install-units", "stop"):
        with app.lock():
            if args.command == "prepare":
                app.prepare()
            elif args.command in ("start", "recover"):
                try:
                    app.start()
                except Exception:
                    if app.admitted:
                        atomic_json(app.state / "readiness.json", {"ok": False, "config_sha256": app.config_sha, "reason": "startup failed"})
                        (app.state / "exit-control/lease.json").unlink(missing_ok=True)
                    raise
            elif args.command == "install-entries":
                app.install_entries()
            elif args.command == "install-units":
                app.install_units()
            else:
                app.compose("stop")
    elif args.command == "exit-monitor":
        from .exit_monitor import main as monitor_main
        return monitor_main(["--config", str(app.state / "config/exit-monitor.json")])
    elif args.command == "exit-check":
        result = refresh(app.config["exit"], publish=lambda value: atomic_json(app.state / "exit-control/lease.json", value))
        print(json.dumps({"ok": result["ok"], "reason": result["reason"]}))
        return 0 if result["ok"] else 1
    elif args.command in ("status", "doctor"):
        print(json.dumps(app.status(), indent=2))
    elif args.command in ("health", "monitor"):
        try:
            with app.lock():
                try:
                    return 0 if app.health() else 1
                except Exception:
                    atomic_json(app.state / "readiness.json", {"ok": False, "config_sha256": app.config_sha, "reason": "health check failed"})
                    (app.state / "exit-control/lease.json").unlink(missing_ok=True)
                    raise
        except RuntimeError as error:
            if str(error) == "another sandbox lifecycle operation is already running":
                return 0
            raise
    elif args.command in ("shell", "root", "root-shell"):
        app.execute(["/bin/bash", "--login", *args.args], args.command != "shell")
    elif args.command == "exec":
        if not args.args:
            parser.error("exec requires a command")
        app.execute(args.args)
    elif args.command in ("claude", "codex"):
        app.execute(["/bin/bash", "--login", "-c", "exec " + shlex.join([args.command, *args.args])])
    elif args.command == "checkpoint":
        from .state_archive import checkpoint
        result = checkpoint(app.apps, app.private / "archive", label="manual", quiesced=not app.status()["running"])
        print(json.dumps({"path": result["path"], "consistent": result["consistent"], "files": len(result["files"])}))
        return 0 if result["consistent"] else 1
    elif args.command == "audit":
        print(app.state / "audit")
    else:
        parser.error("unknown command")
    return 0
