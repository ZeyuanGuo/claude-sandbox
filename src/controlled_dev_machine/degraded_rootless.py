"""Rootless runtime with an isolated target and fixed-parent egress relay."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

import yaml

from controlled_dev_machine.degraded_topology import build_compose


def recovery() -> Path:
    return Path(os.environ.get("CDM_DEGRADED_RECOVERY", Path.home() / "5090-recovery")).expanduser()


def repo() -> Path:
    return Path(os.environ.get("CDM_DEGRADED_REPO", recovery() / "priority-home/claude-sandbox")).expanduser()


def state() -> Path:
    return Path(os.environ.get("CDM_DEGRADED_STATE", Path.home() / ".local/state/claude-sandbox-degraded")).expanduser()


def runtime() -> Path:
    return Path(os.environ.get("CDM_DEGRADED_RUNTIME", Path.home() / "5090-runtime")).expanduser()


def policy_path() -> Path:
    return Path(os.environ.get("CDM_DEGRADED_POLICY", repo() / "policies/strict/0001-bootstrap.yaml")).expanduser()


def docker(*args: str, capture: bool = False, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], text=True, capture_output=capture, check=check)


def write_state(name: str, value: object) -> None:
    state().mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=state(), delete=False) as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    temporary.replace(state() / name)


def image_exists(ref: str) -> bool:
    return docker("image", "inspect", ref, capture=True, check=False).returncode == 0


def image_digest(ref: str) -> str:
    return docker("image", "inspect", ref, "--format", "{{.Id}}", capture=True).stdout.strip()


def source_digest(root: Path, policy: Path) -> str:
    paths = [policy, root / "gateway/mitmproxy/cdm_addon.py",
             root / "gateway/mitmproxy/entrypoint.sh", root / "images/gateway/Dockerfile.degraded"]
    paths.extend(sorted((root / "src").rglob("*.py")))
    digest = hashlib.sha256()
    for path in sorted(set(paths)):
        name = path.relative_to(root) if path.is_relative_to(root) else path
        digest.update(str(name).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def doctor() -> int:
    result = docker("info", "--format", "{{json .SecurityOptions}}", capture=True, check=False)
    facts = {"mode": "rootless-degraded", "rootless_docker": "rootless" in result.stdout,
             "recovery_exists": recovery().is_dir(), "repo_exists": repo().is_dir(),
             "runtime_home_prepared": (runtime() / "home").is_dir(),
             "available": {"internal_network": True, "http_gateway": True,
                           "fixed_parent_relay": True, "application_audit": True},
             "unavailable": {"host_nftables": True, "host_ebpf": True, "host_pcap": True,
                             "transparent_redirect": True}}
    print(json.dumps(facts, indent=2))
    return 0 if result.returncode == 0 and facts["rootless_docker"] and facts["repo_exists"] else 2


def _decode_image(archive: Path, action: list[str]) -> None:
    decoder = subprocess.Popen(["zstd", "-dc", str(archive)], stdout=subprocess.PIPE)
    assert decoder.stdout is not None
    try:
        loaded = subprocess.run(["docker", *action], stdin=decoder.stdout)
    finally:
        decoder.stdout.close()
    decoded = decoder.wait()
    if loaded.returncode or decoded:
        raise SystemExit("image archive import failed")


def import_images() -> int:
    state().mkdir(mode=0o700, parents=True, exist_ok=True)
    with (state() / "import.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SystemExit("another image import is running; do not start a duplicate") from exc
        archive = recovery() / "containers/latest-verified"
        base, target = "cdm-degraded-base:5090", "cdm-degraded-target:5090-rootfs"
        if not image_exists(base):
            _decode_image(archive / "base-images.tar.zst", ["load"])
            candidates = docker("image", "ls", "--all", "-q", "--no-trunc", capture=True).stdout.splitlines()
            for candidate in dict.fromkeys(candidates):
                probe = docker("run", "--rm", "--pull=never", "--network=none", "--cap-drop=ALL",
                               "--entrypoint=/bin/sh", candidate, "-c", "command -v mitmdump >/dev/null",
                               capture=True, check=False)
                if probe.returncode == 0:
                    docker("tag", candidate, base)
                    break
            else:
                raise SystemExit("archive has no mitmproxy gateway image")
        if not image_exists(target):
            _decode_image(archive / "target-rootfs.tar.zst", ["import", "-", target])
        write_state("images.json", {"target": target, "gateway_base": base,
                                   "target_digest": image_digest(target), "base_digest": image_digest(base)})
    return 0


def render() -> int:
    images = json.loads((state() / "images.json").read_text())
    parent = os.environ.get("CDM_DEGRADED_UPSTREAM_HOST", "").strip()
    port = os.environ.get("CDM_DEGRADED_UPSTREAM_PORT", "").strip()
    if bool(parent) != bool(port):
        raise SystemExit("parent IP and port must be configured together")
    if parent:
        ipaddress.ip_address(parent)
        if not port.isdecimal() or not 1 <= int(port) <= 65535:
            raise SystemExit("invalid parent port")
    policy = policy_path()
    digest = "raw:" + hashlib.sha256(policy.read_bytes()).hexdigest()
    code_digest = source_digest(repo(), policy)
    tag = "cdm-degraded-gateway:5090"
    label = docker("image", "inspect", tag, "--format",
                   '{{index .Config.Labels "cdm.source_digest"}}', capture=True, check=False)
    if label.returncode or label.stdout.strip() != code_digest:
        docker("build", "--pull=false", "--network=none", "--tag", tag,
               "--build-arg", f"BASE_IMAGE={images['gateway_base']}",
               "--build-arg", f"CODE_DIGEST={code_digest}",
               "--file", str(repo() / "images/gateway/Dockerfile.degraded"), str(repo()))
    for part in ("audit/review", "audit/plaintext", "audit/dns", "audit/egress", "dns-control", "proxy-ca", "trust"):
        (state() / part).mkdir(mode=0o700, parents=True, exist_ok=True)
    suffixes = tuple(x.strip() for x in os.environ.get("CDM_DEGRADED_DNS_SUFFIXES", "").split(",") if x.strip())
    strict_local = os.environ.get("CDM_DEGRADED_STRICT_LOCAL") == "1"
    project_root = runtime() / "projects"
    if not any((project_root / name).is_dir() for name in ("newdfm", "dfm")):
        # Avoid copying hundreds of GB a second time while the immutable
        # recovery tree is still the authoritative project mirror.  This
        # fallback is explicit in mode.json and can be replaced by a decoded
        # runtime/projects tree later without changing the container contract.
        project_root = recovery() / "home"
    document = build_compose(root=repo(), runtime=runtime(), state=state(),
                             target_image=images["target"], gateway_image=tag, policy=policy,
                             policy_digest=digest, upstream_host=parent, upstream_port=port,
                             dns_suffixes=suffixes, projects=project_root,
                             strict_local=strict_local)
    canary = os.environ.get("CDM_DEGRADED_LOCAL_CANARY") == "1"
    if canary:
        document["networks"].pop("egress_net", None)
        document["services"]["egress"]["networks"].pop("egress_net", None)
    path = state() / "compose.degraded.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False))
    path.chmod(0o600)
    write_state("mode.json", {"mode": "rootless-degraded", "source_digest": code_digest,
                               "policy_path": str(policy), "policy_digest": digest,
                               "target_image_digest": image_digest(images["target"]),
                               "gateway_image_digest": image_digest(tag),
                               "compose_digest": hashlib.sha256(path.read_bytes()).hexdigest(),
                               "project_root": str(project_root),
                               "upstream_configured": bool(parent), "local_canary": canary,
                               "strict_local": strict_local})
    print(path)
    return 0


def validate_render() -> dict:
    mode = json.loads((state() / "mode.json").read_text())
    path = state() / "compose.degraded.yaml"
    if source_digest(repo(), Path(mode["policy_path"])) != mode["source_digest"]:
        raise SystemExit("source/policy drift: render again")
    if hashlib.sha256(path.read_bytes()).hexdigest() != mode["compose_digest"]:
        raise SystemExit("compose drift: render again")
    for tag, key in (("cdm-degraded-target:5090-rootfs", "target_image_digest"),
                     ("cdm-degraded-gateway:5090", "gateway_image_digest")):
        if image_digest(tag) != mode[key]:
            raise SystemExit("image drift: render again")
    return mode


def compose(action: str) -> int:
    args = ["compose", "-f", str(state() / "compose.degraded.yaml")]
    if action != "up":
        return docker(*args, "ps" if action == "status" else action).returncode
    mode = validate_render()
    if mode["upstream_configured"] and not mode["local_canary"] and os.environ.get("CDM_DEGRADED_EGRESS_APPROVED") != "1":
        raise SystemExit("external egress not approved: compare original 5090 exit first")
    for part in ("home", "miniconda3"):
        if not (runtime() / part).is_dir():
            raise SystemExit("runtime not prepared: " + part)
    docker(*args, "up", "-d", "egress", "dns", "gateway")
    for _ in range(30):
        result = docker(*args, "exec", "-T", "gateway", "python3", "-m",
                        "controlled_dev_machine.gateway_health", capture=True, check=False)
        if result.returncode == 0:
            break
        time.sleep(1)
    else:
        raise SystemExit("gateway policy/audit health gate failed; target not started")
    public_ca = docker(*args, "exec", "-T", "gateway", "cat", "/ca/mitmproxy-ca-cert.pem", capture=True).stdout
    base_trust = docker("run", "--rm", "--pull=never", "--network=none", "--cap-drop=ALL",
                        "--entrypoint=cat", "cdm-degraded-target:5090-rootfs",
                        "/etc/ssl/certs/ca-certificates.crt", capture=True).stdout
    trust = state() / "trust/ca-certificates.crt"
    trust.write_text(base_trust.rstrip() + "\n" + public_ca)
    trust.chmod(0o600)
    if mode.get("strict_local"):
        return docker(*args, "up", "-d", "net-bridge", "target", "local-bridge").returncode
    return docker(*args, "up", "-d", "target").returncode


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(prog="sandboxctl-degraded")
    parser.add_argument("command", choices=("doctor", "import-images", "render", "up", "down", "status", "exec"))
    parser.add_argument("command_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    actions = {"doctor": doctor, "import-images": import_images, "render": render}
    if args.command in actions:
        return actions[args.command]()
    if args.command == "exec":
        if not args.command_args:
            raise SystemExit("exec requires a command")
        validate_render()
        return docker("compose", "-f", str(state() / "compose.degraded.yaml"), "exec",
                      "-T", "target", *args.command_args).returncode
    return compose(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
