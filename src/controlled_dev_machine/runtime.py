from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any

import yaml

from controlled_dev_machine.config import HostConfig
from controlled_dev_machine.errors import DeploymentError
from controlled_dev_machine.network_watchdog import process_identity, process_matches
from controlled_dev_machine.policy import PolicySnapshot, load_policy

_UBUNTU_SOURCE = (
    "docker://docker.io/library/ubuntu@"
    "sha256:52df9b1ee71626e0088f7d400d5c6b5f7bb916f8f0c82b474289a4ece6cf3faf"
)
_UBUNTU_LOCAL = "cdm-base-ubuntu:24.04-sha256-52df9b1e"
_MITMPROXY_SOURCE = (
    "docker://docker.io/mitmproxy/mitmproxy@"
    "sha256:68afa70d7b6ac9d269b88f88534f9ffceb363b4ce31703a78702341fba82e831"
)
_MITMPROXY_LOCAL = "cdm-base-mitmproxy:12.2.3-sha256-68afa70d"
_GATEWAY_UID = 1000
_GATEWAY_GID = 1000
_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_LIFECYCLE_LOCK_ROOT = Path("/run/controlled-dev-machine-locks")


@dataclass(frozen=True)
class RuntimeManifest:
    schema_version: int
    instance: str
    resource_prefix: str
    created_at: str
    repo_root: str
    compose_path: str
    policy_path: str
    policy_snapshot_path: str
    policy_digest: str
    target_subnet: str
    canary_subnet: str
    upstream_subnet: str
    proxy_target_address: str
    proxy_canary_address: str
    target_address: str
    canary_address: str
    upstream_gateway_address: str
    gateway_upstream_address: str
    dns_upstream_address: str
    target_image: str
    gateway_image: str
    gateway_build_digest: str
    profile_digest: str = ""
    profile_source_digest: str = ""
    target_build_digest: str = ""


@dataclass(frozen=True)
class _ExistingAllocation:
    created_at: str
    target_subnet: str
    canary_subnet: str
    upstream_subnet: str | None = None


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _gateway_build_digest(root: Path) -> str:
    candidates = [
        root / "images/gateway/Dockerfile",
        root / "gateway/mitmproxy/cdm_addon.py",
        root / "gateway/mitmproxy/entrypoint.sh",
        root / "config/claude/CLAUDE.md",
        root / "src/controlled_dev_machine/connect.bt",
        *sorted((root / "src").rglob("*.py")),
    ]
    digest = hashlib.sha256()
    for path in candidates:
        if path.is_symlink() or not path.is_file():
            raise DeploymentError(f"网关构建输入缺失或不是普通文件: {path}")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _target_build_digest(config: HostConfig, root: Path) -> str:
    dockerfile = root / "images/target/Dockerfile"
    if dockerfile.is_symlink() or not dockerfile.is_file():
        raise DeploymentError(f"目标镜像构建输入缺失或不是普通文件: {dockerfile}")
    inputs = {
        "base_image": _UBUNTU_LOCAL,
        "target_name": config.target.name,
        "target_uid": str(config.target.uid),
        "target_gid": str(config.target.gid),
        "target_home": str(config.target.home),
        "target_timezone": config.profile.timezone,
    }
    digest = hashlib.sha256(dockerfile.read_bytes())
    digest.update(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode())
    return digest.hexdigest()


@contextmanager
def _lifecycle_lock(config: HostConfig) -> Iterator[None]:
    lock_root = _LIFECYCLE_LOCK_ROOT
    if lock_root.is_symlink() or (lock_root.exists() and not lock_root.is_dir()):
        raise DeploymentError(f"生命周期锁目录类型异常: {lock_root}")
    lock_root.mkdir(mode=0o700, exist_ok=True)
    root_metadata = lock_root.lstat()
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or root_metadata.st_mode & 0o077
    ):
        raise DeploymentError(f"生命周期锁目录权限异常: {lock_root}")
    lock_path = lock_root / f"u{config.target.uid}.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        expected_owner = 0 if os.geteuid() == 0 else os.geteuid()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_owner
            or metadata.st_mode & 0o077
        ):
            raise DeploymentError(f"生命周期锁文件权限异常: {lock_path}")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise DeploymentError(
                f"同一实例已有生命周期操作正在执行: {config.resource_prefix}"
            ) from exc
        yield
    finally:
        os.close(descriptor)


def _locked_lifecycle(function: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(function)
    def wrapped(config: HostConfig, *args: Any, **kwargs: Any) -> Any:
        _require_root()
        with _lifecycle_lock(config):
            return function(config, *args, **kwargs)

    return wrapped


def _profile_bundle(
    config: HostConfig, root: Path
) -> tuple[dict[str, str], str]:
    source_paths = {
        "claude_instructions": config.profile.claude_instructions,
        "bashrc": config.profile.bashrc,
        "login_profile": config.profile.login_profile,
        "gitconfig": config.profile.gitconfig,
        "tmux_config": config.profile.tmux_config,
    }
    sources: dict[str, str] = {}
    source_digest = hashlib.sha256()
    for name, path in source_paths.items():
        source_digest.update(name.encode("utf-8") + b"\0")
        if path is None:
            source_digest.update(b"unset\0")
            continue
        content = _read_profile_source(config, path)
        sources[name] = content
        source_digest.update(str(path).encode("utf-8") + b"\0")
        source_digest.update(content.encode("utf-8") + b"\0")

    controlled_path = root / "config/claude/CLAUDE.md"
    if controlled_path.is_symlink() or not controlled_path.is_file():
        raise DeploymentError(f"沙箱 Claude 约束文件缺失: {controlled_path}")
    controlled = controlled_path.read_text(encoding="utf-8").rstrip()
    source_digest.update(b"controlled_claude\0")
    source_digest.update(controlled.encode("utf-8") + b"\0")
    environment = config.profile.default_conda_env or ""
    source_digest.update(b"default_conda_env\0" + environment.encode("utf-8") + b"\0")
    conda_root = str(config.profile.conda_root or "")
    source_digest.update(b"conda_root\0" + conda_root.encode("utf-8") + b"\0")

    host_instructions = sources.get("claude_instructions", "").rstrip()
    instructions = (
        f"{host_instructions}\n\n{controlled}\n" if host_instructions else f"{controlled}\n"
    )
    bashrc = sources.get("bashrc", "").rstrip()
    bashrc = _network_neutral_shell(bashrc)
    if bashrc:
        bashrc += "\n"
    bashrc += """

# Managed by controlled-dev-machine. Keep host shell behavior, but networking
# is transparent and controlled outside this shell.
if [ -n "${CDM_DEFAULT_CONDA_ENV:-}" ]; then
    if ! command -v conda >/dev/null 2>&1 \
        && [ -n "${CDM_CONDA_ROOT:-}" ] \
        && [ -f "$CDM_CONDA_ROOT/etc/profile.d/conda.sh" ]; then
        . "$CDM_CONDA_ROOT/etc/profile.d/conda.sh"
    fi
    if command -v conda >/dev/null 2>&1; then
        if [ "${CONDA_DEFAULT_ENV:-}" = "$CDM_DEFAULT_CONDA_ENV" ]; then
            conda deactivate >/dev/null 2>&1 || true
        fi
        conda activate "$CDM_DEFAULT_CONDA_ENV" \
            || printf 'warning: unable to activate conda environment %s\\n' \
                "$CDM_DEFAULT_CONDA_ENV" >&2
    fi
fi
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY
unset http_proxy https_proxy all_proxy no_proxy
unset CURL_CA_BUNDLE GIT_SSL_CAINFO NODE_EXTRA_CA_CERTS
unset REQUESTS_CA_BUNDLE SSL_CERT_FILE
unset -f proxy_on proxy_off 2>/dev/null || true
""".lstrip()

    login_profile = sources.get("login_profile")
    if login_profile is None:
        login_profile = """if [ -n "${BASH_VERSION:-}" ] && [ -f "$HOME/.bashrc" ]; then
    . "$HOME/.bashrc"
fi
"""
    else:
        login_profile = _network_neutral_shell(login_profile.rstrip()) + "\n"
    login_profile += """

# Managed by controlled-dev-machine. A host profile may alter PATH or network
# variables after sourcing .bashrc, so restore the transparent-network state.
if [ -n "${CDM_DEFAULT_CONDA_ENV:-}" ] \
    && [ -n "${CDM_CONDA_ROOT:-}" ] \
    && [ -d "$CDM_CONDA_ROOT/envs/$CDM_DEFAULT_CONDA_ENV/bin" ]; then
    export PATH="$CDM_CONDA_ROOT/envs/$CDM_DEFAULT_CONDA_ENV/bin:$PATH"
fi
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY
unset http_proxy https_proxy all_proxy no_proxy
unset CURL_CA_BUNDLE GIT_SSL_CAINFO NODE_EXTRA_CA_CERTS
unset REQUESTS_CA_BUNDLE SSL_CERT_FILE
unset -f proxy_on proxy_off 2>/dev/null || true
"""
    files = {
        "CLAUDE.md": instructions,
        ".bashrc": bashrc,
        ".profile": login_profile,
    }
    if "gitconfig" in sources:
        files[".gitconfig"] = _network_neutral_gitconfig(sources["gitconfig"])
    if "tmux_config" in sources:
        files[".tmux.conf"] = sources["tmux_config"]
    return files, source_digest.hexdigest()


def _network_neutral_shell(content: str) -> str:
    lines = []
    invocation = re.compile(r"^\s*proxy_(?:on|off)(?:\s+[^#;]+)?\s*(?:#.*)?$")
    network_assignment = re.compile(
        r"^\s*(?:export\s+)?(?:HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|"
        r"http_proxy|https_proxy|all_proxy|no_proxy|CURL_CA_BUNDLE|"
        r"GIT_SSL_CAINFO|NODE_EXTRA_CA_CERTS|REQUESTS_CA_BUNDLE|SSL_CERT_FILE)="
    )
    for line in content.splitlines():
        if not invocation.fullmatch(line) and not network_assignment.match(line):
            lines.append(line)
    return "\n".join(lines).rstrip()


def _network_neutral_gitconfig(content: str) -> str:
    section = ""
    output: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].split(' "', 1)[0].lower()
            output.append(line)
            continue
        key = stripped.split("=", 1)[0].strip().lower()
        if section in {"http", "https"} and key in {"proxy", "ssl", "sslverify"}:
            continue
        output.append(line)
    output.extend(["", "[http]", "\tsslVerify = true", "[https]", "\tsslVerify = true"])
    return "\n".join(output).rstrip() + "\n"


def _read_profile_source(config: HostConfig, path: Path) -> str:
    if path.is_symlink():
        raise DeploymentError(f"宿主 profile 不允许符号链接: {path}")
    descriptor = -1
    try:
        home = config.target.home.resolve(strict=True)
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
        opened_path = Path(f"/proc/self/fd/{descriptor}").resolve(strict=True)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise DeploymentError(f"宿主配置文件不存在或无法读取: {path}") from exc
    try:
        if not opened_path.is_relative_to(home):
            raise DeploymentError(f"宿主 profile 必须位于目标用户 Home 内: {path}")
        if not stat.S_ISREG(metadata.st_mode):
            raise DeploymentError(f"宿主配置文件不是普通文件: {path}")
        if metadata.st_uid != config.target.uid:
            raise DeploymentError(f"宿主 profile 所有者不是目标用户: {path}")
        if metadata.st_mode & stat.S_IWOTH:
            raise DeploymentError(f"宿主 profile 不允许其他用户写入: {path}")
        if metadata.st_mode & stat.S_IWGRP and metadata.st_gid != config.target.gid:
            raise DeploymentError(f"宿主 profile 的可写用户组不属于目标用户: {path}")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            return handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise DeploymentError(f"无法读取 UTF-8 宿主配置文件: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _profile_digest(files: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for name, content in sorted(files.items()):
        encoded_name = name.encode("utf-8")
        encoded_content = content.encode("utf-8")
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(len(encoded_content).to_bytes(8, "big"))
        digest.update(encoded_content)
    return digest.hexdigest()


def _profile_directory_digest(path: Path) -> str:
    if path.is_symlink() or not path.is_dir():
        raise DeploymentError(f"运行 profile 缺失或类型异常: {path}")
    files: dict[str, str] = {}
    for item in path.iterdir():
        if item.is_symlink() or not item.is_file():
            raise DeploymentError(f"运行 profile 包含异常项目: {item}")
        try:
            files[item.name] = item.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise DeploymentError(f"无法读取运行 profile: {item}") from exc
    return _profile_digest(files)


def _host_password_hash(
    username: str, shadow_path: Path = Path("/etc/shadow")
) -> str:
    try:
        content = shadow_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DeploymentError("无法读取宿主密码信息；请使用 root 执行 init") from exc
    for line in content.splitlines():
        fields = line.split(":")
        if fields[0] != username:
            continue
        password_hash = fields[1]
        if not password_hash or password_hash.startswith(("!", "*")):
            raise DeploymentError(
                f"宿主用户 {username} 没有可用于容器 sudo 的密码"
            )
        return password_hash
    raise DeploymentError(f"宿主密码信息中找不到用户 {username}")


def manifest_path(config: HostConfig) -> Path:
    return config.paths.state / "generated" / "current" / "runtime.json"


def _legacy_manifest_path(config: HostConfig) -> Path:
    return config.paths.state / "runtime.json"


def load_runtime(config: HostConfig) -> RuntimeManifest:
    path = manifest_path(config)
    _require_current_generation(config)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        manifest = RuntimeManifest(**raw)
    except FileNotFoundError as exc:
        raise DeploymentError("运行环境尚未初始化；先执行 sandboxctl init") from exc
    except (json.JSONDecodeError, TypeError) as exc:
        raise DeploymentError(f"运行清单损坏: {path}") from exc
    if manifest.schema_version != 4 or manifest.resource_prefix != config.resource_prefix:
        raise DeploymentError("运行清单与当前主机配置不一致")
    expected = config.paths.state / "generated" / "current" / "compose.closed.yaml"
    if Path(manifest.compose_path) != expected:
        raise DeploymentError("运行清单中的 Compose 路径不属于当前实例")
    expected_active = config.paths.state / "generated" / "current" / "policy.active.yaml"
    if Path(manifest.policy_path) != expected_active:
        raise DeploymentError("运行清单中的活动策略路径不属于当前实例")
    snapshot = Path(manifest.policy_snapshot_path)
    if snapshot.parent != config.paths.state / "policies":
        raise DeploymentError("运行清单中的策略快照路径不属于当前实例")
    if snapshot.name != f"{manifest.policy_digest}.yaml":
        raise DeploymentError("运行清单中的策略快照文件名与摘要不一致")
    if manifest.profile_digest:
        profile_path = config.paths.state / "generated" / "current" / "profile"
        if _profile_directory_digest(profile_path) != manifest.profile_digest:
            raise DeploymentError("运行 profile 与运行清单摘要不一致")
    return manifest


@_locked_lifecycle
def prepare_runtime(
    config: HostConfig,
    policy_path: Path,
    *,
    repo_root: Path | None = None,
) -> RuntimeManifest:
    _require_root()
    _require_instance_stopped(config, operation="init")
    root = (repo_root or repository_root()).resolve()
    policy = load_policy(policy_path)
    _require_deployable_policy(policy)
    _prepare_directories(config)
    stored_policy = _store_policy(config, policy_path, policy)
    _ensure_canary_certificates(config)
    _ensure_upstream_trust_bundle(config)

    old = _load_existing_manifest(config)
    if old is None:
        target_subnet, canary_subnet, upstream_subnet = _allocate_subnets(config)
        created_at = _now()
    else:
        target_subnet = ipaddress.ip_network(old.target_subnet)
        canary_subnet = ipaddress.ip_network(old.canary_subnet)
        if old.upstream_subnet is None:
            (upstream_subnet,) = _allocate_subnets(
                config,
                count=1,
                reserved=(target_subnet, canary_subnet),
            )
        else:
            upstream_subnet = ipaddress.ip_network(old.upstream_subnet)
        created_at = old.created_at
    addresses = _network_addresses(target_subnet, canary_subnet, upstream_subnet)
    gateway_build_digest = _gateway_build_digest(root)
    target_build_digest = _target_build_digest(config, root)
    profile_files, profile_source_digest = _profile_bundle(config, root)
    profile_digest = _profile_digest(profile_files)
    generated = config.paths.state / "generated"
    generation_root = generated / "generations"
    generation_name = (
        datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
        + f"-{policy.digest()[:12]}-{gateway_build_digest[:12]}-{target_build_digest[:12]}"
    )
    generation = generation_root / generation_name
    generation.mkdir(mode=0o700)
    os.chown(generation, 0, 0)
    current = generated / "current"
    active_policy = current / "policy.active.yaml"
    compose_path = current / "compose.closed.yaml"
    manifest = RuntimeManifest(
        schema_version=4,
        instance=config.instance,
        resource_prefix=config.resource_prefix,
        created_at=created_at,
        repo_root=str(root),
        compose_path=str(compose_path),
        policy_path=str(active_policy),
        policy_snapshot_path=str(stored_policy),
        policy_digest=policy.digest(),
        target_subnet=str(target_subnet),
        canary_subnet=str(canary_subnet),
        upstream_subnet=str(upstream_subnet),
        target_image=f"{config.resource_prefix}-target:{target_build_digest[:16]}",
        gateway_image=f"{config.resource_prefix}-gateway:{gateway_build_digest[:16]}",
        gateway_build_digest=gateway_build_digest,
        profile_digest=profile_digest,
        profile_source_digest=profile_source_digest,
        target_build_digest=target_build_digest,
        **addresses,
    )
    generation_policy = generation / "policy.active.yaml"
    generation_compose = generation / "compose.closed.yaml"
    generation_manifest = generation / "runtime.json"
    generation_profile = generation / "profile"
    generation_resolver = generation / "target-resolv.conf"
    generation_password_hash = generation / "target-password-hash"
    activated = False
    try:
        _atomic_text(
            generation_policy,
            stored_policy.read_text(encoding="utf-8"),
            mode=0o644,
        )
        generation_profile.mkdir(mode=0o700)
        os.chown(generation_profile, 0, 0)
        for name, content in profile_files.items():
            _atomic_text(generation_profile / name, content, mode=0o644)
        _atomic_text(
            generation_resolver,
            _target_resolver_content(manifest),
            mode=0o644,
        )
        _atomic_text(
            generation_password_hash,
            _host_password_hash(config.target.name) + "\n",
            mode=0o400,
        )
        compose = render_closed_compose(config, manifest)
        _atomic_text(
            generation_compose,
            yaml.safe_dump(compose, sort_keys=False),
            mode=0o600,
        )
        _atomic_text(
            generation_manifest,
            json.dumps(asdict(manifest), indent=2, sort_keys=True) + "\n",
            mode=0o600,
        )
        _validate_compose(
            config,
            replace(
                manifest,
                compose_path=str(generation_compose),
                policy_path=str(generation_policy),
            ),
        )
        _fsync_directory(generation)
        _activate_generation(config, generation)
        activated = True
    finally:
        if not activated:
            shutil.rmtree(generation, ignore_errors=True)
    return manifest


def render_closed_compose(
    config: HostConfig, manifest: RuntimeManifest
) -> dict[str, Any]:
    root = Path(manifest.repo_root)
    proxy_ca = config.paths.state / "proxy-ca"
    canary = config.paths.state / "canary"
    dns_state = config.paths.state / "dns"
    dns_control = config.paths.state / "dns-control"
    target_trust = config.paths.state / "target-trust"
    target_resolver = config.paths.state / "generated/current/target-resolv.conf"
    target_password_hash = (
        config.paths.state / "generated/current/target-password-hash"
    )
    plaintext = config.paths.audit / "plaintext"
    review = config.paths.review
    profile = config.paths.state / "generated" / "current" / "profile"
    common_security: dict[str, Any] = {
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "stop_grace_period": "2s",
    }
    project_mounts = [
        {
            "type": "bind",
            "source": str(item.host_path),
            "target": str(item.container_path),
            "read_only": item.read_only,
            "bind": {"create_host_path": False},
        }
        for item in config.mounts
    ]
    profile_mounts = [
        _bind(profile / "CLAUDE.md", config.target.home / ".claude/CLAUDE.md"),
        _bind(profile / ".bashrc", config.target.home / ".bashrc"),
        _bind(profile / ".profile", config.target.home / ".profile"),
    ]
    if config.profile.gitconfig is not None:
        profile_mounts.append(
            _bind(profile / ".gitconfig", config.target.home / ".gitconfig")
        )
    if config.profile.tmux_config is not None:
        profile_mounts.append(
            _bind(profile / ".tmux.conf", config.target.home / ".tmux.conf")
        )
    conda_trust_mounts = _conda_trust_mounts(
        config, target_trust / "ca-certificates.crt"
    )
    upstream_enabled = config.upstream.kind == "http"
    upstream_port = config.upstream.port if upstream_enabled else 9
    dns_policy_args = _dns_policy_args(manifest)
    gateway_networks: dict[str, Any] = {
        "target_net": {"ipv4_address": manifest.proxy_target_address},
        "canary_net": {"ipv4_address": manifest.proxy_canary_address},
    }
    gateway_extra_hosts = [f"canary.test:{manifest.canary_address}"]
    if upstream_enabled:
        gateway_networks["upstream_net"] = {
            "ipv4_address": manifest.gateway_upstream_address
        }
        gateway_extra_hosts.append(
            f"upstream.cdm.test:{manifest.upstream_gateway_address}"
        )
    dns_address = _target_dns_address(manifest)
    services: dict[str, Any] = {
        "canary": {
            "image": manifest.target_image,
            "user": "0:0",
            "command": [
                "python3",
                "/opt/cdm/canary_server.py",
                "--record-root",
                "/var/lib/cdm/received",
                "--cert",
                "/run/cdm/server.crt",
                "--key",
                "/run/cdm/server.key",
            ],
            "read_only": True,
            "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=32m"],
            "volumes": [
                _bind(root / "tests/integration/canary_server.py", "/opt/cdm/canary_server.py"),
                _bind(canary / "server.crt", "/run/cdm/server.crt"),
                _bind(canary / "server.key", "/run/cdm/server.key"),
                _bind(canary / "received", "/var/lib/cdm/received", read_only=False),
            ],
            "networks": {
                "canary_net": {"ipv4_address": manifest.canary_address},
            },
            "healthcheck": {
                "test": ["CMD", "curl", "-fsS", "http://127.0.0.1/health"],
                "interval": "2s",
                "timeout": "1s",
                "retries": 15,
            },
            **common_security,
        },
        "dns": {
            "image": manifest.target_image,
            "user": "0:0",
            "command": [
                "python3",
                "/opt/cdm/dns_gateway.py",
                "--record-path",
                "/var/lib/cdm/dns/queries.jsonl",
                "--proxy-host",
                "upstream.cdm.test",
                "--proxy-port",
                str(upstream_port),
                "--doh-address",
                "1.1.1.1",
                "--doh-server-name",
                "cloudflare-dns.com",
                "--lease-socket",
                "/run/cdm-dns/lease.sock",
                "--static-address",
                f"canary.test={manifest.canary_address}",
                *dns_policy_args,
            ],
            "read_only": True,
            "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=16m"],
            "volumes": [
                _bind(
                    root / "src/controlled_dev_machine/dns_gateway.py",
                    "/opt/cdm/dns_gateway.py",
                ),
                _bind(dns_state, "/var/lib/cdm/dns", read_only=False),
                _bind(dns_control, "/run/cdm-dns", read_only=False),
            ],
            "extra_hosts": (
                [f"upstream.cdm.test:{manifest.upstream_gateway_address}"]
                if upstream_enabled
                else []
            ),
            "networks": {
                "target_net": {"ipv4_address": dns_address},
                **(
                    {
                        "upstream_net": {
                            "ipv4_address": manifest.dns_upstream_address
                        }
                    }
                    if upstream_enabled
                    else {}
                ),
            },
            "healthcheck": {
                "test": [
                    "CMD",
                    "python3",
                    "-c",
                    "import socket;s=socket.create_connection(('127.0.0.1',53),1);s.close()",
                ],
                "interval": "2s",
                "timeout": "1s",
                "retries": 15,
            },
            "pids_limit": 128,
            **common_security,
        },
        "gateway": {
            "build": {
                "context": str(root),
                "dockerfile": str(root / "images/gateway/Dockerfile"),
                "args": {
                    "BASE_IMAGE": _MITMPROXY_LOCAL,
                    "GATEWAY_BUILD_DIGEST": manifest.gateway_build_digest,
                },
            },
            "image": manifest.gateway_image,
            "user": f"{_GATEWAY_UID}:{_GATEWAY_GID}",
            "entrypoint": ["/opt/cdm/gateway/entrypoint.sh"],
            "command": [
                "--mode",
                "transparent",
                "--listen-host",
                "0.0.0.0",
                "--listen-port",
                "8080",
                "--set",
                "connection_strategy=lazy",
                "--set",
                "rawtcp=false",
                "--set",
                "confdir=/home/mitmproxy/.mitmproxy",
                "--set",
                "ssl_insecure=false",
                "--set",
                "ssl_verify_upstream_trusted_ca=/run/cdm/upstream-trust-bundle.crt",
                "--set",
                "termlog_verbosity=info",
                "-w",
                "/audit/plaintext/flows.mitm",
                "-s",
                "/opt/cdm/gateway/cdm_addon.py",
            ],
            "environment": {
                "CDM_POLICY_PATH": "/run/cdm/policy.yaml",
                "CDM_EXPECTED_POLICY_DIGEST": manifest.policy_digest,
                "CDM_GATEWAY_BUILD_DIGEST": manifest.gateway_build_digest,
                "CDM_REVIEW_DIR": "/audit/review",
                "CDM_REVIEW_TTL_SECONDS": "300",
                "CDM_REVIEW_POLL_SECONDS": "0.10",
                "CDM_CANARY_ADDRESS": manifest.canary_address,
                "CDM_DNS_LEASE_SOCKET": "/run/cdm-dns/lease.sock",
                **(
                    {
                        "CDM_UPSTREAM_HOST": "upstream.cdm.test",
                        "CDM_UPSTREAM_PORT": str(config.upstream.port),
                    }
                    if upstream_enabled
                    else {}
                ),
            },
            "extra_hosts": gateway_extra_hosts,
            "dns": [dns_address],
            "read_only": True,
            "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m"],
            "volumes": [
                _bind(Path(manifest.policy_path), "/run/cdm/policy.yaml"),
                _bind(canary / "ca.crt", "/run/cdm/canary-ca.crt"),
                _bind(canary / "upstream-trust-bundle.crt", "/run/cdm/upstream-trust-bundle.crt"),
                _bind(proxy_ca, "/home/mitmproxy/.mitmproxy", read_only=False),
                _bind(review, "/audit/review", read_only=False),
                _bind(plaintext, "/audit/plaintext", read_only=False),
                _bind(dns_control, "/run/cdm-dns"),
            ],
            "networks": gateway_networks,
            "depends_on": {
                "canary": {"condition": "service_healthy"},
                "dns": {"condition": "service_healthy"},
            },
            "healthcheck": {
                "test": [
                    "CMD",
                    "python",
                    "-m",
                    "controlled_dev_machine.gateway_health",
                ],
                "interval": "5s",
                "timeout": "2s",
                "retries": 3,
                "start_period": "20s",
            },
            **common_security,
        },
        "target": {
            "build": {
                "context": str(root),
                "dockerfile": str(root / "images/target/Dockerfile"),
                "args": {
                    "BASE_IMAGE": _UBUNTU_LOCAL,
                    "TARGET_NAME": config.target.name,
                    "TARGET_UID": str(config.target.uid),
                    "TARGET_GID": str(config.target.gid),
                    "TARGET_HOME": str(config.target.home),
                    "TARGET_TIMEZONE": config.profile.timezone,
                    "TARGET_BUILD_DIGEST": manifest.target_build_digest,
                },
            },
            "image": manifest.target_image,
            "user": f"{config.target.uid}:{config.target.gid}",
            "group_add": ["sudo"],
            "hostname": "devbox",
            "command": ["sleep", "infinity"],
            "init": True,
            "stdin_open": True,
            "tty": True,
            "environment": {
                "HOME": str(config.target.home),
                "CLAUDE_CONFIG_DIR": str(config.target.home / ".claude"),
                "USER": config.target.name,
                "TZ": config.profile.timezone,
                "LANG": "en_US.UTF-8",
                "LC_ALL": "en_US.UTF-8",
                "NODE_USE_SYSTEM_CA": "1",
                "NVIDIA_VISIBLE_DEVICES": "all",
                "NVIDIA_DRIVER_CAPABILITIES": "compute,utility",
                **(
                    {"CDM_DEFAULT_CONDA_ENV": config.profile.default_conda_env}
                    if config.profile.default_conda_env is not None
                    else {}
                ),
                **(
                    {"CDM_CONDA_ROOT": str(config.profile.conda_root)}
                    if config.profile.conda_root is not None
                    else {}
                ),
            },
            "devices": ["nvidia.com/gpu=all"],
            "volumes": [
                _bind(config.paths.persistent_home, config.target.home, read_only=False),
                *project_mounts,
                *profile_mounts,
                _bind(
                    target_trust / "ca-certificates.crt",
                    "/etc/ssl/certs/ca-certificates.crt",
                ),
                _bind(target_resolver, "/etc/resolv.conf"),
                _bind(
                    target_password_hash,
                    "/run/cdm/target-password-hash",
                ),
                *conda_trust_mounts,
            ],
            "networks": {
                "target_net": {"ipv4_address": manifest.target_address},
            },
            "pids_limit": 4096,
            "stop_grace_period": "2s",
        },
    }
    return {
        "name": config.resource_prefix,
        "services": services,
        "networks": {
            "target_net": _isolated_network(manifest.target_subnet),
            "canary_net": _isolated_network(manifest.canary_subnet),
            **(
                {"upstream_net": _upstream_network(manifest.upstream_subnet)}
                if upstream_enabled
                else {}
            ),
        },
    }


@_locked_lifecycle
def compose_build(config: HostConfig) -> None:
    manifest = load_runtime(config)
    _require_root()
    _require_instance_stopped(config, operation="build")
    sync_base_images(config)
    _compose(config, manifest, "build", "target", "gateway")
    _pin_built_images(config, manifest)


def sync_base_images(config: HostConfig) -> None:
    _require_root()
    if os.uname().machine not in {"x86_64", "amd64"}:
        raise DeploymentError("当前基础镜像导入器只固定了 amd64 manifest")
    if not shutil.which("skopeo"):
        raise DeploymentError("缺少 skopeo；它用于绕过失效的共享 Docker registry mirror")
    for source, local in (
        (_UBUNTU_SOURCE, _UBUNTU_LOCAL),
        (_MITMPROXY_SOURCE, _MITMPROXY_LOCAL),
    ):
        exists = _docker(config, "image", "inspect", local, check=False, capture=True)
        if exists.returncode == 0:
            continue
        _run(
            [
                "skopeo",
                "copy",
                "--override-os",
                "linux",
                "--override-arch",
                "amd64",
                source,
                f"docker-daemon:{local}",
            ],
            env=_docker_env(config),
        )


@_locked_lifecycle
def compose_start_closed(config: HostConfig, *, timeout_seconds: int = 90) -> None:
    manifest = load_runtime(config)
    _require_root()
    _require_policy_files(manifest)
    _require_target_image(config, manifest)
    _require_gateway_image(config, manifest)
    _require_profile_sources(config, manifest)
    _check_gpu_cdi(config)
    if _service_container_id(config, manifest, "target"):
        raise DeploymentError("环境已经运行；配置变更时先执行 sandboxctl stop")
    _install_host_parent_guard(config, manifest)
    _configure_stopped_host_parent_guard(config, manifest)
    observed_upstream_ip = _check_upstream(config)
    _stop_audit(config)
    _archive_current_flow(config)
    _compose(config, manifest, "create", "canary", "dns", "gateway")
    try:
        _configure_host_parent_guard(config, manifest)
        _compose(config, manifest, "up", "-d", "canary", "dns", "gateway")
        ca_path = config.paths.state / "proxy-ca" / "mitmproxy-ca-cert.pem"
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if (
                ca_path.is_file()
                and _service_healthy(config, manifest, "dns")
                and _service_healthy(config, manifest, "gateway")
            ):
                break
            time.sleep(1)
        else:
            raise DeploymentError("代理未在期限内就绪；保持封闭网络并保留现场")
        os.chmod(ca_path, 0o644)
        _ensure_target_trust_bundle(config, manifest)
        _configure_infrastructure_network(config, manifest)
        _compose(config, manifest, "up", "-d", "target")
        _configure_target_sudo(config, manifest)
        _configure_target_network(config, manifest)
        _start_audit(config, manifest, observed_upstream_ip=observed_upstream_ip)
        _enable_target_route(config, manifest)
    except Exception:
        _disable_target_route(config, manifest)
        _stop_audit(config)
        _compose(config, manifest, "down", "--remove-orphans", check=False)
        _configure_stopped_host_parent_guard(config, manifest)
        raise


def _configure_target_sudo(config: HostConfig, manifest: RuntimeManifest) -> None:
    script = r"""
password_hash=$(cat /run/cdm/target-password-hash)
test -n "$password_hash"
{ printf '%s:' "$1"; printf '%s\n' "$password_hash"; } | chpasswd --encrypted
test -u /usr/bin/sudo
id -nG "$1" | tr ' ' '\n' | grep -qx sudo
""".strip()
    _compose(
        config,
        manifest,
        "exec",
        "-T",
        "--user",
        "0:0",
        "target",
        "sh",
        "-eu",
        "-c",
        script,
        "sh",
        config.target.name,
    )
    _compose(
        config,
        manifest,
        "exec",
        "-T",
        "target",
        "sh",
        "-eu",
        "-c",
        "id -nG | tr ' ' '\\n' | grep -qx sudo",
    )


@_locked_lifecycle
def compose_stop(config: HostConfig) -> None:
    _require_root()
    manifest: RuntimeManifest | None = None
    try:
        manifest = load_runtime(config)
        compose_path = Path(manifest.compose_path)
    except DeploymentError as exc:
        compose_path = _legacy_compose_path_for_stop(config)
        if compose_path is None:
            raise exc
    if manifest is not None:
        _disable_target_route(config, manifest)
    _stop_audit(config)
    _compose_path(config, compose_path, "down", "--remove-orphans")
    if manifest is not None:
        _configure_stopped_host_parent_guard(config, manifest)
    _archive_current_flow(config)


def compose_status(config: HostConfig) -> str:
    manifest = load_runtime(config)
    result = _compose(config, manifest, "ps", "--format", "json", capture=True)
    return result.stdout


def service_is_healthy(config: HostConfig, service: str) -> bool:
    manifest = load_runtime(config)
    return _service_healthy(config, manifest, service)


def audit_status(config: HostConfig) -> dict[str, object]:
    _require_root()
    path = _active_audit_path(config)
    if not path.exists():
        return {"active": False}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeploymentError(f"审计运行清单无法读取: {path}") from exc
    entries = state.get("entries", [])
    if not isinstance(entries, list):
        raise DeploymentError(f"审计运行清单字段损坏: {path}")
    namespaces = state.get("namespaces", [])
    if not isinstance(namespaces, list) or len(namespaces) != 3:
        raise DeploymentError(f"审计运行清单缺少网络命名空间记录: {path}")

    def process_status(entry: object, *, name_field: str) -> dict[str, object]:
        if not isinstance(entry, dict):
            raise DeploymentError(f"审计运行清单包含异常进程项: {path}")
        try:
            pid = int(entry["pid"])
            starttime = int(entry["starttime"])
            name = str(entry[name_field])
            identity = entry["identity"]
        except (KeyError, TypeError, ValueError) as exc:
            raise DeploymentError(f"审计运行清单进程字段损坏: {path}") from exc
        if not isinstance(identity, dict):
            raise DeploymentError(f"审计运行清单进程身份损坏: {path}")
        return {
            name_field: name,
            "pid": pid,
            "alive": process_matches(pid, starttime, identity),
        }

    processes: list[dict[str, object]] = []
    for entry in entries:
        processes.append(process_status(entry, name_field="kind"))
    namespace_status = [
        process_status(namespace, name_field="name") for namespace in namespaces
    ]
    expected_processes = {
        "target-pcap",
        "gateway-pcap",
        "dns-pcap",
        "target-connect-ebpf",
        "network-watchdog",
    }
    process_names = [str(item["kind"]) for item in processes]
    if len(process_names) != len(expected_processes) or set(process_names) != expected_processes:
        raise DeploymentError(f"审计运行清单探针集合不完整: {path}")
    expected_namespaces = {"target", "gateway", "dns"}
    namespace_names = [str(item["name"]) for item in namespace_status]
    if (
        len(namespace_names) != len(expected_namespaces)
        or set(namespace_names) != expected_namespaces
    ):
        raise DeploymentError(f"审计运行清单网络命名空间集合不完整: {path}")
    all_status = [*processes, *namespace_status]
    return {
        "active": bool(processes) and all(item["alive"] for item in all_status),
        "run_id": state.get("run_id"),
        "gateway_pid": state.get("gateway_pid"),
        "dns_pid": state.get("dns_pid"),
        "target_cgroup_id": state.get("target_cgroup_id"),
        "upstream_kind": state.get("upstream_kind"),
        "observed_upstream_ip": state.get("observed_upstream_ip"),
        "processes": processes,
        "namespaces": namespace_status,
    }


def compose_shell(config: HostConfig, *, root: bool) -> int:
    manifest = load_runtime(config)
    _require_root()
    user = "0:0" if root else f"{config.target.uid}:{config.target.gid}"
    result = _compose(config, manifest, "exec", "--user", user, "target", "bash", check=False)
    return result.returncode


def compose_exec(
    config: HostConfig,
    service: str,
    args: list[str],
    *,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    manifest = load_runtime(config)
    return _compose(
        config,
        manifest,
        "exec",
        "-T",
        service,
        *args,
        check=check,
        capture=capture,
    )


def compose_exec_async(
    config: HostConfig,
    service: str,
    args: list[str],
) -> subprocess.Popen[str]:
    """Start a non-interactive command in a service without hiding its lifetime."""
    manifest = load_runtime(config)
    _require_root()
    command = [
        "docker",
        "compose",
        "--project-name",
        config.resource_prefix,
        "--file",
        manifest.compose_path,
        "exec",
        "-T",
        service,
        *args,
    ]
    try:
        return subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_docker_env(config),
        )
    except FileNotFoundError as exc:
        raise DeploymentError(f"缺少命令: {command[0]}") from exc


def _prepare_directories(config: HostConfig) -> None:
    _mkdir(config.paths.persistent_home, 0o700, config.target.uid, config.target.gid)
    _mkdir(
        config.paths.persistent_home / ".claude",
        0o700,
        config.target.uid,
        config.target.gid,
    )
    _mkdir(config.paths.state, 0o700, 0, 0)
    _mkdir(config.paths.audit, 0o700, 0, 0)
    for path in (
        config.paths.state / "generated",
        config.paths.state / "generated" / "generations",
        config.paths.state / "policies",
        config.paths.state / "canary",
        config.paths.state / "canary" / "received",
        config.paths.state / "dns",
        config.paths.state / "target-trust",
        config.paths.audit / "plaintext" / "archive",
        config.paths.audit / "pcap",
        config.paths.audit / "structured",
    ):
        _mkdir(path, 0o700, 0, 0)
    _mkdir(config.paths.state / "dns-control", 0o755, 0, 0)
    for path in (
        config.paths.state / "proxy-ca",
        config.paths.review,
        config.paths.audit / "plaintext",
    ):
        _mkdir(path, 0o700, _GATEWAY_UID, _GATEWAY_GID)
    _normalize_gateway_tree(config.paths.state / "proxy-ca")
    _normalize_gateway_tree(config.paths.review)
    flow_path = config.paths.audit / "plaintext" / "flows.mitm"
    if flow_path.exists():
        if flow_path.is_symlink() or not flow_path.is_file():
            raise DeploymentError(f"明文流量文件类型异常: {flow_path}")
        os.chmod(flow_path, 0o600)
        os.chown(flow_path, _GATEWAY_UID, _GATEWAY_GID)
    for mount in config.mounts:
        if not (mount.host_path.is_dir() or mount.host_path.is_file()):
            raise DeploymentError(f"挂载源不存在或不是普通文件/目录: {mount.host_path}")


def _store_policy(config: HostConfig, source: Path, policy: PolicySnapshot) -> Path:
    target = config.paths.state / "policies" / f"{policy.digest()}.yaml"
    content = source.read_text(encoding="utf-8")
    if target.exists() and target.read_text(encoding="utf-8") != content:
        raise DeploymentError("同一策略 digest 对应的已存文件内容发生冲突")
    if not target.exists():
        _atomic_text(target, content, mode=0o644)
    else:
        os.chmod(target, 0o644)
    return target


def _require_deployable_policy(policy: PolicySnapshot) -> None:
    if policy.deployment != "active":
        raise DeploymentError(
            f"策略 {policy.policy_id} 标记为 {policy.deployment}，不能部署"
        )
    if policy.mode == "strict" and policy.web_default not in {"block", "review"}:
        raise DeploymentError("strict 策略必须默认阻断或逐请求审核")
    if policy.mode == "daily" and policy.web_default != "allow_audited_public":
        raise DeploymentError("daily 策略必须默认放行受审计的公网 Web")
    if policy.mode not in {"strict", "daily"}:
        raise DeploymentError("当前只实现 strict 和 daily 策略部署")


def _ensure_canary_certificates(config: HostConfig) -> None:
    canary = config.paths.state / "canary"
    expected = (canary / "ca.key", canary / "ca.crt", canary / "server.key", canary / "server.crt")
    if all(path.is_file() for path in expected):
        return
    with tempfile.TemporaryDirectory(prefix="cert-build-", dir=canary) as temp_text:
        temp = Path(temp_text)
        _run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:3072",
                "-sha256",
                "-days",
                "30",
                "-nodes",
                "-subj",
                "/CN=CDM Canary Test CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout",
                str(temp / "ca.key"),
                "-out",
                str(temp / "ca.crt"),
            ]
        )
        _run(
            [
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-subj",
                "/CN=canary.test",
                "-keyout",
                str(temp / "server.key"),
                "-out",
                str(temp / "server.csr"),
            ]
        )
        extensions = temp / "server.ext"
        extensions.write_text(
            "subjectAltName=DNS:canary.test\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n",
            encoding="ascii",
        )
        _run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(temp / "server.csr"),
                "-CA",
                str(temp / "ca.crt"),
                "-CAkey",
                str(temp / "ca.key"),
                "-CAcreateserial",
                "-days",
                "30",
                "-sha256",
                "-extfile",
                str(extensions),
                "-out",
                str(temp / "server.crt"),
            ]
        )
        for name in ("ca.key", "ca.crt", "server.key", "server.crt"):
            destination = canary / name
            os.replace(temp / name, destination)
            os.chmod(destination, 0o600 if name.endswith(".key") else 0o644)


def _ensure_target_trust_bundle(config: HostConfig, manifest: RuntimeManifest) -> None:
    result = _docker(
        config,
        "run",
        "--rm",
        "--network",
        "none",
        "--entrypoint",
        "cat",
        manifest.target_image,
        "/etc/ssl/certs/ca-certificates.crt",
        capture=True,
        check=False,
    )
    if result.returncode != 0 or "BEGIN CERTIFICATE" not in result.stdout:
        detail = (result.stderr or result.stdout).strip()
        raise DeploymentError(f"无法从目标镜像读取系统 CA: {detail[-1000:]}")
    proxy_ca = config.paths.state / "proxy-ca" / "mitmproxy-ca-cert.pem"
    try:
        controlled = proxy_ca.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise DeploymentError("无法读取透明网关 CA") from exc
    if "BEGIN CERTIFICATE" not in controlled:
        raise DeploymentError("透明网关 CA 内容无效")
    bundle = result.stdout.rstrip() + "\n" + controlled.rstrip() + "\n"
    _atomic_text(
        config.paths.state / "target-trust" / "ca-certificates.crt",
        bundle,
        mode=0o644,
    )


def _conda_trust_mounts(config: HostConfig, bundle: Path) -> list[dict[str, Any]]:
    root = config.profile.conda_root
    if root is None:
        return []
    environment_roots = [root]
    if config.profile.default_conda_env is not None:
        environment_roots.append(root / "envs" / config.profile.default_conda_env)
    candidates: list[Path] = []
    for environment_root in environment_roots:
        candidates.append(environment_root / "ssl" / "cacert.pem")
        candidates.extend(
            sorted(
                environment_root.glob(
                    "lib/python*/site-packages/certifi/cacert.pem"
                )
            )
        )
    targets: list[Path] = []
    for candidate in candidates:
        try:
            regular = candidate.is_file() and not candidate.is_symlink()
        except OSError:
            regular = False
        if regular and candidate not in targets:
            targets.append(candidate)
    return [_bind(bundle, target) for target in targets]


def _ensure_upstream_trust_bundle(config: HostConfig) -> None:
    system_ca = Path("/etc/ssl/certs/ca-certificates.crt")
    canary_ca = config.paths.state / "canary" / "ca.crt"
    bundle = config.paths.state / "canary" / "upstream-trust-bundle.crt"
    if not system_ca.is_file():
        raise DeploymentError(f"系统 CA bundle 不存在: {system_ca}")
    if not canary_ca.is_file():
        raise DeploymentError(f"canary CA 不存在: {canary_ca}")
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=bundle.parent, prefix="trust-bundle-", delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(system_ca.read_bytes())
        handle.write(b"\n")
        handle.write(canary_ca.read_bytes())
    os.replace(temporary, bundle)
    os.chmod(bundle, 0o644)
    os.chown(bundle, 0, 0)


def _allocate_subnets(
    config: HostConfig,
    *,
    count: int = 3,
    reserved: tuple[ipaddress.IPv4Network, ...] = (),
) -> tuple[ipaddress.IPv4Network, ...]:
    occupied = _occupied_ipv4_networks(config)
    selected: list[ipaddress.IPv4Network] = list(reserved)
    allocated: list[ipaddress.IPv4Network] = []
    pool = ipaddress.ip_network("172.28.0.0/14")
    for candidate in pool.subnets(new_prefix=28):
        if any(candidate.overlaps(item) for item in (*occupied, *selected)):
            continue
        selected.append(candidate)
        allocated.append(candidate)
        if len(allocated) == count:
            return tuple(allocated)
    raise DeploymentError(f"找不到 {count} 个不冲突的封闭容器子网")


def _occupied_ipv4_networks(config: HostConfig) -> tuple[ipaddress.IPv4Network, ...]:
    result: list[ipaddress.IPv4Network] = []
    routes = _run(["ip", "-j", "route", "show", "table", "all"], capture=True)
    for item in json.loads(routes.stdout):
        destination = item.get("dst")
        if not destination or destination == "default" or ":" in destination:
            continue
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network):
            result.append(network)
    network_ids = _docker(config, "network", "ls", "-q", capture=True).stdout.split()
    if network_ids:
        inspected = _docker(config, "network", "inspect", *network_ids, capture=True)
        for network in json.loads(inspected.stdout):
            for item in network.get("IPAM", {}).get("Config", []) or []:
                subnet = item.get("Subnet")
                if not subnet or ":" in subnet:
                    continue
                try:
                    parsed = ipaddress.ip_network(subnet)
                except ValueError:
                    continue
                if isinstance(parsed, ipaddress.IPv4Network):
                    result.append(parsed)
    return tuple(result)


def _network_addresses(
    target: ipaddress.IPv4Network,
    canary: ipaddress.IPv4Network,
    upstream: ipaddress.IPv4Network,
) -> dict[str, str]:
    target_hosts = list(target.hosts())
    canary_hosts = list(canary.hosts())
    upstream_hosts = list(upstream.hosts())
    return {
        "proxy_target_address": str(target_hosts[1]),
        "target_address": str(target_hosts[2]),
        "proxy_canary_address": str(canary_hosts[1]),
        "canary_address": str(canary_hosts[2]),
        "upstream_gateway_address": str(upstream_hosts[0]),
        "gateway_upstream_address": str(upstream_hosts[1]),
        "dns_upstream_address": str(upstream_hosts[2]),
    }


def _target_dns_address(manifest: RuntimeManifest) -> str:
    target = ipaddress.ip_network(manifest.target_subnet)
    return str(list(target.hosts())[3])


def _target_resolver_content(manifest: RuntimeManifest) -> str:
    return (
        f"nameserver {_target_dns_address(manifest)}\n"
        "search .\n"
        "options edns0 trust-ad ndots:0\n"
    )


def _configure_infrastructure_network(
    config: HostConfig, manifest: RuntimeManifest
) -> None:
    if config.upstream.kind != "http" or config.upstream.port is None:
        raise DeploymentError("透明网络要求本机 HTTP 父代理")
    gateway_pid = _service_pid(config, manifest, "gateway")
    dns_pid = _service_pid(config, manifest, "dns")
    upstream_address = _container_host_address(gateway_pid, "upstream.cdm.test")
    dns_upstream_address = _container_host_address(dns_pid, "upstream.cdm.test")
    if dns_upstream_address != upstream_address:
        raise DeploymentError("网关与 DNS 看到的父代理地址不一致")
    tcp_ports = _nft_port_set(_transparent_tcp_ports(manifest))
    _apply_nft(
        gateway_pid,
        f"""
table inet cdm_control {{
  set audit_parent_addresses {{ type ipv4_addr; flags timeout; timeout 5s; }}
  set audit_canary_addresses {{ type ipv4_addr; flags timeout; timeout 5s; }}
  set audit_target_addresses {{ type ipv4_addr; flags timeout; timeout 5s; }}
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
    ip saddr {manifest.target_address} tcp dport {{ {tcp_ports} }} redirect to :8080
  }}
  chain input {{
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related accept
    ip saddr @audit_target_addresses tcp dport 8080 accept
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
  }}
  chain output {{
    type filter hook output priority filter; policy drop;
    oifname "lo" accept
    ip daddr @audit_parent_addresses tcp dport {config.upstream.port} accept
    ip daddr @audit_canary_addresses tcp dport {{ 80, 443 }} accept
    ip daddr @audit_target_addresses ct state established,related accept
  }}
}}
""",
    )
    _apply_nft(
        dns_pid,
        f"""
table inet cdm_control {{
  set audit_parent_addresses {{ type ipv4_addr; flags timeout; timeout 5s; }}
  set audit_target_addresses {{ type ipv4_addr; flags timeout; timeout 5s; }}
  chain input {{
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related accept
    ip saddr @audit_target_addresses udp dport 53 accept
    ip saddr @audit_target_addresses tcp dport 53 accept
  }}
  chain output {{
    type filter hook output priority filter; policy drop;
    oifname "lo" accept
    ip daddr @audit_parent_addresses tcp dport {config.upstream.port} accept
    ip daddr @audit_target_addresses udp sport 53 accept
    ip daddr @audit_target_addresses tcp sport 53 accept
  }}
}}
""",
    )
    _verify_nft_table(gateway_pid)
    _verify_nft_table(dns_pid)


def _configure_host_parent_guard(
    config: HostConfig, manifest: RuntimeManifest
) -> None:
    if config.upstream.kind != "http" or config.upstream.port is None:
        raise DeploymentError("宿主父代理防火墙要求本机 HTTP 父代理")
    bridge = _upstream_bridge_name(config, manifest)
    table = _host_parent_table(manifest)
    sources = ", ".join(
        (manifest.gateway_upstream_address, manifest.dns_upstream_address)
    )
    _apply_host_nft(
        table,
        f"""
table inet {table} {{
  chain input {{
    type filter hook input priority -20; policy accept;
    iifname "lo" tcp dport {config.upstream.port} accept
    iifname "{bridge}" ip saddr {{ {sources} }} tcp dport {config.upstream.port} accept
    iifname "{bridge}" drop
    tcp dport {config.upstream.port} drop
  }}
}}
""",
    )
    result = _run(
        ["nft", "list", "table", "inet", table],
        capture=True,
    )
    if f"tcp dport {config.upstream.port} drop" not in result.stdout:
        raise DeploymentError("宿主父代理防火墙没有默认拒绝规则")


def _configure_stopped_host_parent_guard(
    config: HostConfig, manifest: RuntimeManifest
) -> None:
    if config.upstream.kind != "http" or config.upstream.port is None:
        raise DeploymentError("宿主父代理防火墙要求本机 HTTP 父代理")
    table = _host_parent_table(manifest)
    _apply_host_nft(table, _stopped_host_parent_guard_script(config, manifest))


def _stopped_host_parent_guard_script(
    config: HostConfig, manifest: RuntimeManifest
) -> str:
    if config.upstream.port is None:
        raise DeploymentError("宿主父代理端口未配置")
    table = _host_parent_table(manifest)
    return f"""
table inet {table} {{
  chain input {{
    type filter hook input priority -20; policy accept;
    iifname "lo" tcp dport {config.upstream.port} accept
    tcp dport {config.upstream.port} drop
  }}
}}
"""


def _install_host_parent_guard(config: HostConfig, manifest: RuntimeManifest) -> None:
    if config.upstream.kind != "http" or config.upstream.port is None:
        raise DeploymentError("宿主父代理防火墙要求本机 HTTP 父代理")
    nft = shutil.which("nft")
    systemctl = shutil.which("systemctl")
    if nft is None or systemctl is None:
        raise DeploymentError("持久父代理门禁要求宿主提供 nft 和 systemctl")

    guard_root = Path("/etc/controlled-dev-machine")
    _mkdir(guard_root, 0o755, 0, 0)
    name = f"{manifest.resource_prefix}-parent-guard"
    nft_path = guard_root / f"{name}.nft"
    reload_path = guard_root / f"{name}.reload.nft"
    runner_path = guard_root / f"{name}.sh"
    unit_path = Path("/etc/systemd/system") / f"{name}.service"
    for path in (nft_path, reload_path, runner_path, unit_path):
        if path.is_symlink():
            raise DeploymentError(f"父代理门禁文件不能是符号链接: {path}")

    table = _host_parent_table(manifest)
    stopped_script = _stopped_host_parent_guard_script(config, manifest).lstrip()
    _atomic_text(
        nft_path,
        stopped_script,
        mode=0o644,
    )
    _atomic_text(
        reload_path,
        f"delete table inet {table}\n{stopped_script}",
        mode=0o644,
    )
    _atomic_text(
        runner_path,
        _host_parent_guard_runner_script(nft, table, nft_path, reload_path),
        mode=0o755,
    )
    _atomic_text(
        unit_path,
        (
            "[Unit]\n"
            "Description=Controlled development machine parent proxy guard\n"
            "DefaultDependencies=no\n"
            "After=local-fs.target\n"
            "Before=network-pre.target docker.service\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            f"ExecStart={runner_path}\n"
            "RemainAfterExit=yes\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        ),
        mode=0o644,
    )
    _run([systemctl, "daemon-reload"])
    _run([systemctl, "enable", unit_path.name])


def _host_parent_guard_runner_script(
    nft: str, table: str, nft_path: Path, reload_path: Path
) -> str:
    return (
        "#!/bin/sh\n"
        "set -eu\n"
        f"NFT={shlex.quote(nft)}\n"
        f"if $NFT list table inet {table} >/dev/null 2>&1; then\n"
        f"  exec $NFT -f {shlex.quote(str(reload_path))}\n"
        "fi\n"
        f"exec $NFT -f {shlex.quote(str(nft_path))}\n"
    )


def _remove_host_parent_guard(manifest: RuntimeManifest) -> None:
    table = _host_parent_table(manifest)
    result = _run(
        ["nft", "list", "table", "inet", table],
        check=False,
        capture=True,
    )
    if result.returncode == 0:
        _run(["nft", "delete", "table", "inet", table])


def _host_parent_table(manifest: RuntimeManifest) -> str:
    suffix = hashlib.sha256(manifest.resource_prefix.encode("ascii")).hexdigest()[:12]
    return f"cdm_parent_{suffix}"


def _upstream_bridge_name(config: HostConfig, manifest: RuntimeManifest) -> str:
    network_name = f"{manifest.resource_prefix}_upstream_net"
    result = _docker(config, "network", "inspect", network_name, capture=True)
    try:
        networks = json.loads(result.stdout)
        network = networks[0]
        network_id = str(network["Id"])
        options = network.get("Options") or {}
        bridge = options.get("com.docker.network.bridge.name") or f"br-{network_id[:12]}"
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise DeploymentError("无法读取上游 Docker 网桥") from exc
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", bridge) is None:
        raise DeploymentError("上游 Docker 网桥名称无效")
    if not Path("/sys/class/net", bridge).is_dir():
        raise DeploymentError(f"上游 Docker 网桥不存在: {bridge}")
    return bridge


def _apply_host_nft(table: str, script: str) -> None:
    if not shutil.which("nft"):
        raise DeploymentError("透明网络要求宿主提供 nft")
    existing = _run(
        ["nft", "list", "table", "inet", table],
        check=False,
        capture=True,
    )
    if existing.returncode == 0:
        script = f"delete table inet {table}\n" + script
    _run_with_input(["nft", "-f", "-"], script)


def _configure_target_network(config: HostConfig, manifest: RuntimeManifest) -> None:
    target_pid = _service_pid(config, manifest, "target")
    _apply_nft(
        target_pid,
        """
table inet cdm_control {
  set audit_tcp_ports { type inet_service; flags timeout; timeout 5s; }
  set audit_dns_addresses { type ipv4_addr; flags timeout; timeout 5s; }
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related accept
  }
  chain output {
    type filter hook output priority filter; policy drop;
    oifname "lo" accept
    ip daddr @audit_dns_addresses udp dport 53 accept
    ip daddr @audit_dns_addresses tcp dport 53 accept
    tcp dport @audit_tcp_ports accept
  }
}
""",
    )
    _verify_nft_table(target_pid)


def _enable_target_route(config: HostConfig, manifest: RuntimeManifest) -> None:
    target_pid = _service_pid(config, manifest, "target")
    _run(
        [
            "nsenter",
            "--target",
            str(target_pid),
            "--net",
            "--",
            "ip",
            "route",
            "replace",
            "default",
            "via",
            manifest.proxy_target_address,
        ]
    )


def _disable_target_route(config: HostConfig, manifest: RuntimeManifest) -> None:
    if not _service_container_id(config, manifest, "target"):
        return
    target_pid = _service_pid(config, manifest, "target")
    _run(
        [
            "nsenter",
            "--target",
            str(target_pid),
            "--net",
            "--",
            "ip",
            "route",
            "del",
            "default",
        ],
        check=False,
    )


def _transparent_tcp_ports(manifest: RuntimeManifest) -> tuple[int, ...]:
    policy = load_policy(Path(manifest.policy_snapshot_path))
    if policy.digest() != manifest.policy_digest:
        raise DeploymentError("透明网络端口来源与运行策略摘要不一致")
    return tuple(sorted({80, 443, *(port for rule in policy.rules for port in rule.ports)}))


def _dns_policy_args(manifest: RuntimeManifest) -> list[str]:
    policy = load_policy(Path(manifest.policy_snapshot_path))
    if policy.digest() != manifest.policy_digest:
        raise DeploymentError("DNS 域名来源与运行策略摘要不一致")
    # DNS is transparent for public names in both modes. The Web gateway decides
    # whether the subsequent HTTP/HTTPS request is allowed or requires review.
    return ["--allow-public-domains"]


def _nft_port_set(ports: tuple[int, ...]) -> str:
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise DeploymentError("透明网络 TCP 端口集合无效")
    return ", ".join(str(port) for port in ports)


def _container_host_address(pid: int, hostname: str) -> str:
    hosts_path = Path(f"/proc/{pid}/root/etc/hosts")
    try:
        lines = hosts_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise DeploymentError(f"无法读取容器 hosts: {hosts_path}") from exc
    for line in lines:
        fields = line.split("#", 1)[0].split()
        if len(fields) >= 2 and hostname in fields[1:]:
            try:
                return str(ipaddress.ip_address(fields[0]))
            except ValueError as exc:
                raise DeploymentError(f"{hostname} 对应的不是 IP 地址") from exc
    raise DeploymentError(f"容器 hosts 缺少 {hostname}")


def _apply_nft(pid: int, script: str) -> None:
    if not shutil.which("nsenter") or not shutil.which("nft"):
        raise DeploymentError("透明网络要求宿主提供 nsenter 和 nft")
    existing = _run(
        [
            "nsenter",
            "--target",
            str(pid),
            "--net",
            "--",
            "nft",
            "list",
            "table",
            "inet",
            "cdm_control",
        ],
        check=False,
        capture=True,
    )
    if existing.returncode == 0:
        script = "delete table inet cdm_control\n" + script
    _run_with_input(
        [
            "nsenter",
            "--target",
            str(pid),
            "--net",
            "--",
            "nft",
            "-f",
            "-",
        ],
        script,
    )


def _verify_nft_table(pid: int) -> None:
    result = _run(
        [
            "nsenter",
            "--target",
            str(pid),
            "--net",
            "--",
            "nft",
            "list",
            "table",
            "inet",
            "cdm_control",
        ],
        capture=True,
    )
    if "policy drop" not in result.stdout:
        raise DeploymentError("透明网络防火墙没有默认阻断")


def _isolated_network(subnet: str) -> dict[str, Any]:
    return {
        "driver": "bridge",
        "internal": True,
        "enable_ipv6": False,
        "driver_opts": {
            "com.docker.network.bridge.gateway_mode_ipv4": "isolated",
            "com.docker.network.bridge.gateway_mode_ipv6": "isolated",
        },
        "ipam": {"config": [{"subnet": subnet}]},
    }


def _upstream_network(subnet: str) -> dict[str, Any]:
    network = ipaddress.ip_network(subnet)
    return {
        "driver": "bridge",
        "internal": True,
        "enable_ipv6": False,
        "ipam": {
            "config": [
                {"subnet": subnet, "gateway": str(next(network.hosts()))}
            ]
        },
    }


def _bind(source: Path, target: str | Path, *, read_only: bool = True) -> dict[str, Any]:
    return {
        "type": "bind",
        "source": str(source),
        "target": str(target),
        "read_only": read_only,
        "bind": {"create_host_path": False},
    }


def _validate_compose(config: HostConfig, manifest: RuntimeManifest) -> None:
    _compose(config, manifest, "config", "--quiet")


def _service_healthy(config: HostConfig, manifest: RuntimeManifest, service: str) -> bool:
    container_id = _service_container_id(config, manifest, service)
    if not container_id:
        return False
    result = _docker(
        config,
        "inspect",
        "--format",
        "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
        container_id,
        capture=True,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "healthy"


def _require_gateway_image(config: HostConfig, manifest: RuntimeManifest) -> None:
    current_digest = _gateway_build_digest(Path(manifest.repo_root))
    if current_digest != manifest.gateway_build_digest:
        raise DeploymentError(
            "网关源码已变化；重新执行 sandboxctl init、build 后再启动"
        )
    result = _docker(
        config,
        "image",
        "inspect",
        "--format",
        '{{index .Config.Labels "org.controlled-dev-machine.gateway-build-digest"}}',
        manifest.gateway_image,
        capture=True,
        check=False,
    )
    if result.returncode != 0 or result.stdout.strip() != manifest.gateway_build_digest:
        raise DeploymentError(
            "网关镜像不存在或构建摘要不符；重新执行 sandboxctl build 后再启动"
        )
    _require_pinned_image_id(config, manifest, "gateway", manifest.gateway_image)


def _require_target_image(config: HostConfig, manifest: RuntimeManifest) -> None:
    if not manifest.target_build_digest:
        raise DeploymentError("目标镜像缺少构建摘要；重新执行 sandboxctl init、build")
    current_digest = _target_build_digest(config, Path(manifest.repo_root))
    if current_digest != manifest.target_build_digest:
        raise DeploymentError(
            "目标镜像构建输入已变化；重新执行 sandboxctl init、build 后再启动"
        )
    result = _docker(
        config,
        "image",
        "inspect",
        "--format",
        '{{index .Config.Labels "org.controlled-dev-machine.target-build-digest"}}',
        manifest.target_image,
        capture=True,
        check=False,
    )
    if result.returncode != 0 or result.stdout.strip() != manifest.target_build_digest:
        raise DeploymentError(
            "目标镜像不存在或构建摘要不符；重新执行 sandboxctl build 后再启动"
        )
    _require_pinned_image_id(config, manifest, "target", manifest.target_image)


def _image_record_path(config: HostConfig, manifest: RuntimeManifest) -> Path:
    return config.paths.state / "images" / (
        f"{manifest.target_build_digest}-{manifest.gateway_build_digest}.json"
    )


def _inspect_image_id(config: HostConfig, image: str) -> str:
    result = _docker(
        config,
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        image,
        capture=True,
        check=False,
    )
    image_id = result.stdout.strip()
    if result.returncode != 0 or _IMAGE_ID_RE.fullmatch(image_id) is None:
        raise DeploymentError(f"镜像不存在或内容 ID 无效: {image}")
    return image_id


def _pin_built_images(config: HostConfig, manifest: RuntimeManifest) -> None:
    images_root = config.paths.state / "images"
    _mkdir(images_root, 0o700, 0, 0)
    record = {
        "schema_version": 1,
        "created_at": _now(),
        "target_image": manifest.target_image,
        "target_build_digest": manifest.target_build_digest,
        "target_image_id": _inspect_image_id(config, manifest.target_image),
        "gateway_image": manifest.gateway_image,
        "gateway_build_digest": manifest.gateway_build_digest,
        "gateway_image_id": _inspect_image_id(config, manifest.gateway_image),
    }
    path = _image_record_path(config, manifest)
    if path.exists() or path.is_symlink():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise DeploymentError(f"已有镜像内容记录损坏，拒绝覆盖: {path}") from exc
        immutable_keys = tuple(key for key in record if key != "created_at")
        if not isinstance(previous, dict) or any(
            previous.get(key) != record[key] for key in immutable_keys
        ):
            raise DeploymentError(
                "同一构建摘要已经登记了不同的镜像内容；恢复旧镜像或更换构建输入"
            )
        return
    _atomic_text(path, json.dumps(record, indent=2, sort_keys=True) + "\n", mode=0o600)


def _load_image_record(config: HostConfig, manifest: RuntimeManifest) -> dict[str, Any]:
    path = _image_record_path(config, manifest)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DeploymentError("缺少构建后镜像内容记录；重新执行 sandboxctl build") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise DeploymentError(f"镜像内容记录损坏: {path}") from exc
    expected = {
        "schema_version": 1,
        "target_image": manifest.target_image,
        "target_build_digest": manifest.target_build_digest,
        "gateway_image": manifest.gateway_image,
        "gateway_build_digest": manifest.gateway_build_digest,
    }
    if not isinstance(raw, dict) or any(raw.get(key) != value for key, value in expected.items()):
        raise DeploymentError("镜像内容记录与当前运行清单不一致；重新执行 sandboxctl build")
    for key in ("target_image_id", "gateway_image_id"):
        if not isinstance(raw.get(key), str) or _IMAGE_ID_RE.fullmatch(raw[key]) is None:
            raise DeploymentError("镜像内容记录包含无效的 Docker image ID")
    return raw


def _require_pinned_image_id(
    config: HostConfig,
    manifest: RuntimeManifest,
    kind: str,
    image: str,
) -> None:
    record = _load_image_record(config, manifest)
    expected = record[f"{kind}_image_id"]
    actual = _inspect_image_id(config, image)
    if actual != expected:
        raise DeploymentError(
            f"{kind} 镜像内容 ID 已变化；重新执行 sandboxctl build 或恢复已登记镜像"
        )


def _require_instance_stopped(config: HostConfig, *, operation: str) -> None:
    result = _docker(
        config,
        "ps",
        "-q",
        "--filter",
        f"label=com.docker.compose.project={config.resource_prefix}",
        capture=True,
    )
    if result.stdout.strip():
        raise DeploymentError(f"环境仍在运行；执行 {operation} 前先运行 sandboxctl stop")


def _require_policy_files(manifest: RuntimeManifest) -> None:
    snapshot = load_policy(Path(manifest.policy_snapshot_path))
    active = load_policy(Path(manifest.policy_path))
    if snapshot.digest() != manifest.policy_digest:
        raise DeploymentError("不可变策略快照与运行清单摘要不符")
    if active.digest() != manifest.policy_digest:
        raise DeploymentError("活动策略副本与运行清单摘要不符；重新执行 sandboxctl init")


def _require_profile_sources(config: HostConfig, manifest: RuntimeManifest) -> None:
    if not manifest.profile_source_digest:
        return
    _, current_digest = _profile_bundle(config, Path(manifest.repo_root))
    if current_digest != manifest.profile_source_digest:
        raise DeploymentError("宿主 profile 已变化；重新执行 sandboxctl init 后再启动")


def _check_gpu_cdi(config: HostConfig) -> None:
    if config.gpu.mode != "all":
        raise DeploymentError(f"不支持的 GPU 模式: {config.gpu.mode}")
    if shutil.which("nvidia-ctk") is None:
        raise DeploymentError("目标要求全部 GPU，但宿主缺少 nvidia-ctk")
    result = _run(["nvidia-ctk", "cdi", "list"], capture=True, check=False)
    if result.returncode != 0 or "nvidia.com/gpu=all" not in result.stdout.splitlines():
        detail = (result.stderr or result.stdout).strip()
        raise DeploymentError(f"宿主没有可用的 nvidia.com/gpu=all CDI 设备: {detail}")


def _check_upstream(config: HostConfig) -> str | None:
    if config.upstream.kind == "unset":
        return None
    if config.upstream.kind != "http" or not config.upstream.port:
        raise DeploymentError("当前只实现本机 HTTP 上游代理；配置未满足启动条件")
    proxy = f"http://{config.upstream.host}:{config.upstream.port}"
    result = _run(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "15",
            "--proxy",
            proxy,
            "https://api.ipify.org",
        ],
        capture=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise DeploymentError(f"本机上游代理不可用，拒绝启动公网路径: {detail}")
    observed = result.stdout.strip()
    try:
        address = ipaddress.ip_address(observed)
    except ValueError as exc:
        raise DeploymentError(f"上游出口返回的不是 IP 地址: {observed!r}") from exc
    if config.upstream.expected_exit_cidr is None:
        raise DeploymentError("HTTP 父代理没有声明 expected_exit_cidr")
    expected = ipaddress.ip_network(config.upstream.expected_exit_cidr)
    if address not in expected:
        raise DeploymentError(f"上游出口 {address} 不在声明范围 {expected}")
    return str(address)


def _service_container_id(
    config: HostConfig, manifest: RuntimeManifest, service: str
) -> str:
    return _compose(
        config, manifest, "ps", "-q", service, capture=True, check=False
    ).stdout.strip()


def _start_audit(
    config: HostConfig,
    manifest: RuntimeManifest,
    *,
    observed_upstream_ip: str | None = None,
) -> None:
    if shutil.which("nsenter") is None or shutil.which("tcpdump") is None:
        raise DeploymentError("缺少 nsenter 或 tcpdump，拒绝启动未审计的目标容器")
    if shutil.which("bpftrace") is None:
        raise DeploymentError("缺少 bpftrace，拒绝启动未审计的目标容器")
    target_pid = _service_pid(config, manifest, "target")
    gateway_pid = _service_pid(config, manifest, "gateway")
    dns_pid = _service_pid(config, manifest, "dns")
    namespaces = [
        {
            "name": name,
            "pid": pid,
            "starttime": _proc_starttime(pid),
            "identity": process_identity(pid),
        }
        for name, pid in (
            ("target", target_pid),
            ("gateway", gateway_pid),
            ("dns", dns_pid),
        )
    ]
    cgroup_path = _target_cgroup_path(target_pid)
    cgroup_id = _bpftrace_cgroup_id(cgroup_path)
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ") + "-" + uuid.uuid4().hex[:8]
    pcap_root = config.paths.audit / "pcap" / run_id
    structured_root = config.paths.audit / "structured" / run_id
    _mkdir(pcap_root, 0o700, 0, 0)
    _mkdir(structured_root, 0o700, 0, 0)
    _secure_empty_file(structured_root / "connect.log")
    state = {
        "schema_version": 2,
        "run_id": run_id,
        "created_at": _now(),
        "target_pid": target_pid,
        "gateway_pid": gateway_pid,
        "dns_pid": dns_pid,
        "target_cgroup_path": cgroup_path,
        "target_cgroup_id": cgroup_id,
        "upstream_kind": config.upstream.kind,
        "observed_upstream_ip": observed_upstream_ip,
        "namespaces": namespaces,
        "entries": [],
    }
    _write_audit_state(config, state)
    commands = (
        (
            "target-pcap",
            [
                "nsenter",
                "--target",
                str(target_pid),
                "--net",
                "--",
                "tcpdump",
                "-i",
                "any",
                "-U",
                "-s",
                "0",
                "-B",
                "4096",
                "-nn",
                "-Z",
                "root",
                "-w",
                "-",
            ],
            pcap_root / "target.tcpdump.log",
            pcap_root / "target.pcap",
        ),
        (
            "gateway-pcap",
            [
                "nsenter",
                "--target",
                str(gateway_pid),
                "--net",
                "--",
                "tcpdump",
                "-i",
                "any",
                "-U",
                "-s",
                "0",
                "-B",
                "4096",
                "-nn",
                "-Z",
                "root",
                "-w",
                "-",
            ],
            pcap_root / "gateway.tcpdump.log",
            pcap_root / "gateway.pcap",
        ),
        (
            "dns-pcap",
            [
                "nsenter",
                "--target",
                str(dns_pid),
                "--net",
                "--",
                "tcpdump",
                "-i",
                "any",
                "-U",
                "-s",
                "0",
                "-B",
                "4096",
                "-nn",
                "-Z",
                "root",
                "-w",
                "-",
            ],
            pcap_root / "dns.tcpdump.log",
            pcap_root / "dns.pcap",
        ),
        (
            "target-connect-ebpf",
            [
                "bpftrace",
                "-q",
                str(Path(manifest.repo_root) / "src/controlled_dev_machine/connect.bt"),
                str(cgroup_id),
            ],
            structured_root / "connect.bpftrace.log",
            structured_root / "connect.log",
        ),
    )
    started: list[dict[str, object]] = []
    try:
        for kind, command, error_log, capture_path in commands:
            process = _spawn_audit_process(command, error_log, capture_path)
            starttime = _proc_starttime(process.pid)
            entry = {
                "kind": kind,
                "pid": process.pid,
                "starttime": starttime,
                "command": command,
                "identity": process_identity(process.pid),
            }
            started.append(entry)
            state["entries"] = started
            _write_audit_state(config, state)
            try:
                if kind == "target-connect-ebpf" and capture_path is not None:
                    _wait_target_ebpf_ready(
                        config,
                        process,
                        error_log=error_log,
                        capture_path=capture_path,
                    )
                else:
                    _wait_audit_probe_ready(
                        kind,
                        process,
                        error_log=error_log,
                    )
            finally:
                try:
                    current_starttime = (
                        _proc_starttime(process.pid) if process.poll() is None else None
                    )
                    current_identity = (
                        process_identity(process.pid)
                        if current_starttime == starttime
                        else None
                    )
                except (DeploymentError, OSError):
                    current_identity = None
                if current_identity is not None:
                    entry["identity"] = current_identity
                    _write_audit_state(config, state)
        watchdog_config = structured_root / "network-watchdog.json"
        watchdog_ready = structured_root / "network-watchdog.ready"
        watchdog_ready.unlink(missing_ok=True)
        upstream_address = _container_host_address(gateway_pid, "upstream.cdm.test")
        dns_upstream_address = _container_host_address(dns_pid, "upstream.cdm.test")
        target_network = ipaddress.ip_network(manifest.target_subnet)
        dns_address = str(list(target_network.hosts())[3])
        watchdog = {
            "schema_version": 2,
            "lease_seconds": 5,
            "probes": [
                {
                    "pid": entry["pid"],
                    "starttime": entry["starttime"],
                    "identity": entry["identity"],
                }
                for entry in started
            ],
            "namespaces": [
                {
                    "name": "target",
                    "pid": target_pid,
                    "starttime": namespaces[0]["starttime"],
                    "identity": namespaces[0]["identity"],
                    "sets": [
                        {
                            "name": "audit_tcp_ports",
                            "kind": "port",
                            "values": list(_transparent_tcp_ports(manifest)),
                        },
                        {
                            "name": "audit_dns_addresses",
                            "kind": "ipv4",
                            "values": [dns_address],
                        },
                    ],
                },
                {
                    "name": "gateway",
                    "pid": gateway_pid,
                    "starttime": namespaces[1]["starttime"],
                    "identity": namespaces[1]["identity"],
                    "sets": [
                        {
                            "name": "audit_parent_addresses",
                            "kind": "ipv4",
                            "values": [upstream_address],
                        },
                        {
                            "name": "audit_canary_addresses",
                            "kind": "ipv4",
                            "values": [manifest.canary_address],
                        },
                        {
                            "name": "audit_target_addresses",
                            "kind": "ipv4",
                            "values": [manifest.target_address],
                        },
                    ],
                },
                {
                    "name": "dns",
                    "pid": dns_pid,
                    "starttime": namespaces[2]["starttime"],
                    "identity": namespaces[2]["identity"],
                    "sets": [
                        {
                            "name": "audit_parent_addresses",
                            "kind": "ipv4",
                            "values": [dns_upstream_address],
                        },
                        {
                            "name": "audit_target_addresses",
                            "kind": "ipv4",
                            "values": [manifest.target_address],
                        },
                    ],
                },
            ],
        }
        _atomic_text(
            watchdog_config,
            json.dumps(watchdog, indent=2, sort_keys=True) + "\n",
            mode=0o600,
        )
        watchdog_process = _spawn_audit_process(
            [
                sys.executable,
                str(
                    Path(manifest.repo_root)
                    / "src/controlled_dev_machine/network_watchdog.py"
                ),
                "--config",
                str(watchdog_config),
                "--ready",
                str(watchdog_ready),
            ],
            structured_root / "network-watchdog.log",
            None,
        )
        watchdog_entry = {
            "kind": "network-watchdog",
            "pid": watchdog_process.pid,
            "starttime": _proc_starttime(watchdog_process.pid),
            "command": [
                sys.executable,
                str(
                    Path(manifest.repo_root)
                    / "src/controlled_dev_machine/network_watchdog.py"
                ),
                "--config",
                str(watchdog_config),
                "--ready",
                str(watchdog_ready),
            ],
            "identity": process_identity(watchdog_process.pid),
        }
        started.append(watchdog_entry)
        state["entries"] = started
        _write_audit_state(config, state)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if watchdog_process.poll() is not None:
                raise DeploymentError(
                    f"网络审计监督启动失败；详见 {structured_root / 'network-watchdog.log'}"
                )
            if watchdog_ready.is_file():
                break
            time.sleep(0.1)
        else:
            raise DeploymentError("网络审计监督未在期限内续期防火墙")
    except Exception:
        state["entries"] = started
        _write_audit_state(config, state)
        raise


def _stop_audit(config: HostConfig) -> None:
    path = _active_audit_path(config)
    if not path.exists():
        return
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        entries = state.get("entries", [])
        if not isinstance(entries, list):
            raise ValueError("entries is not a list")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise DeploymentError(f"审计运行清单损坏，拒绝猜测并停止: {path}") from exc
    for entry in entries:
        if not isinstance(entry, dict):
            raise DeploymentError(f"审计运行清单包含异常进程项: {path}")
        _terminate_owned_process(entry)
    path.unlink(missing_ok=True)


def _active_audit_path(config: HostConfig) -> Path:
    return config.paths.state / "audit-active.json"


def _write_audit_state(config: HostConfig, state: dict[str, object]) -> None:
    _atomic_text(
        _active_audit_path(config),
        json.dumps(state, indent=2, sort_keys=True) + "\n",
        mode=0o600,
    )


def _secure_empty_file(path: Path) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def _service_pid(config: HostConfig, manifest: RuntimeManifest, service: str) -> int:
    container_id = _service_container_id(config, manifest, service)
    if not container_id:
        raise DeploymentError(f"服务未创建，无法启动审计: {service}")
    result = _docker(
        config,
        "inspect",
        "--format",
        "{{.State.Pid}}",
        container_id,
        capture=True,
    )
    try:
        pid = int(result.stdout.strip())
    except ValueError as exc:
        raise DeploymentError(f"无法读取服务 PID: {service}") from exc
    if pid <= 0:
        raise DeploymentError(f"服务没有运行中的 PID: {service}")
    return pid


def _target_cgroup_path(pid: int) -> str:
    try:
        lines = Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise DeploymentError(f"无法读取目标 cgroup: PID {pid}") from exc
    for line in lines:
        fields = line.split(":", 2)
        if len(fields) == 3 and fields[0] == "0":
            return "/sys/fs/cgroup" + fields[2]
    raise DeploymentError("目标不是 cgroup v2，拒绝启动无范围 eBPF")


def _bpftrace_cgroup_id(path: str) -> int:
    expression = f'BEGIN {{ printf("%llu\\n", cgroupid("{path}")); exit(); }}'
    result = _run(["bpftrace", "-e", expression], capture=True)
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.isdecimal():
            return int(line)
    raise DeploymentError(f"无法解析目标 cgroup ID: {path}")


def _spawn_audit_process(
    command: list[str], error_log: Path, capture_path: Path | None
) -> subprocess.Popen[bytes]:
    descriptor = os.open(error_log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    capture_descriptor: int | None = None
    try:
        process_command = list(command)
        if capture_path is not None:
            capture_descriptor = os.open(
                capture_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
            )
        process = subprocess.Popen(
            process_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL if capture_descriptor is None else capture_descriptor,
            stderr=descriptor,
            start_new_session=True,
        )
    finally:
        os.close(descriptor)
        if capture_descriptor is not None:
            os.close(capture_descriptor)
    return process


def _wait_audit_probe_ready(
    kind: str,
    process: subprocess.Popen[bytes],
    *,
    error_log: Path,
    timeout_seconds: float = 15.0,
) -> None:
    if kind.endswith("-pcap"):
        ready_path = error_log
        marker = "listening on"
    else:
        raise DeploymentError(f"未知审计探针类型，无法确认就绪: {kind}")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            detail = error_log.read_text(encoding="utf-8", errors="replace").strip()
            raise DeploymentError(f"审计进程启动失败: {kind}; {detail[-1000:]}")
        try:
            detail = ready_path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            detail = ""
        if marker.lower() in detail.lower():
            return
        time.sleep(0.05)
    raise DeploymentError(f"审计探针未在期限内就绪: {kind}; 详见 {error_log}")


def _wait_target_ebpf_ready(
    config: HostConfig,
    process: subprocess.Popen[bytes],
    *,
    error_log: Path,
    capture_path: Path,
    timeout_seconds: float = 15.0,
) -> None:
    required = {
        "CDM_EXEC|",
        "CDM_CONNECT_BEGIN|",
        "CDM_CONNECT_END|",
        "CDM_SENDTO_BEGIN|",
        "CDM_SENDTO_END|",
        "CDM_SENDMSG_BEGIN|",
        "CDM_SENDMSG_END|",
    }
    canary = (
        "import os,socket\n"
        "stream=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
        "stream.setblocking(False)\n"
        "stream.connect_ex(('1.1.1.1',22))\n"
        "stream.close()\n"
        "for method in ('sendto','sendmsg'):\n"
        "    datagram=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
        "    try:\n"
        "        if method == 'sendto':\n"
        "            datagram.sendto(b'cdm-ebpf-ready',('1.1.1.1',443))\n"
        "        else:\n"
        "            datagram.sendmsg([b'cdm-ebpf-ready'],[],0,('1.1.1.1',443))\n"
        "    except OSError:\n"
        "        pass\n"
        "    finally:\n"
        "        datagram.close()\n"
        "os.execv('/bin/true',['true'])\n"
    )
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            detail = error_log.read_text(encoding="utf-8", errors="replace").strip()
            raise DeploymentError(f"目标 eBPF 审计启动失败: {detail[-1000:]}")
        probe = compose_exec_async(config, "target", ["python3", "-c", canary])
        try:
            stdout, stderr = probe.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            probe.kill()
            stdout, stderr = probe.communicate()
        if probe.returncode != 0:
            detail = (stderr or stdout or "").strip()
            raise DeploymentError(f"目标 eBPF 就绪探针执行失败: {detail[-1000:]}")
        try:
            observed = capture_path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            observed = ""
        if all(marker in observed for marker in required):
            return
        time.sleep(0.05)
    missing = sorted(marker for marker in required if marker not in observed)
    raise DeploymentError(f"目标 eBPF 未确认全部探针附着: {', '.join(missing)}")


def _proc_starttime(pid: int) -> int:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except OSError as exc:
        raise DeploymentError(f"审计进程启动后立即消失: PID {pid}") from exc
    try:
        tail = raw.rsplit(") ", 1)[1].split()
        return int(tail[19])
    except (IndexError, ValueError) as exc:
        raise DeploymentError(f"无法读取进程启动时间: PID {pid}") from exc


def _terminate_owned_process(entry: dict[str, object]) -> None:
    try:
        pid = int(entry["pid"])
        expected_starttime = int(entry["starttime"])
        command = entry["command"]
        identity = entry["identity"]
        if not isinstance(command, list) or not command or not isinstance(identity, dict):
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise DeploymentError("审计进程记录字段损坏") from exc
    proc = Path(f"/proc/{pid}")
    if not proc.exists():
        return
    if not process_matches(pid, expected_starttime, identity, allow_stopped=True):
        raise DeploymentError(f"审计进程身份不匹配，拒绝终止: PID {pid}")
    os.kill(pid, signal.SIGINT)
    deadline = time.monotonic() + 5
    while proc.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    if proc.exists() and _proc_starttime(pid) == expected_starttime:
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 2
        while proc.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
    if proc.exists() and _proc_starttime(pid) == expected_starttime:
        os.kill(pid, signal.SIGKILL)


def _archive_current_flow(config: HostConfig) -> None:
    source = config.paths.audit / "plaintext" / "flows.mitm"
    if not source.is_file() or source.stat().st_size == 0:
        return
    digest = _sha256_file(source)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    archive = config.paths.audit / "plaintext" / "archive"
    archive.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = archive / f"{timestamp}-{digest[:16]}.mitm"
    if destination.exists():
        raise DeploymentError(f"明文归档目标已经存在: {destination}")
    os.replace(source, destination)
    os.chmod(destination, 0o600)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _compose(
    config: HostConfig,
    manifest: RuntimeManifest,
    *args: str,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return _compose_path(
        config,
        Path(manifest.compose_path),
        *args,
        capture=capture,
        check=check,
    )


def _compose_path(
    config: HostConfig,
    compose_path: Path,
    *args: str,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            "docker",
            "compose",
            "--project-name",
            config.resource_prefix,
            "--file",
            str(compose_path),
            *args,
        ],
        capture=capture,
        check=check,
        env=_docker_env(config),
    )


def _docker(
    config: HostConfig,
    *args: str,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return _run(
        ["docker", *args], capture=capture, check=check, env=_docker_env(config)
    )


def _docker_env(config: HostConfig) -> dict[str, str]:
    return {**os.environ, "DOCKER_HOST": f"unix://{config.docker.socket}"}


def _run(
    command: list[str],
    *,
    capture: bool = False,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=capture,
            env=env,
        )
    except FileNotFoundError as exc:
        raise DeploymentError(f"缺少命令: {command[0]}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        if len(detail) > 2000:
            detail = detail[-2000:]
        raise DeploymentError(f"命令失败 ({result.returncode}): {' '.join(command)}\n{detail}")
    return result


def _run_with_input(command: list[str], content: str) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            check=False,
            text=True,
            input=content,
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise DeploymentError(f"缺少命令: {command[0]}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise DeploymentError(
            f"命令失败 ({result.returncode}): {' '.join(command)}\n{detail[-2000:]}"
        )
    return result


def _load_existing_manifest(
    config: HostConfig,
) -> RuntimeManifest | _ExistingAllocation | None:
    current_path = manifest_path(config)
    path = current_path if current_path.exists() else _legacy_manifest_path(config)
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeploymentError("运行清单损坏，无法保留原网络分配") from exc
    if not isinstance(raw, dict):
        raise DeploymentError("运行清单根节点损坏")
    schema_version = raw.get("schema_version")
    if schema_version not in {1, 2, 3, 4}:
        raise DeploymentError(f"不支持迁移运行清单 schema_version={schema_version}")
    if path == current_path and schema_version == 4:
        return load_runtime(config)
    try:
        if raw.get("resource_prefix") != config.resource_prefix:
            raise ValueError
        return _ExistingAllocation(
            created_at=str(raw["created_at"]),
            target_subnet=str(ipaddress.ip_network(raw["target_subnet"])),
            canary_subnet=str(ipaddress.ip_network(raw["canary_subnet"])),
            upstream_subnet=(
                str(ipaddress.ip_network(raw["upstream_subnet"]))
                if raw.get("upstream_subnet") is not None
                else None
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise DeploymentError("旧运行清单损坏，无法保留原网络分配") from exc


def _legacy_compose_path_for_stop(config: HostConfig) -> Path | None:
    """Resolve only the old fixed compose path needed during migration."""
    path = _legacy_manifest_path(config)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict) or raw.get("schema_version") not in {1, 2, 3}:
        return None
    expected = config.paths.state / "generated" / "compose.closed.yaml"
    if (
        raw.get("resource_prefix") != config.resource_prefix
        or raw.get("instance") != config.instance
        or raw.get("compose_path") != str(expected)
    ):
        return None
    return expected


def _mkdir(path: Path, mode: int, uid: int, gid: int) -> None:
    if path.is_symlink():
        raise DeploymentError(f"登记目录不能是符号链接: {path}")
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    os.chmod(path, mode)
    os.chown(path, uid, gid)


def _normalize_gateway_tree(root: Path) -> None:
    for directory, dir_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in dir_names:
            path = directory_path / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise DeploymentError(f"网关状态目录包含异常项目: {path}")
            os.chmod(path, 0o700)
            os.chown(path, _GATEWAY_UID, _GATEWAY_GID)
        for name in file_names:
            path = directory_path / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                raise DeploymentError(f"网关状态目录包含异常项目: {path}")
            file_mode = 0o644 if name == "mitmproxy-ca-cert.pem" else 0o600
            os.chmod(path, file_mode)
            os.chown(path, _GATEWAY_UID, _GATEWAY_GID)


def _atomic_text(path: Path, content: str, *, mode: int) -> None:
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        _fsync_directory(path.parent)
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise


def _activate_generation(config: HostConfig, generation: Path) -> None:
    generated = config.paths.state / "generated"
    generations = generated / "generations"
    if generation.parent != generations or generation.is_symlink() or not generation.is_dir():
        raise DeploymentError("运行 generation 不属于当前实例")
    required = {
        "runtime.json",
        "compose.closed.yaml",
        "policy.active.yaml",
        "target-resolv.conf",
        "target-password-hash",
    }
    if {
        item.name
        for item in generation.iterdir()
        if item.is_file() and not item.is_symlink()
    } != required:
        raise DeploymentError("运行 generation 文件集合不完整")
    temporary = generated / f".current.{uuid.uuid4().hex}"
    try:
        os.symlink(Path("generations") / generation.name, temporary)
        os.replace(temporary, generated / "current")
        _fsync_directory(generated)
    finally:
        temporary.unlink(missing_ok=True)


def _require_current_generation(config: HostConfig) -> None:
    generated = config.paths.state / "generated"
    current = generated / "current"
    if not current.is_symlink():
        raise DeploymentError("运行环境尚未发布原子 current generation")
    target = Path(os.readlink(current))
    if len(target.parts) != 2 or target.parts[0] != "generations" or target.is_absolute():
        raise DeploymentError("current generation 指针异常")
    resolved = (generated / target).resolve()
    generations = (generated / "generations").resolve()
    if resolved.parent != generations or not resolved.is_dir():
        raise DeploymentError("current generation 不属于当前实例")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_root() -> None:
    if os.geteuid() != 0:
        raise DeploymentError("此操作会管理宿主容器或 root-only 状态，请使用 sudo sandboxctl")


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
