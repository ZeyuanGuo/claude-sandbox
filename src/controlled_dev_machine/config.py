from __future__ import annotations

import os
import pwd
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from controlled_dev_machine.errors import ConfigError

_INSTANCE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_ENVIRONMENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True)
class TargetIdentity:
    name: str
    uid: int
    gid: int
    home: Path


@dataclass(frozen=True)
class HostPaths:
    persistent_home: Path
    state: Path
    audit: Path

    @property
    def review(self) -> Path:
        return self.audit / "review"


@dataclass(frozen=True)
class DockerConfig:
    socket: Path


@dataclass(frozen=True)
class GpuConfig:
    mode: str


@dataclass(frozen=True)
class StorageThreshold:
    min_free_gib: float
    min_free_percent: float

    def required_free_bytes(self, total_bytes: int) -> int:
        fixed = int(self.min_free_gib * 1024**3)
        fractional = int(total_bytes * self.min_free_percent / 100)
        return max(fixed, fractional)


@dataclass(frozen=True)
class StorageConfig:
    root: StorageThreshold
    audit: StorageThreshold
    pcap_limit_gib: float
    plaintext_limit_gib: float
    structured_limit_gib: float


@dataclass(frozen=True)
class ProjectMount:
    host_path: Path
    container_path: Path
    read_only: bool


@dataclass(frozen=True)
class UpstreamConfig:
    kind: str
    host: str | None
    port: int | None
    config_path: Path | None
    expected_exit_cidr: str | None = None


@dataclass(frozen=True)
class HostProfile:
    claude_instructions: Path | None
    bashrc: Path | None
    login_profile: Path | None
    gitconfig: Path | None
    tmux_config: Path | None
    conda_root: Path | None
    default_conda_env: str | None
    timezone: str = "UTC"


@dataclass(frozen=True)
class HostConfig:
    schema_version: int
    instance: str
    target: TargetIdentity
    paths: HostPaths
    docker: DockerConfig
    gpu: GpuConfig
    storage: StorageConfig
    mounts: tuple[ProjectMount, ...]
    upstream: UpstreamConfig
    profile: HostProfile

    @property
    def resource_prefix(self) -> str:
        return f"cdm-u{self.target.uid}-{self.instance}"


def default_config_path() -> Path:
    """Resolve the invoking user's config even when sandboxctl runs through sudo."""
    account = invoking_account()
    return Path(account.pw_dir) / ".config" / "controlled-dev-machine" / "host.yaml"


def invoking_account() -> pwd.struct_passwd:
    """Return the real invoking account instead of root after sudo."""
    sudo_uid = os.environ.get("SUDO_UID")
    uid = int(sudo_uid) if sudo_uid and sudo_uid.isdecimal() else os.getuid()
    try:
        return pwd.getpwuid(uid)
    except KeyError as exc:
        raise ConfigError(f"找不到 UID {uid} 的 Home") from exc


def ensure_invoking_target(config: HostConfig) -> None:
    """Prevent an explicit config from selecting another real host account."""
    account = invoking_account()
    if (
        config.target.name != account.pw_name
        or config.target.uid != account.pw_uid
        or config.target.gid != account.pw_gid
        or config.target.home != Path(account.pw_dir)
    ):
        raise ConfigError("配置目标必须是当前调用者账号，不能管理其他用户的沙箱")


def create_host_config(path: Path) -> None:
    """Create a safe host-specific starting config without overwriting one."""
    if path.exists() or path.is_symlink():
        raise ConfigError(f"主机配置已存在，拒绝覆盖: {path}")
    account = invoking_account()
    home = Path(account.pw_dir)

    profile_candidates = {
        "claude_instructions": home / ".claude" / "CLAUDE.md",
        "bashrc": home / ".bashrc",
        "login_profile": home / ".profile",
        "gitconfig": home / ".gitconfig",
        "tmux_config": home / ".tmux.conf",
    }
    profile = {
        name: _home_relative(candidate, home)
        if _safe_profile_candidate(candidate, account.pw_uid, account.pw_gid)
        else None
        for name, candidate in profile_candidates.items()
    }
    profile.update({"conda_root": None, "default_conda_env": None, "timezone": "UTC"})

    # Codex keeps credentials and session data in this directory. Share the
    # complete user-owned directory so host and target use the same state.
    codex_home = home / ".codex"
    if not codex_home.exists() and not codex_home.is_symlink():
        codex_home.mkdir(mode=0o700)

    mounts = []
    for relative, access in (
        (".claude/skills", "rw"),
        (".claude/agents", "rw"),
        (".agents/skills", "rw"),
        (".codex", "rw"),
        (".config/git", "rw"),
        (".ssh", "ro"),
        (".condarc", "rw"),
    ):
        source = home / relative
        if source.is_symlink() or not (source.is_file() or source.is_dir()):
            continue
        mounts.append(
            {
                "host_path": f"~/{relative}",
                "container_path": str(home / relative),
                "access": access,
            }
        )

    content = {
        "schema_version": 1,
        "instance": "main",
        "target": {
            "name": account.pw_name,
            "uid": account.pw_uid,
            "gid": account.pw_gid,
            "home": str(home),
        },
        "docker": {"socket": "/var/run/docker.sock"},
        "gpu": {"mode": "all"},
        "paths": {
            "persistent_home": "~/.local/share/controlled-dev-machine/home",
            "state": "~/.local/state/controlled-dev-machine/runtime",
            "audit": "~/.local/state/controlled-dev-machine/audit",
        },
        "storage": {
            "root": {"min_free_gib": 50, "min_free_percent": 5},
            "audit": {"min_free_gib": 200, "min_free_percent": 10},
            "pcap_limit_gib": 100,
            "plaintext_limit_gib": 50,
            "structured_limit_gib": 10,
        },
        "upstream": {
            "kind": "http",
            "host": "127.0.0.1",
            "port": 11450,
            "expected_exit_cidr": None,
            "config_path": None,
        },
        "profile": profile,
        "mounts": mounts,
    }
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            yaml.safe_dump(content, handle, sort_keys=False)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _safe_profile_candidate(path: Path, uid: int, gid: int) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return bool(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == uid
        and not metadata.st_mode & stat.S_IWOTH
        and not (metadata.st_mode & stat.S_IWGRP and metadata.st_gid != gid)
    )


def _home_relative(path: Path, home: Path) -> str:
    return "~/" + path.relative_to(home).as_posix()


def load_host_config(path: Path) -> HostConfig:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"主机配置不存在: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"主机配置不是有效 YAML: {exc}") from exc

    root = _mapping(raw, "配置根节点")
    schema_version = _integer(root.get("schema_version"), "schema_version")
    if schema_version != 1:
        raise ConfigError(f"不支持 schema_version={schema_version}，当前只支持 1")

    instance = _string(root.get("instance"), "instance")
    if not _INSTANCE_RE.fullmatch(instance):
        raise ConfigError("instance 必须以小写字母开头，且只包含小写字母、数字和连字符")
    if instance != "main":
        raise ConfigError("每个用户只允许一套沙箱，instance 必须为 main")

    target_raw = _mapping(root.get("target"), "target")
    target = TargetIdentity(
        name=_string(target_raw.get("name"), "target.name"),
        uid=_nonnegative_int(target_raw.get("uid"), "target.uid"),
        gid=_nonnegative_int(target_raw.get("gid"), "target.gid"),
        home=_absolute_path(target_raw.get("home"), "target.home"),
    )

    paths_raw = _mapping(root.get("paths"), "paths")
    paths = HostPaths(
        persistent_home=_user_path(
            paths_raw.get("persistent_home"), "paths.persistent_home", target.home
        ),
        state=_user_path(paths_raw.get("state"), "paths.state", target.home),
        audit=_user_path(paths_raw.get("audit"), "paths.audit", target.home),
    )
    _validate_distinct_paths(paths)

    docker_raw = _mapping(root.get("docker"), "docker")
    docker = DockerConfig(socket=_absolute_path(docker_raw.get("socket"), "docker.socket"))

    gpu_raw = _mapping(root.get("gpu", {"mode": "all"}), "gpu")
    gpu_mode = _string(gpu_raw.get("mode", "all"), "gpu.mode")
    if gpu_mode != "all":
        raise ConfigError("gpu.mode 当前只允许 all；不启用 GPU 不符合本项目边界")
    gpu = GpuConfig(mode=gpu_mode)

    storage_raw = _mapping(root.get("storage"), "storage")
    storage = StorageConfig(
        root=_threshold(storage_raw.get("root"), "storage.root"),
        audit=_threshold(storage_raw.get("audit"), "storage.audit"),
        pcap_limit_gib=_positive_number(
            storage_raw.get("pcap_limit_gib"), "storage.pcap_limit_gib"
        ),
        plaintext_limit_gib=_positive_number(
            storage_raw.get("plaintext_limit_gib"), "storage.plaintext_limit_gib"
        ),
        structured_limit_gib=_positive_number(
            storage_raw.get("structured_limit_gib"), "storage.structured_limit_gib"
        ),
    )

    mounts_raw = root.get("mounts", [])
    if not isinstance(mounts_raw, list):
        raise ConfigError("mounts 必须是列表")
    mounts = tuple(_mount(item, index, target.home) for index, item in enumerate(mounts_raw))
    _validate_mounts(mounts, paths)

    upstream_raw = _mapping(root.get("upstream", {}), "upstream")
    upstream_kind = _string(upstream_raw.get("kind", "unset"), "upstream.kind")
    if upstream_kind not in {"unset", "http", "tun"}:
        raise ConfigError("upstream.kind 当前只允许 unset、http 或 tun")
    upstream_host: str | None = None
    upstream_port: int | None = None
    expected_exit_cidr: str | None = None
    if upstream_kind == "http":
        upstream_host = _string(upstream_raw.get("host"), "upstream.host")
        if upstream_host not in {"127.0.0.1", "localhost", "::1"}:
            raise ConfigError("http 上游当前只允许本机地址 127.0.0.1/localhost/::1")
        upstream_port = _integer(upstream_raw.get("port"), "upstream.port")
        if upstream_port < 1 or upstream_port > 65535:
            raise ConfigError("upstream.port 必须在 1 到 65535 之间")
        if upstream_raw.get("expected_exit_cidr") in (None, ""):
            raise ConfigError("http 上游必须显式填写 upstream.expected_exit_cidr")
        expected_exit_cidr = _public_network(
            upstream_raw.get("expected_exit_cidr"), "upstream.expected_exit_cidr"
        )
    config_value = upstream_raw.get("config_path")
    upstream = UpstreamConfig(
        kind=upstream_kind,
        host=upstream_host,
        port=upstream_port,
        config_path=(
            None
            if config_value in (None, "")
            else _user_path(config_value, "upstream.config_path", target.home)
        ),
        expected_exit_cidr=expected_exit_cidr,
    )

    profile_raw = _mapping(root.get("profile", {}), "profile")
    environment_value = profile_raw.get("default_conda_env")
    default_conda_env = (
        None
        if environment_value in (None, "")
        else _string(environment_value, "profile.default_conda_env")
    )
    if default_conda_env is not None and not _ENVIRONMENT_NAME_RE.fullmatch(
        default_conda_env
    ):
        raise ConfigError(
            "profile.default_conda_env 只能包含字母、数字、点、下划线和连字符"
        )
    timezone = _string(profile_raw.get("timezone", "UTC"), "profile.timezone")
    if ".." in timezone or timezone.startswith("/"):
        raise ConfigError("profile.timezone 必须是 IANA 时区名称")
    try:
        ZoneInfo(timezone)
    except ZoneInfoNotFoundError as exc:
        raise ConfigError(f"profile.timezone 不是已安装的 IANA 时区: {timezone}") from exc
    profile = HostProfile(
        claude_instructions=_optional_user_path(
            profile_raw.get("claude_instructions"),
            "profile.claude_instructions",
            target.home,
        ),
        bashrc=_optional_user_path(profile_raw.get("bashrc"), "profile.bashrc", target.home),
        login_profile=_optional_user_path(
            profile_raw.get("login_profile"), "profile.login_profile", target.home
        ),
        gitconfig=_optional_user_path(
            profile_raw.get("gitconfig"), "profile.gitconfig", target.home
        ),
        tmux_config=_optional_user_path(
            profile_raw.get("tmux_config"), "profile.tmux_config", target.home
        ),
        conda_root=_optional_user_path(
            profile_raw.get("conda_root"), "profile.conda_root", target.home
        ),
        default_conda_env=default_conda_env,
        timezone=timezone,
    )

    return HostConfig(
        schema_version=schema_version,
        instance=instance,
        target=target,
        paths=paths,
        docker=docker,
        gpu=gpu,
        storage=storage,
        mounts=mounts,
        upstream=upstream,
        profile=profile,
    )


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ConfigError(f"{name} 必须是对象")
    return value


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{name} 必须是非空字符串")
    return value.strip()


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{name} 必须是整数")
    return value


def _nonnegative_int(value: Any, name: str) -> int:
    parsed = _integer(value, name)
    if parsed < 0:
        raise ConfigError(f"{name} 不能为负数")
    return parsed


def _positive_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
        raise ConfigError(f"{name} 必须是正数")
    return float(value)


def _absolute_path(value: Any, name: str) -> Path:
    path = Path(_string(value, name))
    if not path.is_absolute():
        raise ConfigError(f"{name} 必须是绝对路径")
    return path


def _user_path(value: Any, name: str, user_home: Path) -> Path:
    text = _string(value, name)
    if text == "~":
        return user_home
    if text.startswith("~/"):
        return user_home / text[2:]
    path = Path(text)
    return path if path.is_absolute() else user_home / path


def _optional_user_path(value: Any, name: str, user_home: Path) -> Path | None:
    if value in (None, ""):
        return None
    return _user_path(value, name, user_home)


def _public_network(value: Any, name: str) -> str:
    import ipaddress

    text = _string(value, name)
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ConfigError(f"{name} 必须是有效的公网 CIDR") from exc
    if not network.network_address.is_global or not network[-1].is_global:
        raise ConfigError(f"{name} 只能声明公网地址范围")
    return str(network)


def _threshold(value: Any, name: str) -> StorageThreshold:
    raw = _mapping(value, name)
    min_free_gib = _positive_number(raw.get("min_free_gib"), f"{name}.min_free_gib")
    min_free_percent = _positive_number(
        raw.get("min_free_percent"), f"{name}.min_free_percent"
    )
    if min_free_percent > 100:
        raise ConfigError(f"{name}.min_free_percent 不能超过 100")
    return StorageThreshold(min_free_gib, min_free_percent)


def _mount(value: Any, index: int, user_home: Path) -> ProjectMount:
    raw = _mapping(value, f"mounts[{index}]")
    access = _string(raw.get("access", "rw"), f"mounts[{index}].access")
    if access not in {"ro", "rw"}:
        raise ConfigError(f"mounts[{index}].access 只允许 ro 或 rw")
    return ProjectMount(
        host_path=_user_path(raw.get("host_path"), f"mounts[{index}].host_path", user_home),
        container_path=_absolute_path(
            raw.get("container_path"), f"mounts[{index}].container_path"
        ),
        read_only=access == "ro",
    )


def _overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _validate_distinct_paths(paths: HostPaths) -> None:
    named = {
        "paths.persistent_home": paths.persistent_home,
        "paths.state": paths.state,
        "paths.audit": paths.audit,
    }
    items = list(named.items())
    for index, (left_name, left) in enumerate(items):
        for right_name, right in items[index + 1 :]:
            if _overlap(left, right):
                raise ConfigError(f"{left_name} 与 {right_name} 不能重叠")


def _validate_mounts(mounts: tuple[ProjectMount, ...], paths: HostPaths) -> None:
    seen_host: set[Path] = set()
    seen_container: set[Path] = set()
    protected = (paths.state, paths.audit, paths.persistent_home)
    for mount in mounts:
        if mount.host_path in seen_host:
            raise ConfigError(f"重复宿主挂载路径: {mount.host_path}")
        if mount.container_path in seen_container:
            raise ConfigError(f"重复容器挂载路径: {mount.container_path}")
        if any(_overlap(mount.host_path, item) for item in protected):
            raise ConfigError(f"项目挂载不能暴露控制或审计目录: {mount.host_path}")
        seen_host.add(mount.host_path)
        seen_container.add(mount.container_path)
