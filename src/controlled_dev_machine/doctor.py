from __future__ import annotations

import os
import platform
import pwd
import re
import shutil
import socket
import subprocess
from dataclasses import asdict, dataclass
from enum import IntEnum
from pathlib import Path

from controlled_dev_machine.config import HostConfig, StorageThreshold


class CheckLevel(IntEnum):
    PASS = 0
    WARN = 1
    BLOCKED = 2


@dataclass(frozen=True)
class Check:
    name: str
    level: CheckLevel
    message: str
    facts: dict[str, object]

    def as_json(self) -> dict[str, object]:
        result = asdict(self)
        result["level"] = self.level.name.lower()
        return result


def run_doctor(config: HostConfig) -> tuple[Check, ...]:
    checks = [
        _identity_check(config),
        _cgroup_check(),
        _apparmor_check(),
        _docker_socket_check(config),
        _docker_engine_check(config),
        _architecture_check(),
        _docker_compose_check(),
        _systemd_check(),
        _filesystem_check("root_storage", Path("/"), config.storage.root),
        _filesystem_check("audit_storage", config.paths.audit, config.storage.audit),
    ]
    for command, required in (
        ("docker", True),
        ("nsenter", True),
        ("tcpdump", True),
        ("bpftrace", True),
        ("bpftool", False),
        ("nft", True),
        ("skopeo", True),
        ("curl", True),
        ("openssl", True),
        ("systemctl", True),
        ("ip", True),
        ("nvidia-ctk", config.gpu.mode == "all"),
    ):
        checks.append(_command_check(command, required=required))
    if config.upstream.kind == "unset":
        checks.append(
            Check(
                "upstream",
                CheckLevel.WARN,
                "尚未配置公网父代理；只能进行离线和全断测试",
                {"kind": "unset"},
            )
        )
    else:
        checks.append(_upstream_check(config))
    if config.gpu.mode == "all":
        checks.append(_gpu_cdi_check())
    return tuple(checks)


def overall_level(checks: tuple[Check, ...]) -> CheckLevel:
    return max((check.level for check in checks), default=CheckLevel.PASS)


def _identity_check(config: HostConfig) -> Check:
    try:
        account = pwd.getpwnam(config.target.name)
    except KeyError:
        return Check(
            "target_identity",
            CheckLevel.BLOCKED,
            "目标账号不存在",
            {"name": config.target.name},
        )
    matches = (
        account.pw_uid == config.target.uid
        and account.pw_gid == config.target.gid
        and Path(account.pw_dir) == config.target.home
    )
    return Check(
        "target_identity",
        CheckLevel.PASS if matches else CheckLevel.BLOCKED,
        "目标账号与配置一致" if matches else "目标账号 UID/GID/Home 与配置不一致",
        {
            "configured_uid": config.target.uid,
            "actual_uid": account.pw_uid,
            "configured_gid": config.target.gid,
            "actual_gid": account.pw_gid,
            "configured_home": str(config.target.home),
            "actual_home": account.pw_dir,
        },
    )


def _cgroup_check() -> Check:
    path = Path("/sys/fs/cgroup/cgroup.controllers")
    return Check(
        "cgroup_v2",
        CheckLevel.PASS if path.is_file() else CheckLevel.BLOCKED,
        "cgroup v2 可用" if path.is_file() else "未检测到 cgroup v2",
        {"path": str(path)},
    )


def _apparmor_check() -> Check:
    path = Path("/sys/module/apparmor/parameters/enabled")
    enabled = path.is_file() and path.read_text(encoding="ascii").strip().upper() == "Y"
    return Check(
        "apparmor",
        CheckLevel.PASS if enabled else CheckLevel.BLOCKED,
        "AppArmor 已启用" if enabled else "AppArmor 未启用",
        {"path": str(path)},
    )


def _docker_socket_check(config: HostConfig) -> Check:
    path = config.docker.socket
    exists = path.exists()
    accessible = exists and os.access(path, os.R_OK | os.W_OK)
    if accessible:
        message = "登记的 Docker socket 可访问"
        level = CheckLevel.PASS
    elif exists:
        message = "Docker socket 存在，但当前进程无权访问；部署阶段需要宿主提权"
        level = CheckLevel.BLOCKED
    else:
        message = "登记的 Docker socket 不存在"
        level = CheckLevel.BLOCKED
    return Check(
        "docker_socket",
        level,
        message,
        {"path": str(path), "exists": exists, "accessible": accessible},
    )


def _docker_compose_check() -> Check:
    docker = shutil.which("docker")
    if docker is None:
        return Check(
            "docker_compose",
            CheckLevel.BLOCKED,
            "缺少 Docker Compose v2 插件",
            {"version": None},
        )
    result = subprocess.run(
        [docker, "compose", "version", "--short"],
        check=False,
        capture_output=True,
        text=True,
    )
    version = result.stdout.strip() if result.returncode == 0 else None
    match = re.match(r"v?(\d+)", version or "")
    supported = bool(match and int(match.group(1)) >= 2)
    return Check(
        "docker_compose",
        CheckLevel.PASS if supported else CheckLevel.BLOCKED,
        "Docker Compose v2 可用" if supported else "缺少 Docker Compose v2 插件",
        {"version": version},
    )


def _docker_engine_check(config: HostConfig) -> Check:
    docker = shutil.which("docker")
    if docker is None:
        return Check(
            "docker_engine",
            CheckLevel.BLOCKED,
            "缺少 Docker Engine 28+",
            {"version": None},
        )
    result = subprocess.run(
        [
            docker,
            "--host",
            f"unix://{config.docker.socket}",
            "version",
            "--format",
            "{{.Server.Version}}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    version = result.stdout.strip() if result.returncode == 0 else None
    match = re.match(r"(\d+)", version or "")
    supported = bool(match and int(match.group(1)) >= 28)
    return Check(
        "docker_engine",
        CheckLevel.PASS if supported else CheckLevel.BLOCKED,
        "Docker Engine 28+ 可用" if supported else "Docker Engine 版本低于 28 或不可访问",
        {"version": version},
    )


def _architecture_check() -> Check:
    machine = platform.machine()
    supported = machine in {"x86_64", "amd64"}
    return Check(
        "architecture",
        CheckLevel.PASS if supported else CheckLevel.BLOCKED,
        "宿主架构为 amd64" if supported else "当前发布只支持 amd64",
        {"machine": machine},
    )


def _systemd_check() -> Check:
    path = Path("/run/systemd/system")
    available = path.is_dir()
    return Check(
        "systemd",
        CheckLevel.PASS if available else CheckLevel.BLOCKED,
        "systemd 正在管理宿主" if available else "宿主不是可用的 systemd 环境",
        {"path": str(path)},
    )


def _upstream_check(config: HostConfig) -> Check:
    if config.upstream.kind == "tun":
        return Check(
            "upstream",
            CheckLevel.BLOCKED,
            "tun 上游适配器尚未实现；当前只支持 HTTP 父代理",
            {"kind": "tun"},
        )
    assert config.upstream.host is not None and config.upstream.port is not None
    reachable = False
    detail = ""
    try:
        with socket.create_connection(
            (config.upstream.host, config.upstream.port), timeout=2
        ):
            reachable = True
    except OSError as exc:
        detail = str(exc)
    config_path = config.upstream.config_path
    config_ok = config_path is None or config_path.is_file()
    passed = reachable and config_ok
    if not config_ok:
        message = "父代理配置记录指向不存在的文件"
    elif not reachable:
        message = "本机父代理端口不可连接"
    else:
        message = "本机父代理端口可连接"
    return Check(
        "upstream",
        CheckLevel.PASS if passed else CheckLevel.BLOCKED,
        message,
        {
            "kind": config.upstream.kind,
            "host": config.upstream.host,
            "port": config.upstream.port,
            "expected_exit_cidr": config.upstream.expected_exit_cidr,
            "config_path": str(config_path) if config_path is not None else None,
            "config_path_ok": config_ok,
            "detail": detail,
        },
    )


def _gpu_cdi_check() -> Check:
    command = shutil.which("nvidia-ctk")
    if command is None:
        return Check(
            "gpu_cdi",
            CheckLevel.BLOCKED,
            "缺少 NVIDIA CDI 管理工具",
            {"device": "nvidia.com/gpu=all"},
        )
    result = subprocess.run(
        [command, "cdi", "list"], check=False, capture_output=True, text=True
    )
    available = result.returncode == 0 and "nvidia.com/gpu=all" in result.stdout.splitlines()
    return Check(
        "gpu_cdi",
        CheckLevel.PASS if available else CheckLevel.BLOCKED,
        "全部 GPU 的 CDI 设备可用" if available else "缺少 nvidia.com/gpu=all CDI 设备",
        {"device": "nvidia.com/gpu=all"},
    )


def _filesystem_check(name: str, path: Path, threshold: StorageThreshold) -> Check:
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    usage = shutil.disk_usage(probe)
    required = threshold.required_free_bytes(usage.total)
    enough = usage.free >= required
    return Check(
        name,
        CheckLevel.PASS if enough else CheckLevel.BLOCKED,
        "剩余空间达到保留线" if enough else "剩余空间低于保留线",
        {
            "configured_path": str(path),
            "mount_probe": str(probe),
            "total_bytes": usage.total,
            "free_bytes": usage.free,
            "required_free_bytes": required,
        },
    )


def _command_check(command: str, *, required: bool) -> Check:
    path = shutil.which(command)
    level = CheckLevel.PASS if path else (CheckLevel.BLOCKED if required else CheckLevel.WARN)
    return Check(
        f"command:{command}",
        level,
        f"{command} 可用" if path else f"缺少命令: {command}",
        {"path": path},
    )
