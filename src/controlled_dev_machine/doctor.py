from __future__ import annotations

import ipaddress
import json
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
from typing import Any

from controlled_dev_machine.config import HostConfig, StorageThreshold
from controlled_dev_machine.errors import DeploymentError
from controlled_dev_machine.policy import load_policy
from controlled_dev_machine.runtime import (
    _gateway_build_digest,
    _load_image_record,
    _target_build_digest,
    audit_status,
    load_runtime,
)


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
    action: str | None = None

    def as_json(self) -> dict[str, object]:
        result = asdict(self)
        result["level"] = self.level.name.lower()
        if self.action is None:
            result.pop("action", None)
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
        _ssh_host_check(config),
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
        ("iptables", config.ssh.enabled),
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
    checks.extend(_runtime_checks(config))
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
        "sudo bin/sandboxctl doctor --json" if not accessible else None,
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
            "修改 host.yaml 为 HTTP 父代理后重新运行 doctor",
        )
    assert config.upstream.host is not None and config.upstream.port is not None
    reachable = False
    detail = ""
    try:
        with socket.create_connection((config.upstream.host, config.upstream.port), timeout=2):
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
        "systemctl --user status claude-sandbox-mihomo.service --no-pager" if not passed else None,
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
    result = subprocess.run([command, "cdi", "list"], check=False, capture_output=True, text=True)
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
        "sudo bin/sandboxctl storage plan" if not enough else None,
    )


def _command_check(command: str, *, required: bool) -> Check:
    path = shutil.which(command)
    level = CheckLevel.PASS if path else (CheckLevel.BLOCKED if required else CheckLevel.WARN)
    return Check(
        f"command:{command}",
        level,
        f"{command} 可用" if path else f"缺少命令: {command}",
        {"path": path},
        f"安装或恢复 {command} 后重新运行 doctor" if path is None else None,
    )


def _ssh_host_check(config: HostConfig) -> Check:
    if not config.ssh.enabled:
        return Check(
            "ssh_host",
            CheckLevel.PASS,
            "主机配置未启用 SSH 出站路径",
            {"enabled": False},
        )
    interface_path = Path("/sys/class/net", config.ssh.interface)
    interface_ok = interface_path.is_dir()
    route_failures: list[str] = []
    ip = shutil.which("ip")
    if ip is None:
        route_failures.extend(config.ssh.allowed_addresses)
    else:
        for address in config.ssh.allowed_addresses:
            result = subprocess.run(
                [ip, "route", "get", address],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                route_failures.append(address)
    expected_mounts = {config.target.home / ".ssh"}
    gamma_ssh = config.target.home / ".local/share/gamma-ssh"
    if gamma_ssh.exists():
        expected_mounts.add(gamma_ssh)
    ssh_mounts = [
        mount
        for mount in config.mounts
        if mount.container_path in expected_mounts
    ]
    mounted_targets = {mount.container_path for mount in ssh_mounts}
    unconfigured_mounts = [str(path) for path in sorted(expected_mounts - mounted_targets)]
    missing_mounts = [str(mount.host_path) for mount in ssh_mounts if not mount.host_path.exists()]
    writable_mounts = [str(mount.host_path) for mount in ssh_mounts if not mount.read_only]
    passed = (
        interface_ok
        and not route_failures
        and not unconfigured_mounts
        and not missing_mounts
        and not writable_mounts
    )
    if not interface_ok:
        message = "SSH 网络接口不存在"
    elif route_failures:
        message = "一个或多个 SSH 地址没有宿主路由"
    elif unconfigured_mounts or missing_mounts or writable_mounts:
        message = "SSH 挂载缺失或不是只读"
    else:
        message = "SSH 接口、精确地址路由和只读挂载已就绪"
    return Check(
        "ssh_host",
        CheckLevel.PASS if passed else CheckLevel.BLOCKED,
        message,
        {
            "enabled": True,
            "interface": config.ssh.interface,
            "interface_ok": interface_ok,
            "allowed_addresses": list(config.ssh.allowed_addresses),
            "ports": list(config.ssh.ports),
            "route_failures": route_failures,
            "mounts": [str(mount.host_path) for mount in ssh_mounts],
            "unconfigured_mounts": unconfigured_mounts,
            "missing_mounts": missing_mounts,
            "writable_mounts": writable_mounts,
        },
        "修复 Tailscale 接口、路由或 SSH 只读挂载后重新运行 doctor"
        if not passed
        else None,
    )


def _runtime_checks(config: HostConfig) -> tuple[Check, ...]:
    """Collect fast, read-only facts about the current instance after a reboot."""
    if not hasattr(config, "resource_prefix"):
        return ()
    try:
        manifest = load_runtime(config)
    except Exception as exc:  # doctor must report a broken state instead of aborting
        return (
            Check(
                "runtime_manifest",
                CheckLevel.BLOCKED,
                f"运行清单不可用: {exc}",
                {"path": str(_runtime_manifest_path(config)), "detail_type": type(exc).__name__},
                _rebuild_action(config),
            ),
        )

    checks: list[Check] = [_runtime_manifest_check(config, manifest)]
    checks.append(_ssh_runtime_check(config, manifest))
    checks.append(_runtime_images_check(config, manifest))
    compose_check, target_container = _runtime_compose_check(config, manifest)
    checks.append(compose_check)
    checks.append(_systemd_runtime_check(config, runtime_ok=compose_check.level == CheckLevel.PASS))
    checks.append(_runtime_audit_check(config))
    checks.append(_runtime_pcap_check(config))
    network_check = _target_network_check(config, target_container)
    checks.append(network_check)
    checks.append(_target_claude_check(config, target_container))
    if config.upstream.kind != "unset":
        checks.append(_upstream_http_check(config))
    return tuple(checks)


def _ssh_runtime_check(config: HostConfig, manifest: Any) -> Check:
    configured = {
        "enabled": config.ssh.enabled,
        "interface": config.ssh.interface,
        "allowed_addresses": list(config.ssh.allowed_addresses),
        "ports": list(config.ssh.ports),
    }
    active = {
        "enabled": manifest.ssh_enabled,
        "interface": manifest.ssh_interface,
        "allowed_addresses": list(manifest.ssh_allowed_addresses),
        "ports": list(manifest.ssh_ports),
    }
    matches = configured == active
    return Check(
        "ssh_runtime",
        CheckLevel.PASS if matches else CheckLevel.WARN,
        "SSH 主机配置已写入当前运行清单"
        if matches
        else "SSH 主机配置尚未应用；当前实例继续使用旧运行清单",
        {"configured": configured, "active": active},
        "容器可中断后使用当前策略执行 stop、init、start，再验证 SSH"
        if not matches
        else None,
    )


def _runtime_manifest_path(config: HostConfig) -> Path:
    return config.paths.state / "generated" / "current" / "runtime.json"


def _runtime_manifest_check(config: HostConfig, manifest: Any) -> Check:
    facts: dict[str, object] = {
        "resource_prefix": manifest.resource_prefix,
        "compose_path": manifest.compose_path,
        "policy_digest": manifest.policy_digest,
        "target_image": manifest.target_image,
        "gateway_image": manifest.gateway_image,
    }
    try:
        gateway_digest = _gateway_build_digest(Path(manifest.repo_root))
        target_digest = _target_build_digest(config, Path(manifest.repo_root))
        facts.update(
            {
                "gateway_build_digest": manifest.gateway_build_digest,
                "gateway_build_digest_current": gateway_digest,
                "target_build_digest": manifest.target_build_digest,
                "target_build_digest_current": target_digest,
            }
        )
        snapshot = load_policy(Path(manifest.policy_snapshot_path))
        active = load_policy(Path(manifest.policy_path))
        facts["policy_snapshot_digest"] = snapshot.digest()
        facts["policy_active_digest"] = active.digest()
        if snapshot.digest() != manifest.policy_digest or active.digest() != manifest.policy_digest:
            return Check(
                "runtime_manifest",
                CheckLevel.BLOCKED,
                "活动策略或不可变策略快照与运行清单不一致",
                facts,
                _rebuild_action(config, manifest),
            )
        if (
            gateway_digest != manifest.gateway_build_digest
            or target_digest != manifest.target_build_digest
        ):
            return Check(
                "runtime_manifest",
                CheckLevel.WARN,
                "运行清单与当前构建输入摘要不一致；当前容器可继续使用，但下次启动前需重建",
                facts,
                _rebuild_action(config, manifest),
            )
    except Exception as exc:
        facts["detail_type"] = type(exc).__name__
        return Check(
            "runtime_manifest",
            CheckLevel.BLOCKED,
            f"运行清单关联文件检查失败: {exc}",
            facts,
            _rebuild_action(config, manifest),
        )
    return Check("runtime_manifest", CheckLevel.PASS, "运行清单与当前代码、策略一致", facts)


def _runtime_images_check(config: HostConfig, manifest: Any) -> Check:
    facts: dict[str, object] = {
        "target_image": manifest.target_image,
        "gateway_image": manifest.gateway_image,
    }
    try:
        record = _load_image_record(config, manifest)
        facts["target_image_id_recorded"] = record["target_image_id"]
        facts["gateway_image_id_recorded"] = record["gateway_image_id"]
        for kind, image, label in (
            ("target", manifest.target_image, "org.controlled-dev-machine.target-build-digest"),
            ("gateway", manifest.gateway_image, "org.controlled-dev-machine.gateway-build-digest"),
        ):
            result = _docker_run(
                config,
                "image",
                "inspect",
                "--format",
                "{{.Id}}\t{{index .Config.Labels `" + label + "`}}",
                image,
            )
            if result.returncode != 0:
                raise DeploymentError(f"{kind} 镜像不可访问")
            fields = result.stdout.strip().split("\t", 1)
            if len(fields) != 2:
                raise DeploymentError(f"{kind} 镜像检查结果缺少摘要")
            facts[f"{kind}_image_id_current"] = fields[0]
            facts[f"{kind}_build_digest_label"] = fields[1]
            if fields[0] != record[f"{kind}_image_id"]:
                raise DeploymentError(f"{kind} 镜像内容 ID 与构建记录不一致")
            if fields[1] != getattr(manifest, f"{kind}_build_digest"):
                raise DeploymentError(f"{kind} 镜像构建摘要标签不一致")
    except Exception as exc:
        facts["detail_type"] = type(exc).__name__
        return Check(
            "runtime_images",
            CheckLevel.WARN,
            f"运行镜像与构建记录不一致；下次启动前需重建: {exc}",
            facts,
            _rebuild_action(config, manifest),
        )
    return Check("runtime_images", CheckLevel.PASS, "目标和网关镜像与构建记录一致", facts)


def _runtime_compose_check(config: HostConfig, manifest: Any) -> tuple[Check, str | None]:
    expected = {"canary", "dns", "gateway", "target"}
    facts: dict[str, object] = {"expected_services": sorted(expected)}
    try:
        result = _docker_run(
            config,
            "compose",
            "--project-name",
            manifest.resource_prefix,
            "-f",
            manifest.compose_path,
            "ps",
            "--format",
            "json",
        )
        if result.returncode != 0:
            raise DeploymentError("Docker Compose 状态查询失败")
        rows = _parse_compose_json(result.stdout)
        services: dict[str, dict[str, object]] = {}
        for row in rows:
            service = str(row.get("Service") or row.get("service") or "")
            if service:
                services[service] = {
                    "name": row.get("Name") or row.get("name"),
                    "state": row.get("State") or row.get("state"),
                    "health": row.get("Health") or row.get("health"),
                    "status": row.get("Status") or row.get("status"),
                }
        facts["services"] = services
        missing = sorted(expected - services.keys())
        stopped = sorted(
            service
            for service, row in services.items()
            if service in expected and str(row.get("state", "")).lower() != "running"
        )
        unhealthy = sorted(
            service
            for service, row in services.items()
            if service in {"canary", "dns", "gateway"}
            and str(row.get("health", "")).lower() not in {"healthy"}
        )
        if missing or stopped:
            return (
                Check(
                    "runtime_containers",
                    CheckLevel.BLOCKED,
                    "一个或多个受控容器缺失或未运行",
                    {**facts, "missing": missing, "stopped": stopped},
                    "sudo bin/sandboxctl start",
                ),
                _target_container_name(services),
            )
        if unhealthy:
            return (
                Check(
                    "runtime_containers",
                    CheckLevel.BLOCKED,
                    "DNS、网关或 canary 容器未报告 healthy",
                    {**facts, "unhealthy": unhealthy},
                    "sudo bin/sandboxctl status && sudo docker logs <容器名>",
                ),
                _target_container_name(services),
            )
        return (
            Check(
                "runtime_containers",
                CheckLevel.PASS,
                "四个受控容器均在运行且基础健康检查通过",
                facts,
            ),
            _target_container_name(services),
        )
    except Exception as exc:
        facts["detail_type"] = type(exc).__name__
        return (
            Check(
                "runtime_containers",
                CheckLevel.BLOCKED,
                f"无法读取受控容器状态: {exc}",
                facts,
                "sudo bin/sandboxctl status",
            ),
            None,
        )


def _target_container_name(services: dict[str, dict[str, object]]) -> str | None:
    row = services.get("target")
    name = row.get("name") if row else None
    return str(name) if name else None


def _systemd_runtime_check(config: HostConfig, *, runtime_ok: bool) -> Check:
    units = {
        "sandbox_service": f"{config.resource_prefix}.service",
        "parent_guard": f"{config.resource_prefix}-parent-guard.service",
        "audit_rotate_timer": f"{config.resource_prefix}-audit-rotate.timer",
    }
    facts: dict[str, object] = {"units": {}}
    for key, unit in units.items():
        state = _systemd_unit_state(unit)
        facts["units"][key] = state
    mihomo = _systemd_user_unit_state(config, "claude-sandbox-mihomo.service")
    facts["mihomo"] = mihomo
    service = facts["units"]["sandbox_service"]
    guard = facts["units"]["parent_guard"]
    timer = facts["units"]["audit_rotate_timer"]
    if not service["enabled"] or not guard["enabled"] or not timer["enabled"]:
        return Check(
            "systemd_runtime",
            CheckLevel.BLOCKED,
            "自动启动或审计轮转 unit 未启用",
            facts,
            "sudo bin/sandboxctl automation install",
        )
    if config.upstream.kind != "unset" and mihomo["active"] is not True:
        return Check(
            "systemd_runtime",
            CheckLevel.BLOCKED,
            "父代理用户服务未 active",
            facts,
            "systemctl --user restart claude-sandbox-mihomo.service",
        )
    if not guard["active"]:
        return Check(
            "systemd_runtime",
            CheckLevel.BLOCKED,
            "父代理宿主门禁未 active",
            facts,
            f"sudo systemctl start {units['parent_guard']}",
        )
    if not service["active"]:
        message = (
            "自动启动 unit 当前未 active，但受控容器仍在运行"
            if runtime_ok
            else "自动启动 unit 当前未 active"
        )
        return Check(
            "systemd_runtime",
            CheckLevel.WARN,
            message,
            facts,
            f"sudo systemctl status {units['sandbox_service']} --no-pager",
        )
    return Check(
        "systemd_runtime",
        CheckLevel.PASS,
        "自动启动、父代理门禁和审计轮转均已就绪",
        facts,
    )


def _runtime_audit_check(config: HostConfig) -> Check:
    try:
        state = audit_status(config)
    except Exception as exc:
        return Check(
            "runtime_audit",
            CheckLevel.BLOCKED,
            f"审计状态无法读取: {exc}",
            {"detail_type": type(exc).__name__},
            "sudo bin/sandboxctl audit status",
        )
    facts = {
        "active": state.get("active"),
        "run_id": state.get("run_id"),
        "processes": state.get("processes", []),
        "namespaces": state.get("namespaces", []),
    }
    if state.get("active") is not True:
        return Check(
            "runtime_audit",
            CheckLevel.BLOCKED,
            "基础审计未 active 或存在失活探针",
            facts,
            "sudo bin/sandboxctl audit restart",
        )
    return Check("runtime_audit", CheckLevel.PASS, "基础审计进程和网络命名空间均存活", facts)


def _runtime_pcap_check(config: HostConfig) -> Check:
    try:
        state = audit_status(config)
        run_id = state.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            raise DeploymentError("当前审计没有运行编号")
        pcap_root = config.paths.audit / "pcap" / run_id
        alias = Path("/run/controlled-dev-machine-pcap") / config.resource_prefix
        files: dict[str, list[dict[str, object]]] = {}
        for kind in ("target", "gateway", "dns"):
            matches = sorted(pcap_root.glob(f"{kind}.pcap*"))
            files[kind] = [
                {
                    "name": path.name,
                    "size": path.stat().st_size,
                    "mode": oct(path.stat().st_mode & 0o777),
                }
                for path in matches
                if path.is_file()
            ]
        alias_matches_root = (
            alias.exists() and pcap_root.parent.exists() and alias.samefile(pcap_root.parent)
        )
        facts = {
            "run_id": run_id,
            "pcap_root": str(pcap_root),
            "pcap_alias": str(alias),
            "alias_is_mountpoint": os.path.ismount(alias),
            "alias_matches_root": alias_matches_root,
            "files": files,
        }
        audit_active = state.get("active") is True
        facts["audit_active"] = audit_active
        missing = [kind for kind, entries in files.items() if not entries]
        if (
            missing
            or not audit_active
            or not facts["alias_is_mountpoint"]
            or not facts["alias_matches_root"]
        ):
            return Check(
                "runtime_pcap",
                CheckLevel.BLOCKED,
                "PCAP 抓包目录或绑定路径不完整",
                {**facts, "missing": missing},
                "sudo bin/sandboxctl audit restart",
            )
        return Check(
            "runtime_pcap",
            CheckLevel.PASS,
            "当前审计运行目录存在三处 PCAP，且对应探针存活",
            facts,
        )
    except Exception as exc:
        return Check(
            "runtime_pcap",
            CheckLevel.BLOCKED,
            f"PCAP 状态无法验证: {exc}",
            {"detail_type": type(exc).__name__},
            "sudo bin/sandboxctl audit status",
        )


def _target_network_check(config: HostConfig, container: str | None) -> Check:
    if not container:
        return Check(
            "target_network",
            CheckLevel.BLOCKED,
            "找不到目标容器，无法执行目标环境网络探测",
            {},
            "sudo bin/sandboxctl start",
        )
    script = "\n".join(
        (
            "set +e",
            "printf 'ping_dns=%s\\n' \"$(getent hosts ping0.cc 2>/dev/null | sed -n '1p')\"",
            "curl --silent --show-error --output /dev/null --max-time 8 "
            "--connect-timeout 4 --write-out "
            "'ping_http=%{http_code}\\nping_exit=%{exitcode}\\n' http://ping0.cc",
            "printf 'anthropic_dns=%s\\n' "
            "\"$(getent hosts api.anthropic.com 2>/dev/null | sed -n '1p')\"",
            "curl --silent --show-error --output /dev/null --max-time 8 "
            "--connect-timeout 4 --write-out "
            "'anthropic_http=%{http_code}\\nanthropic_exit=%{exitcode}\\n' "
            "https://api.anthropic.com/",
        )
    )
    result = _docker_run(config, "exec", container, "sh", "-c", script, timeout=20)
    facts: dict[str, object] = {
        "container": container,
        "returncode": result.returncode,
        "detail": _result_detail(result),
    }
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key.endswith("_dns"):
                facts[key] = bool(value.strip())
            else:
                facts[key] = value.strip()
    dns_ok = bool(facts.get("ping_dns")) and bool(facts.get("anthropic_dns"))
    curl_ok = facts.get("ping_exit") == "0" and facts.get("anthropic_exit") == "0"
    if result.returncode != 0 or not dns_ok or not curl_ok:
        return Check(
            "target_network",
            CheckLevel.BLOCKED,
            "目标环境 DNS 或 HTTPS 探测失败",
            facts,
            "sudo bin/sandboxctl audit restart",
        )
    return Check(
        "target_network",
        CheckLevel.PASS,
        "目标环境可解析公网域名并完成 HTTPS 连接",
        facts,
    )


def _target_claude_check(config: HostConfig, container: str | None) -> Check:
    if not container:
        return Check(
            "target_claude",
            CheckLevel.BLOCKED,
            "找不到目标容器，无法检查 Claude",
            {},
            "sudo bin/sandboxctl start",
        )
    command = "command -v claude; claude --version; claude auth status"
    result = _docker_run(
        config,
        "exec",
        "--user",
        f"{config.target.uid}:{config.target.gid}",
        container,
        "bash",
        "-lc",
        command,
        timeout=12,
    )
    lines = result.stdout.splitlines()
    version = next((line.strip() for line in lines if re.search(r"\b\d+\.\d+\.\d+\b", line)), None)
    auth = _parse_claude_auth(lines)
    facts: dict[str, object] = {
        "container": container,
        "returncode": result.returncode,
        "version": version,
        "auth": auth,
        "stdout_bytes": len(result.stdout.encode()),
        "stderr_bytes": len(result.stderr.encode()),
    }
    if result.returncode != 0 or version is None:
        return Check(
            "target_claude",
            CheckLevel.BLOCKED,
            "目标环境中的 Claude 命令不可用",
            facts,
            "sudo bin/sandboxctl shell",
        )
    if auth.get("loggedIn") is not True:
        return Check(
            "target_claude",
            CheckLevel.BLOCKED,
            "Claude 命令可用但当前未登录",
            facts,
            "sudo bin/sandboxctl shell",
        )
    return Check("target_claude", CheckLevel.PASS, "Claude 版本和登录状态可用", facts)


def _upstream_http_check(config: HostConfig) -> Check:
    if (
        config.upstream.kind != "http"
        or config.upstream.host is None
        or config.upstream.port is None
    ):
        return Check(
            "upstream_http",
            CheckLevel.BLOCKED,
            "当前上游不是可探测的 HTTP 父代理",
            {},
            "检查 host.yaml",
        )
    proxy_host = (
        f"[{config.upstream.host}]" if ":" in config.upstream.host else config.upstream.host
    )
    proxy = f"http://{proxy_host}:{config.upstream.port}"
    result = _host_run(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "8",
            "--proxy",
            proxy,
            "https://api.ipify.org",
        ],
        timeout=10,
    )
    observed = result.stdout.strip()
    facts: dict[str, object] = {
        "proxy": f"{config.upstream.host}:{config.upstream.port}",
        "returncode": result.returncode,
        "detail": _result_detail(result),
        "observed_exit_ip": observed if _is_ip(observed) else None,
        "expected_exit_cidr": config.upstream.expected_exit_cidr,
    }
    ip_ok = _is_ip(observed)
    cidr_ok = True
    if ip_ok and config.upstream.expected_exit_cidr:
        cidr_ok = ipaddress.ip_address(observed) in ipaddress.ip_network(
            config.upstream.expected_exit_cidr, strict=False
        )
    if result.returncode != 0 or not ip_ok or not cidr_ok:
        return Check(
            "upstream_http",
            CheckLevel.BLOCKED,
            "父代理不能完成 HTTPS 出口探测或出口不匹配",
            facts,
            "systemctl --user restart claude-sandbox-mihomo.service",
        )
    return Check("upstream_http", CheckLevel.PASS, "父代理 HTTPS 出口探测和固定出口校验通过", facts)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _parse_claude_auth(lines: list[str]) -> dict[str, object]:
    raw = "\n".join(lines)
    start = raw.find("{")
    end = raw.rfind("}")
    if start < 0 or end <= start:
        return {"parsed": False}
    try:
        value = json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return {"parsed": False}
    if not isinstance(value, dict):
        return {"parsed": False}
    allowed = ("loggedIn", "authMethod", "apiProvider", "subscriptionType")
    return {"parsed": True, **{key: value[key] for key in allowed if key in value}}


def _docker_run(
    config: HostConfig, *args: str, timeout: int = 6
) -> subprocess.CompletedProcess[str]:
    docker = shutil.which("docker") or "docker"
    return _host_run([docker, "--host", f"unix://{config.docker.socket}", *args], timeout=timeout)


def _parse_compose_json(raw: str) -> list[dict[str, object]]:
    value = raw.strip()
    if not value:
        return []
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        decoded = [json.loads(line) for line in value.splitlines() if line.strip()]
    if isinstance(decoded, dict):
        return [decoded]
    if not isinstance(decoded, list) or not all(isinstance(item, dict) for item in decoded):
        raise DeploymentError("Docker Compose 状态不是对象列表")
    return decoded


def _systemd_unit_state(unit: str) -> dict[str, object]:
    result = _host_run(
        ["systemctl", "show", unit, "--property=ActiveState,SubState,Result,Unit", "--no-pager"],
        timeout=5,
    )
    values = _key_values(result.stdout)
    return {
        "unit": unit,
        "enabled": _systemd_enabled(unit),
        "active": values.get("ActiveState") == "active",
        "active_state": values.get("ActiveState"),
        "sub_state": values.get("SubState"),
        "result": values.get("Result"),
        "returncode": result.returncode,
    }


def _systemd_user_unit_state(config: HostConfig, unit: str) -> dict[str, object]:
    result = _host_run(
        [
            "systemctl",
            f"--machine={config.target.name}@.host",
            "--user",
            "show",
            unit,
            "--property=ActiveState,SubState,Result,Unit",
            "--no-pager",
        ],
        timeout=5,
    )
    values = _key_values(result.stdout)
    return {
        "unit": unit,
        "active": values.get("ActiveState") == "active",
        "active_state": values.get("ActiveState"),
        "sub_state": values.get("SubState"),
        "result": values.get("Result"),
        "returncode": result.returncode,
    }


def _systemd_enabled(unit: str) -> bool:
    result = _host_run(
        ["systemctl", "is-enabled", unit],
        timeout=5,
    )
    return result.returncode == 0


def _key_values(raw: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in raw.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def _host_run(args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout
        )
        return subprocess.CompletedProcess(
            args,
            124,
            stdout=stdout or "",
            stderr="命令执行超时",
        )
    except OSError as exc:
        return subprocess.CompletedProcess(args, 127, stdout="", stderr=str(exc))


def _result_detail(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stderr or "").strip()[-1000:]


def _rebuild_action(config: HostConfig, manifest: Any | None = None) -> str:
    policy = (
        Path(manifest.policy_snapshot_path)
        if manifest is not None
        else config.paths.state / "generated" / "current" / "policy.active.yaml"
    )
    return (
        "sudo bin/sandboxctl stop && "
        f"sudo bin/sandboxctl init --policy {policy} && "
        "sudo -E bin/sandboxctl build && sudo bin/sandboxctl start"
    )
