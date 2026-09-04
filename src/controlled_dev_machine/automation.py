from __future__ import annotations

import os
import subprocess
import tempfile
from contextlib import suppress
from pathlib import Path

from controlled_dev_machine.config import HostConfig
from controlled_dev_machine.errors import DeploymentError
from controlled_dev_machine.runtime import RuntimeManifest, load_runtime


def install_automation(config: HostConfig) -> tuple[Path, ...]:
    if os.geteuid() != 0:
        raise DeploymentError("自动启动和审计轮转需要宿主提权")
    if (
        config.upstream.kind != "http"
        or config.upstream.host is None
        or config.upstream.port is None
    ):
        raise DeploymentError("自动启动当前只支持已配置的 HTTP 父代理")
    manifest = load_runtime(config)
    guard_unit = Path("/etc/systemd/system") / f"{config.resource_prefix}-parent-guard.service"
    if not guard_unit.is_file():
        raise DeploymentError("尚未安装父代理门禁；先运行 sandboxctl guard")
    root = Path("/etc/systemd/system")
    service = root / f"{config.resource_prefix}.service"
    rotate_service = root / f"{config.resource_prefix}-audit-rotate.service"
    rotate_timer = root / f"{config.resource_prefix}-audit-rotate.timer"
    files = {
        service: _sandbox_service(config, manifest),
        rotate_service: _rotate_service(config),
        rotate_timer: _rotate_timer(config),
    }
    for path, content in files.items():
        if path.is_symlink():
            raise DeploymentError(f"自动化 unit 不能是符号链接: {path}")
        _write_unit(path, content)
    _run_systemctl("daemon-reload")
    _run_systemctl("enable", service.name, rotate_timer.name)
    return tuple(files)


def _sandbox_service(config: HostConfig, manifest: RuntimeManifest) -> str:
    config_path = config.target.home / ".config/controlled-dev-machine/host.yaml"
    return """[Unit]
Description=Controlled development machine
After=network-online.target docker.service {guard} user@{uid}.service
Wants=network-online.target user@{uid}.service
Requires={guard}
ConditionPathExists={config_path}

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=HOME={home}
Environment=SUDO_UID={uid}
Environment=SUDO_GID={gid}
Environment=SUDO_USER={name}
ExecStartPre=/usr/bin/loginctl enable-linger {name}
ExecStartPre=/usr/bin/systemctl --machine={name}@.host --user start claude-sandbox-mihomo.service
ExecStartPre=/usr/bin/curl --fail --silent --show-error --max-time 15 \
  --proxy http://{proxy_host}:{port} https://api.ipify.org
ExecStart={repo}/bin/sandboxctl --config {config_path} recover
ExecStop={repo}/bin/sandboxctl --config {config_path} stop
TimeoutStartSec=180
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
""".format(
        guard=f"{config.resource_prefix}-parent-guard.service",
        uid=config.target.uid,
        gid=config.target.gid,
        name=config.target.name,
        home=config.target.home,
        config_path=config_path,
        repo=manifest.repo_root,
        proxy_host=_proxy_host(config.upstream.host),
        port=config.upstream.port,
    )


def _rotate_service(config: HostConfig) -> str:
    config_path = config.target.home / ".config/controlled-dev-machine/host.yaml"
    return f"""[Unit]
Description=Rotate expired controlled development machine audit data
After=local-fs.target

[Service]
Type=oneshot
Environment=HOME={config.target.home}
Environment=SUDO_UID={config.target.uid}
Environment=SUDO_GID={config.target.gid}
Environment=SUDO_USER={config.target.name}
ExecStart={Path(__file__).resolve().parents[2]}/bin/sandboxctl --config {config_path} storage rotate
"""


def _rotate_timer(config: HostConfig) -> str:
    return """[Unit]
Description=Periodic audit retention cleanup

[Timer]
OnBootSec=15min
OnUnitActiveSec=15min
Persistent=true
RandomizedDelaySec=60
Unit={service}

[Install]
WantedBy=timers.target
""".format(service=f"{config.resource_prefix}-audit-rotate.service")


def _write_unit(path: Path, content: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        os.fchmod(descriptor, 0o644)
        os.fchown(descriptor, 0, 0)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(content)
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary)


def _proxy_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def _run_systemctl(*args: str) -> None:
    result = subprocess.run(["systemctl", *args], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise DeploymentError(f"systemctl 失败: {' '.join(args)}\n{detail[-1000:]}")
