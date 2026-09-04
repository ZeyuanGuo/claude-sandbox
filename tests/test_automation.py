from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from controlled_dev_machine.automation import (
    _proxy_host,
    _rotate_service,
    _rotate_timer,
    _sandbox_service,
)


def _config(tmp_path: Path):
    return SimpleNamespace(
        resource_prefix="cdm-u1010-main",
        target=SimpleNamespace(name="alice", uid=1010, gid=1010, home=tmp_path / "home" / "alice"),
        upstream=SimpleNamespace(kind="http", host="127.0.0.1", port=11450),
    )


def test_automation_units_use_target_home_and_do_not_start_immediately(tmp_path: Path) -> None:
    config = _config(tmp_path)
    manifest = SimpleNamespace(repo_root="/srv/claude-sandbox")

    service = _sandbox_service(config, manifest)
    rotate = _rotate_service(config)
    timer = _rotate_timer(config)

    assert f"Environment=HOME={config.target.home}" in service
    assert "systemctl --machine=alice@.host --user start claude-sandbox-mihomo.service" in service
    assert "ExecStart=/srv/claude-sandbox/bin/sandboxctl --config" in service
    assert "sandboxctl --config " in service and " recover\n" in service
    assert "storage rotate" in rotate
    assert "OnBootSec=15min" in timer
    assert "ExecStart" not in timer


def test_proxy_host_brackets_ipv6_addresses() -> None:
    assert _proxy_host("127.0.0.1") == "127.0.0.1"
    assert _proxy_host("::1") == "[::1]"
