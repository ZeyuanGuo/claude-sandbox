from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from controlled_dev_machine.config import load_host_config
from controlled_dev_machine.errors import DeploymentError
from controlled_dev_machine.storage import rotate_audit


def _config(tmp_path: Path):
    home = tmp_path / "home" / "alice"
    audit = home / ".cdm" / "audit"
    state = home / ".cdm" / "state"
    path = tmp_path / "host.yaml"
    path.write_text(
        f"""
schema_version: 1
instance: main
target:
  name: alice
  uid: 1000
  gid: 1000
  home: {home}
docker:
  socket: /var/run/docker.sock
paths:
  persistent_home: {home}/.cdm/home
  state: {state}
  audit: {audit}
storage:
  root:
    min_free_gib: 1
    min_free_percent: 1
  audit:
    min_free_gib: 1
    min_free_percent: 1
  pcap_limit_gib: 100
  plaintext_limit_gib: 50
  structured_limit_gib: 10
  pcap_retention_hours: 72
  plaintext_retention_hours: 72
  structured_retention_days: 30
upstream:
  kind: unset
mounts: []
""".lstrip(),
        encoding="utf-8",
    )
    return load_host_config(path)


def _run_id(when: datetime, suffix: str = "a") -> str:
    return when.strftime("%Y%m%dT%H%M%S.%fZ") + "-" + suffix * 8


def test_rotate_audit_deletes_only_expired_closed_data(tmp_path: Path, monkeypatch) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr("controlled_dev_machine.storage._geteuid", lambda: 0)
    monkeypatch.setattr("controlled_dev_machine.runtime._LIFECYCLE_LOCK_ROOT", tmp_path / "locks")
    now = datetime(2026, 9, 1, tzinfo=UTC)
    old_run = _run_id(now - timedelta(hours=100))
    active_run = _run_id(now - timedelta(hours=100), suffix="b")
    recent_run = _run_id(now - timedelta(hours=1))

    old_pcap = config.paths.audit / "pcap" / old_run
    active_pcap = config.paths.audit / "pcap" / active_run
    recent_pcap = config.paths.audit / "pcap" / recent_run
    old_structured = config.paths.audit / "structured" / _run_id(now - timedelta(days=31))
    for directory in (old_pcap, active_pcap, recent_pcap, old_structured):
        directory.mkdir(parents=True)
        (directory / "data").write_bytes(b"capture")

    old_archive = (
        config.paths.audit
        / "plaintext"
        / "archive"
        / ((now - timedelta(hours=100)).strftime("%Y%m%dT%H%M%S.%fZ") + "-" + "b" * 16 + ".mitm")
    )
    recent_archive = (
        config.paths.audit
        / "plaintext"
        / "archive"
        / ((now - timedelta(hours=1)).strftime("%Y%m%dT%H%M%S.%fZ") + "-" + "c" * 16 + ".mitm")
    )
    old_archive.parent.mkdir(parents=True)
    old_archive.write_bytes(b"old text")
    recent_archive.write_bytes(b"recent text")
    current_flow = config.paths.audit / "plaintext" / "flows.mitm"
    current_flow.write_bytes(b"current text")
    config.paths.state.mkdir(parents=True)
    (config.paths.state / "audit-active.json").write_text(
        json.dumps({"run_id": active_run}), encoding="utf-8"
    )

    result = rotate_audit(config, now=now)

    assert not old_pcap.exists()
    assert active_pcap.exists()
    assert recent_pcap.exists()
    assert not old_structured.exists()
    assert not old_archive.exists()
    assert recent_archive.exists()
    assert current_flow.read_bytes() == b"current text"
    assert result.active_run_id == active_run
    assert {item["kind"] for item in result.deleted} == {"pcap", "structured", "plaintext"}
    assert any(item["reason"] == "当前运行" for item in result.skipped)


def test_rotate_audit_fails_closed_when_active_state_is_missing_and_container_runs(
    tmp_path: Path, monkeypatch
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr("controlled_dev_machine.storage._geteuid", lambda: 0)
    monkeypatch.setattr("controlled_dev_machine.runtime._LIFECYCLE_LOCK_ROOT", tmp_path / "locks")
    monkeypatch.setattr("controlled_dev_machine.storage._project_running", lambda _config: True)

    with pytest.raises(DeploymentError, match="缺少审计运行清单"):
        rotate_audit(config)


def test_rotate_audit_requires_root(tmp_path: Path, monkeypatch) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr("controlled_dev_machine.storage._geteuid", lambda: 1000)

    with pytest.raises(DeploymentError, match="需要宿主提权"):
        rotate_audit(config)
