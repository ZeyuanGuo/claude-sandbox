import json
from pathlib import Path
import threading

import pytest

from controlled_dev_machine.development import DevelopmentSandbox, install_entry, load_config
from controlled_dev_machine.exit_monitor import refresh, validate_exit_config


def exit_config():
    return {"parent_proxy": "http://192.0.2.10:18080", "expected_exit": "198.51.100.20",
            "probe_urls": ["https://probe-one.example/ip", "https://probe-two.example/ip"]}


def profile(tmp_path):
    home = tmp_path / "host"
    apps = tmp_path / "private/apps"
    (home / "project-a").mkdir(parents=True)
    apps.mkdir(parents=True)
    identity = tmp_path / "identity.json"
    identity.write_text(json.dumps({"hostname": "same-workstation", "machine_id": "a" * 32,
        "mac_address": "02:00:00:00:00:01", "timezone": "UTC", "lang": "en_US.UTF-8", "lc_all": "en_US.UTF-8",
        "boot_id": "12345678-1234-1234-1234-123456789012", "hostid": "01020304"}))
    root = Path(__file__).parents[1]
    value = {"schema_version": 2, "release": str(root), "release_id": "abcdef1234", "private_root": str(tmp_path / "private"),
        "host_home": str(home), "target_home": "/home/developer", "user": "developer", "uid": 1234, "gid": 1234,
        "project": "test-sandbox", "docker_context": "rootless", "python": "/usr/bin/python3", "uid_tools": str(tmp_path / "tools"),
        "target_image": "target:fixture", "gateway_image": "gateway:fixture", "mapper_image": "mapper:fixture",
        "identity_profile": str(identity), "mounts": [{"path": "project-a"}], "exit": exit_config(), "gpu": "none"}
    path = tmp_path / "deployment.json"
    path.write_text(json.dumps(value))
    return path, value


def test_native_launcher_install_does_not_overwrite_symlink_target(tmp_path):
    real = tmp_path / "vendor"
    real.write_bytes(b"native vendor program")
    entry = tmp_path / "claude"
    entry.symlink_to(real)
    install_entry(entry, "#!/bin/sh\nexit 2\n")
    assert not entry.is_symlink()
    assert real.read_bytes() == b"native vendor program"
    install_entry(entry, "#!/bin/sh\nexit 3\n")
    assert real.read_bytes() == b"native vendor program"


def test_render_mounts_private_home_and_only_explicit_host_paths(tmp_path):
    path, value = profile(tmp_path)
    app = DevelopmentSandbox(path)
    compose = app.render()
    target = compose["services"]["target"]
    mounts = {m["target"]: m for m in target["volumes"]}
    assert mounts["/home/developer"]["source"] == str(tmp_path / "private/uid-app/view/home")
    assert mounts["/home/developer/project-a"]["source"] == str(tmp_path / "private/uid-home/view/project-a")
    assert not any(m["source"] == str(tmp_path / "private/uid-home/view") for m in target["volumes"])
    assert "/var/tmp/claude-work" in mounts
    assert mounts["/home/developer/.claude"]["source"].endswith("uid-app/view/.claude")
    assert target["environment"]["CLAUDE_CODE_TMPDIR"] == "/var/tmp/claude-work"
    assert target["devices"] == []
    assert set(target["networks"]) == {"target_net"}
    assert compose["services"]["egress"]["environment"]["CDM_RELAY_EXPECTED_EXIT"] == value["exit"]["expected_exit"]
    assert "+/audit/plaintext/flows-%Y%m%d-%H.mitm" in compose["services"]["gateway"]["command"]


@pytest.mark.parametrize("bad", [".", "../private", ".ssh", ".local/share/docker", "/home/host"])
def test_config_refuses_whole_home_and_control_mounts(tmp_path, bad):
    path, value = profile(tmp_path)
    value["mounts"] = [{"path": bad}]
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        load_config(path)


def test_exit_is_an_exact_configured_address_not_a_hardcoded_provider():
    for address in ("198.51.100.20", "203.0.113.55"):
        config = dict(exit_config(), expected_exit=address)
        result = refresh(config, boot_id="test", probe_fn=lambda c, url: {"ok": True, "observed": c["expected_exit"]})
        assert result["ok"] and result["observed_exit"] == address
    with pytest.raises(ValueError):
        validate_exit_config(dict(exit_config(), expected_exit="198.51.100.0/24"))


@pytest.mark.parametrize("first", ["match", "timeout", "wrong"])
@pytest.mark.parametrize("second", ["match", "timeout", "wrong"])
def test_probe_or_policy_and_wrong_exit_precedence(first, second):
    def probe(config, endpoint):
        kind = first if endpoint.endswith("one.example/ip") else second
        if kind == "timeout":
            return {"ok": False, "error": "curl-exit-28"}
        observed = config["expected_exit"] if kind == "match" else "203.0.113.99"
        return {"ok": kind == "match", "observed": observed}
    published = []
    value = refresh(exit_config(), boot_id="test", probe_fn=probe, publish=published.append)
    expected = "match" in (first, second) and "wrong" not in (first, second)
    assert value["ok"] is expected
    assert value["probe_policy"] == "any-match"
    assert all(v["ok"] is expected for v in published)
    assert len(value["probes"]) == 2


def test_wrong_exit_revokes_before_slow_matching_probe_finishes():
    revoked = threading.Event()
    def probe(config, endpoint):
        if endpoint.endswith("one.example/ip"):
            return {"ok": False, "observed": "203.0.113.99"}
        assert revoked.wait(1)
        return {"ok": True, "observed": config["expected_exit"]}
    def publish(value):
        assert not value["ok"] and value["reason"] == "exit-mismatch"
        revoked.set()
    assert not refresh(exit_config(), boot_id="test", probe_fn=probe, publish=publish)["ok"]


def test_failed_probe_never_publishes_transient_failure_before_matching_sibling():
    finished = threading.Event()
    def probe(config, endpoint):
        if endpoint.endswith("one.example/ip"):
            finished.set()
            return {"ok": False, "error": "timeout"}
        assert finished.wait(1)
        return {"ok": True, "observed": config["expected_exit"]}
    published = []
    value = refresh(exit_config(), boot_id="test", probe_fn=probe, publish=published.append)
    assert value["ok"] and all(v["ok"] for v in published)


def test_missing_runtime_readiness_denies_without_any_probe(tmp_path):
    config = dict(exit_config(), readiness_path=str(tmp_path / "missing"), required_config_sha256="test")
    def forbidden(*args):
        raise AssertionError("unready runtime must not probe or issue a valid lease")
    value = refresh(config, boot_id="test", probe_fn=forbidden)
    assert not value["ok"] and value["reason"] == "runtime-not-ready"


def test_exit_display_is_opt_in_interactive_and_uses_the_controlled_proxy(tmp_path):
    path, value = profile(tmp_path)
    shell, env = DevelopmentSandbox(path).shell_content()
    assert "curl " not in shell
    value["interactive_exit_probe_url"] = "https://probe.example/ip"
    path.write_text(json.dumps(value))
    shell, env = DevelopmentSandbox(path).shell_content()
    assert "case $- in *i*) ( curl " in shell
    assert "--proxy http://172.31.0.23:8080" in shell
    assert "--max-time 5" in shell
    assert env["PYTHONNOUSERSITE"] == "1"
    assert env["PATH"].startswith("/opt/sbc/bin:")


def test_native_updater_absolute_link_is_resolved_in_persistent_home(tmp_path):
    path, _ = profile(tmp_path)
    app = DevelopmentSandbox(path)
    entry = app.apps / "home/.local/bin/claude"
    entry.parent.mkdir(parents=True)
    real = app.apps / "home/.local/share/claude/versions/new"
    real.parent.mkdir(parents=True)
    real.write_bytes(b"new native version")
    entry.symlink_to("/home/developer/.local/share/claude/versions/new")
    assert app.native_host_path() == real


def test_mount_preparation_refuses_to_hide_unmapped_private_work(tmp_path):
    path, _ = profile(tmp_path)
    app = DevelopmentSandbox(path)
    work = app.apps / "home/project-a"
    work.mkdir(parents=True)
    (work / "unsaved-work.txt").write_text("preserve")
    with pytest.raises(RuntimeError, match="hide private Home"):
        app.prepare_mountpoints()
    assert (work / "unsaved-work.txt").read_text() == "preserve"


def test_private_checkpoint_preserves_transcripts_and_skips_sockets(tmp_path):
    import socket
    import tarfile
    from controlled_dev_machine.state_archive import checkpoint
    apps = tmp_path / "apps"
    (apps / ".claude/projects/project").mkdir(parents=True)
    (apps / ".claude/projects/project/session.jsonl").write_text('{"message":"keep"}\n')
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(apps / "runtime.sock"))
    try:
        result = checkpoint(apps, tmp_path / "archive", quiesced=True)
    finally:
        listener.close()
    assert result["consistent"]
    assert result["skipped_runtime_objects"] == ["runtime.sock"]
    with tarfile.open(Path(result["path"]) / "apps.tar.gz") as archive:
        assert archive.extractfile(".claude/projects/project/session.jsonl").read() == b'{"message":"keep"}\n'


def test_failed_admission_does_not_revoke_an_existing_instance(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace
    import controlled_dev_machine.development as module
    writes = []
    app = SimpleNamespace(admitted=False, lock=lambda: nullcontext(), start=lambda: (_ for _ in ()).throw(RuntimeError("preflight rejected")), state=tmp_path, config_sha="new")
    monkeypatch.setattr(module, "DevelopmentSandbox", lambda path: app)
    monkeypatch.setattr(module, "atomic_json", lambda *args: writes.append(args))
    with pytest.raises(RuntimeError, match="preflight rejected"):
        module.main(["--config", "/unused", "start"])
    assert writes == []


def test_failed_admitted_start_revokes_readiness_and_old_lease(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace
    import controlled_dev_machine.development as module
    lease = tmp_path / "exit-control/lease.json"
    lease.parent.mkdir()
    lease.write_text("old lease")
    app = SimpleNamespace(admitted=True, lock=lambda: nullcontext(), start=lambda: (_ for _ in ()).throw(RuntimeError("identity failed")), state=tmp_path, config_sha="new")
    monkeypatch.setattr(module, "DevelopmentSandbox", lambda path: app)
    with pytest.raises(RuntimeError, match="identity failed"):
        module.main(["--config", "/unused", "start"])
    assert not lease.exists()
    assert json.loads((tmp_path / "readiness.json").read_text())["ok"] is False
