from pathlib import Path
from types import SimpleNamespace

from controlled_dev_machine.doctor import (
    Check,
    CheckLevel,
    _docker_engine_check,
    _upstream_check,
    run_doctor,
)


def _pass(name: str) -> Check:
    return Check(name, CheckLevel.PASS, "ok", {})


def test_doctor_requires_every_command_used_by_deploy_and_runtime(monkeypatch) -> None:
    config = SimpleNamespace(
        storage=SimpleNamespace(root=object(), audit=object()),
        paths=SimpleNamespace(audit=Path("/tmp/audit")),
        gpu=SimpleNamespace(mode="all"),
        upstream=SimpleNamespace(kind="unset"),
    )
    monkeypatch.setattr("controlled_dev_machine.doctor._identity_check", lambda _c: _pass("id"))
    monkeypatch.setattr("controlled_dev_machine.doctor._cgroup_check", lambda: _pass("cgroup"))
    monkeypatch.setattr("controlled_dev_machine.doctor._apparmor_check", lambda: _pass("aa"))
    monkeypatch.setattr(
        "controlled_dev_machine.doctor._docker_socket_check", lambda _c: _pass("docker")
    )
    monkeypatch.setattr(
        "controlled_dev_machine.doctor._docker_engine_check", lambda _c: _pass("engine")
    )
    monkeypatch.setattr(
        "controlled_dev_machine.doctor._architecture_check", lambda: _pass("arch")
    )
    monkeypatch.setattr(
        "controlled_dev_machine.doctor._docker_compose_check", lambda: _pass("compose")
    )
    monkeypatch.setattr("controlled_dev_machine.doctor._systemd_check", lambda: _pass("systemd"))
    monkeypatch.setattr("controlled_dev_machine.doctor._gpu_cdi_check", lambda: _pass("gpu"))
    monkeypatch.setattr(
        "controlled_dev_machine.doctor._filesystem_check",
        lambda name, _path, _threshold: _pass(name),
    )
    requirements: dict[str, bool] = {}

    def command_check(command: str, *, required: bool) -> Check:
        requirements[command] = required
        return _pass(command)

    monkeypatch.setattr("controlled_dev_machine.doctor._command_check", command_check)

    run_doctor(config)

    assert requirements["nft"] is True
    assert requirements["skopeo"] is True
    assert requirements["curl"] is True
    assert requirements["openssl"] is True
    assert requirements["systemctl"] is True
    assert requirements["ip"] is True
    assert requirements["nvidia-ctk"] is True
    assert requirements["bpftool"] is False


def test_doctor_requires_docker_engine_28(monkeypatch) -> None:
    config = SimpleNamespace(docker=SimpleNamespace(socket=Path("/run/docker.sock")))
    monkeypatch.setattr("controlled_dev_machine.doctor.shutil.which", lambda _name: "docker")

    monkeypatch.setattr(
        "controlled_dev_machine.doctor.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="27.5.1\n"),
    )
    assert _docker_engine_check(config).level == CheckLevel.BLOCKED

    monkeypatch.setattr(
        "controlled_dev_machine.doctor.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="28.0.0\n"),
    )
    assert _docker_engine_check(config).level == CheckLevel.PASS


def test_doctor_blocks_unimplemented_tun_upstream() -> None:
    config = SimpleNamespace(upstream=SimpleNamespace(kind="tun"))

    check = _upstream_check(config)

    assert check.level == CheckLevel.BLOCKED
    assert "尚未实现" in check.message
