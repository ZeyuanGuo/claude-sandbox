import subprocess
from pathlib import Path
from types import SimpleNamespace

from controlled_dev_machine.doctor import (
    Check,
    CheckLevel,
    _docker_engine_check,
    _parse_claude_auth,
    _runtime_compose_check,
    _ssh_host_check,
    _ssh_runtime_check,
    _target_claude_check,
    _target_network_check,
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
        ssh=SimpleNamespace(enabled=False),
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
    monkeypatch.setattr("controlled_dev_machine.doctor._architecture_check", lambda: _pass("arch"))
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
    assert requirements["iptables"] is False
    assert requirements["nvidia-ctk"] is True
    assert requirements["bpftool"] is False


def test_doctor_reports_ssh_settings_waiting_for_next_init(tmp_path: Path, monkeypatch) -> None:
    ssh_root = tmp_path / ".ssh"
    ssh_root.mkdir()
    config = SimpleNamespace(
        ssh=SimpleNamespace(
            enabled=True,
            interface="tailscale0",
            allowed_addresses=("100.117.92.79",),
            ports=(22,),
        ),
        target=SimpleNamespace(home=tmp_path),
        mounts=(
            SimpleNamespace(
                host_path=ssh_root,
                container_path=ssh_root,
                read_only=True,
            ),
        ),
    )
    monkeypatch.setattr("controlled_dev_machine.doctor.Path.is_dir", lambda _path: True)
    monkeypatch.setattr("controlled_dev_machine.doctor.shutil.which", lambda _name: "/sbin/ip")
    monkeypatch.setattr(
        "controlled_dev_machine.doctor.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""),
    )

    host_check = _ssh_host_check(config)
    runtime_check = _ssh_runtime_check(
        config,
        SimpleNamespace(
            ssh_enabled=False,
            ssh_interface="tailscale0",
            ssh_allowed_addresses=(),
            ssh_ports=(),
        ),
    )

    assert host_check.level == CheckLevel.PASS
    assert runtime_check.level == CheckLevel.WARN
    assert "尚未应用" in runtime_check.message


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


def test_parse_claude_auth_keeps_status_fields_only() -> None:
    parsed = _parse_claude_auth(
        [
            '{"loggedIn":true,"authMethod":"claude.ai",'
            '"email":"person@example.com","organizationId":"secret"}',
        ]
    )

    assert parsed == {
        "parsed": True,
        "loggedIn": True,
        "authMethod": "claude.ai",
    }
    assert "person@example.com" not in str(parsed)


def test_runtime_compose_check_returns_target_container(monkeypatch) -> None:
    config = SimpleNamespace(docker=SimpleNamespace(socket=Path("/run/docker.sock")))
    manifest = SimpleNamespace(resource_prefix="cdm-u1000-main", compose_path="/tmp/compose.yaml")
    output = """[
      {"Service":"canary","Name":"canary-1","State":"running","Health":"healthy"},
      {"Service":"dns","Name":"dns-1","State":"running","Health":"healthy"},
      {"Service":"gateway","Name":"gateway-1","State":"running","Health":"healthy"},
      {"Service":"target","Name":"target-1","State":"running","Health":""}
    ]"""
    monkeypatch.setattr(
        "controlled_dev_machine.doctor._docker_run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, output, ""),
    )

    check, target = _runtime_compose_check(config, manifest)

    assert check.level == CheckLevel.PASS
    assert target == "target-1"
    assert check.facts["services"]["gateway"]["health"] == "healthy"


def test_target_network_check_distinguishes_dns_failure(monkeypatch) -> None:
    config = SimpleNamespace(docker=SimpleNamespace(socket=Path("/run/docker.sock")))
    result = subprocess.CompletedProcess(
        [],
        0,
        "ping_dns=\nping_http=000\nping_exit=6\nanthropic_dns=\n"
        "anthropic_http=000\nanthropic_exit=6\n",
        "Could not resolve host",
    )
    monkeypatch.setattr("controlled_dev_machine.doctor._docker_run", lambda *_a, **_k: result)

    check = _target_network_check(config, "target-1")

    assert check.level == CheckLevel.BLOCKED
    assert check.facts["ping_dns"] is False
    assert check.facts["anthropic_dns"] is False
    assert "Could not resolve host" in check.facts["detail"]


def test_target_claude_check_does_not_expose_auth_identity(monkeypatch) -> None:
    config = SimpleNamespace(
        docker=SimpleNamespace(socket=Path("/run/docker.sock")),
        target=SimpleNamespace(uid=1000, gid=1000),
    )
    result = subprocess.CompletedProcess(
        [],
        0,
        "/usr/local/bin/claude\n2.1.258\n"
        '{"loggedIn":true,"authMethod":"claude.ai",'
        '"email":"person@example.com","organizationId":"secret"}\n',
        "",
    )
    monkeypatch.setattr("controlled_dev_machine.doctor._docker_run", lambda *_a, **_k: result)

    check = _target_claude_check(config, "target-1")

    assert check.level == CheckLevel.PASS
    assert check.facts["auth"] == {
        "parsed": True,
        "loggedIn": True,
        "authMethod": "claude.ai",
    }
    assert "person@example.com" not in str(check.facts)
