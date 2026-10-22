import json
import os
import subprocess
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from controlled_dev_machine import runtime
from controlled_dev_machine.config import (
    ControlledMount,
    HostProfile,
    HostSshConfig,
    ProjectMount,
    ServicePorts,
    UpstreamConfig,
    WorkspaceConfig,
    load_host_config,
)
from controlled_dev_machine.errors import DeploymentError
from controlled_dev_machine.policy import load_policy
from controlled_dev_machine.runtime import (
    RuntimeManifest,
    _activate_generation,
    _bpftrace_cgroup_id,
    _check_upstream,
    _configure_host_parent_guard,
    _configure_host_ssh_guard,
    _configure_infrastructure_network,
    _configure_target_network,
    _controlled_mount_source,
    _dns_policy_args,
    _enable_target_route,
    _gateway_build_digest,
    _host_parent_guard_runner_script,
    _host_parent_table,
    _host_password_hash,
    _initialize_user_profile,
    _legacy_compose_path_for_stop,
    _lifecycle_lock,
    _pin_built_images,
    _prepare_directories,
    _profile_bundle,
    _profile_host_location,
    _require_deployable_policy,
    _require_gateway_image,
    _require_instance_stopped,
    _require_pinned_image_id,
    _require_policy_files,
    _require_target_image,
    _service_relay_command,
    _stopped_host_parent_guard_script,
    _stopped_host_ssh_guard_script,
    _target_build_digest,
    _wait_audit_probe_ready,
    _wait_target_ebpf_ready,
    audit_status,
    compose_build,
    compose_shell,
    compose_start_closed,
    render_closed_compose,
)


@pytest.fixture(autouse=True)
def _use_test_lifecycle_lock(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._LIFECYCLE_LOCK_ROOT", tmp_path / "locks"
    )


def test_unchanged_enabled_systemd_unit_does_not_reload(tmp_path: Path, monkeypatch):
    unit = tmp_path / "guard.service"
    unit.write_text("[Service]\nType=oneshot\n")
    enabled = tmp_path / "multi-user.target.wants"
    enabled.mkdir()
    (enabled / unit.name).symlink_to(unit)
    commands = []
    monkeypatch.setattr(runtime, "_run", lambda args: commands.append(args))
    runtime._install_systemd_unit(unit, unit.read_text(), systemctl="systemctl")
    assert commands == []


@pytest.mark.parametrize("existing", [None, "old unit\n"])
def test_changed_systemd_unit_is_reloaded(tmp_path: Path, monkeypatch, existing):
    unit = tmp_path / "guard.service"
    if existing is not None:
        unit.write_text(existing)
    commands = []
    monkeypatch.setattr(runtime, "_run", lambda args: commands.append(args))
    runtime._install_systemd_unit(unit, "new unit\n", systemctl="systemctl")
    assert unit.read_text() == "new unit\n"
    assert commands == [["systemctl", "daemon-reload"],
                        ["systemctl", "enable", "--no-reload", "guard.service"]]


def test_unchanged_disabled_systemd_unit_is_enabled_without_reload(tmp_path: Path, monkeypatch):
    unit = tmp_path / "guard.service"
    unit.write_text("unit\n")
    commands = []
    monkeypatch.setattr(runtime, "_run", lambda args: commands.append(args))
    runtime._install_systemd_unit(unit, "unit\n", systemctl="systemctl")
    assert commands == [["systemctl", "enable", "--no-reload", "guard.service"]]


@pytest.mark.parametrize("existing", [None, "old unit\n"])
def test_failed_systemd_reload_is_retried(tmp_path: Path, monkeypatch, existing):
    unit = tmp_path / "guard.service"
    if existing is not None:
        unit.write_text(existing)
    commands = []

    def reload_fails(args):
        commands.append(args)
        raise DeploymentError("reload failed")

    monkeypatch.setattr(runtime, "_run", reload_fails)
    for _ in range(2):
        with pytest.raises(DeploymentError, match="reload failed"):
            runtime._install_systemd_unit(unit, "new unit\n", systemctl="systemctl")
        if existing is None:
            assert not unit.exists()
        else:
            assert unit.read_text() == existing
    assert commands == [["systemctl", "daemon-reload"], ["systemctl", "daemon-reload"]]


def _host_config(tmp_path: Path):
    home = tmp_path / "home" / "alice"
    project = home / "project"
    project.mkdir(parents=True)
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
  state: {home}/.cdm/state
  audit: {home}/.cdm/audit
storage:
  root:
    min_free_gib: 1
    min_free_percent: 1
  audit:
    min_free_gib: 1
    min_free_percent: 1
  pcap_limit_gib: 1
  plaintext_limit_gib: 1
  structured_limit_gib: 1
upstream:
  kind: unset
mounts:
  - host_path: {project}
    container_path: {project}
    access: rw
""".lstrip(),
        encoding="utf-8",
    )
    return load_host_config(path)


def _manifest(config, tmp_path: Path) -> RuntimeManifest:
    policy_path = tmp_path / "policy.test.snapshot.yaml"
    policy_path.write_text(
        """
schema_version: 1
policy_id: strict-test
revision: 1
mode: strict
created_at: "2026-07-28T00:00:00Z"
parent_digest:
web_default: block
rules: []
""".lstrip(),
        encoding="utf-8",
    )
    policy_digest = load_policy(policy_path).digest()
    return RuntimeManifest(
        schema_version=4,
        instance="main",
        resource_prefix="cdm-u1000-main",
        created_at="2026-07-28T00:00:00Z",
        repo_root=str(Path.cwd()),
        compose_path=str(config.paths.state / "generated/current/compose.closed.yaml"),
        policy_path=str(config.paths.state / "generated/current/policy.active.yaml"),
        policy_snapshot_path=str(policy_path),
        policy_digest=policy_digest,
        target_subnet="172.28.0.0/28",
        canary_subnet="172.28.0.16/28",
        upstream_subnet="172.28.0.32/28",
        proxy_target_address="172.28.0.2",
        proxy_canary_address="172.28.0.18",
        target_address="172.28.0.3",
        canary_address="172.28.0.19",
        upstream_gateway_address="172.28.0.33",
        gateway_upstream_address="172.28.0.34",
        dns_upstream_address="172.28.0.35",
        target_image="cdm-u1000-main-target:" + "c" * 16,
        gateway_image="cdm-u1000-main-gateway:" + "b" * 16,
        gateway_build_digest="b" * 64,
        target_build_digest="c" * 64,
    )


def test_target_has_no_publication_or_audit_mount(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    compose = render_closed_compose(config, _manifest(config, tmp_path))
    target = compose["services"]["target"]
    assert "ports" not in target
    assert "dns" not in target
    assert "cap_drop" not in target
    assert "security_opt" not in target
    assert target["devices"] == ["nvidia.com/gpu=all"]
    assert target["environment"]["NVIDIA_VISIBLE_DEVICES"] == "all"
    assert target["user"] == "1000:1000"
    assert target["group_add"] == ["sudo"]
    assert target["build"]["provenance"] is False
    assert target["build"]["sbom"] is False
    assert target["build"]["args"]["TARGET_BUILD_DIGEST"] == "c" * 64
    assert "CDM_TARGET_UID" not in target["environment"]
    assert "CDM_TARGET_GID" not in target["environment"]
    assert target["environment"]["NODE_OPTIONS"] == "--use-system-ca"
    assert "NODE_USE_SYSTEM_CA" not in target["environment"]
    assert not any("PROXY" in name or "proxy" in name for name in target["environment"])
    assert target["environment"]["SSL_CERT_FILE"] == "/etc/ssl/certs/ca-certificates.crt"
    assert target["environment"]["REQUESTS_CA_BUNDLE"] == "/etc/ssl/certs/ca-certificates.crt"
    sources = {item["source"] for item in target["volumes"]}
    assert str(config.paths.audit) not in sources
    assert str(config.docker.socket) not in sources
    password_hash = next(
        item
        for item in target["volumes"]
        if item["target"] == "/run/cdm/target-password-hash"
    )
    assert password_hash["read_only"] is True
    assert password_hash["source"].endswith(
        "/generated/current/target-password-hash"
    )
    resolver = next(
        item for item in target["volumes"] if item["target"] == "/etc/resolv.conf"
    )
    assert resolver == {
        "type": "bind",
        "source": str(
            config.paths.state / "generated/current/target-resolv.conf"
        ),
        "target": "/etc/resolv.conf",
        "read_only": True,
        "bind": {"create_host_path": False},
    }


def test_target_home_uses_fixed_persistent_host_bind(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    compose = render_closed_compose(config, _manifest(config, tmp_path))
    target = compose["services"]["target"]
    home = next(
        item for item in target["volumes"] if item["target"] == str(config.target.home)
    )
    assert home == {
        "type": "bind",
        "source": str(config.paths.persistent_home),
        "target": str(config.target.home),
        "read_only": False,
        "bind": {"create_host_path": False},
    }
    assert not any(
        item.get("type") == "volume" and item["target"] == str(config.target.home)
        for item in target["volumes"]
    )


def test_target_hostname_uses_config_without_changing_image_inputs(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    changed = replace(config, target=replace(config.target, hostname="workstation-a24f"))
    compose = render_closed_compose(changed, _manifest(changed, tmp_path))
    assert compose["services"]["target"]["hostname"] == "workstation-a24f"
    files, _ = _profile_bundle(changed, Path.cwd())
    assert "Ubuntu container, workstation-a24f," in files[".bashrc"]
    assert _target_build_digest(changed, Path.cwd()) == _target_build_digest(config, Path.cwd())


def test_target_mac_is_persistent_per_network_and_not_an_image_input(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    manifest = _manifest(config, tmp_path)
    original = render_closed_compose(config, manifest)["services"]["target"]
    assert "mac_address" not in original["networks"]["target_net"]
    changed = replace(config, target=replace(config.target, mac_address="02:7b:3c:4d:5e:6f"))
    for _ in range(2):
        target = render_closed_compose(changed, manifest)["services"]["target"]
        assert target["networks"]["target_net"] == {
            "ipv4_address": manifest.target_address,
            "mac_address": "02:7b:3c:4d:5e:6f",
        }
        assert "mac_address" not in target
    assert _target_build_digest(changed, Path.cwd()) == _target_build_digest(config, Path.cwd())


def test_shared_host_home_and_declared_service_ports_are_rendered(tmp_path: Path) -> None:
    config = replace(
        _host_config(tmp_path),
        workspace=WorkspaceConfig(share_host_home=True),
        service_ports=ServicePorts(bind_address="0.0.0.0", start=25600, end=25700),
    )

    target = render_closed_compose(config, _manifest(config, tmp_path))["services"]["target"]
    home = next(
        item for item in target["volumes"] if item["target"] == str(config.target.home)
    )

    assert home["source"] == str(config.target.home)
    assert home["read_only"] is False
    assert "ports" not in target

    command = _service_relay_command(config, _manifest(config, tmp_path), 4321)
    assert command is not None
    assert command[-12:] == [
        "--bind-address",
        "0.0.0.0",
        "--start",
        "25600",
        "--end",
        "25700",
        "--target-netns",
        "/proc/4321/ns/net",
        "--uid",
        "65534",
        "--gid",
        "65534",
    ]


def test_controlled_mounts_override_shared_home_and_preserve_data_propagation(
    tmp_path: Path,
) -> None:
    base_config = _host_config(tmp_path)
    config = replace(
        base_config,
        workspace=WorkspaceConfig(
            share_host_home=True,
            controlled_mounts=(
                ControlledMount(Path(".claude"), read_only=False),
                ControlledMount(Path(".codex"), read_only=False),
            ),
        ),
        mounts=(
            ProjectMount(
                host_path=tmp_path / "data",
                container_path=Path("/data"),
                read_only=False,
                propagation="rslave",
            ),
            ProjectMount(
                host_path=base_config.target.home / ".claude" / "skills",
                container_path=base_config.target.home / ".claude" / "skills",
                read_only=False,
            ),
        ),
        paths=replace(
            base_config.paths,
            persistent_home=tmp_path / "managed-home",
            state=tmp_path / "state",
            audit=tmp_path / "audit",
        ),
    )
    (config.target.home / ".claude").mkdir()
    (config.target.home / ".claude" / "skills").mkdir()
    (config.target.home / ".codex").mkdir()
    manifest = _manifest(config, tmp_path)
    volumes = render_closed_compose(config, manifest)["services"]["target"]["volumes"]

    home_index = next(
        index for index, item in enumerate(volumes) if item["target"] == str(config.target.home)
    )
    claude_index = next(
        index
        for index, item in enumerate(volumes)
        if item["target"] == str(config.target.home / ".claude")
    )
    codex_index = next(
        index
        for index, item in enumerate(volumes)
        if item["target"] == str(config.target.home / ".codex")
    )
    data = next(item for item in volumes if item["target"] == "/data")
    skills_index = next(
        index
        for index, item in enumerate(volumes)
        if item["target"] == str(config.target.home / ".claude" / "skills")
    )

    assert home_index < claude_index < codex_index < skills_index
    assert volumes[claude_index]["source"] == str(
        _controlled_mount_source(config, config.workspace.controlled_mounts[0])
    )
    assert volumes[codex_index]["source"] == str(
        _controlled_mount_source(config, config.workspace.controlled_mounts[1])
    )
    assert data["bind"]["propagation"] == "rslave"


def test_controlled_mount_seed_copies_host_tree_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _host_config(tmp_path)
    (config.target.home / ".claude").mkdir()
    (config.target.home / ".claude" / "settings.json").write_text(
        "{\"fixture\": true}\n", encoding="utf-8"
    )
    config = replace(
        config,
        target=replace(config.target, uid=os.getuid(), gid=os.getgid()),
        paths=replace(
            config.paths,
            persistent_home=tmp_path / "managed-home",
            state=tmp_path / "state",
            audit=tmp_path / "audit",
        ),
        workspace=WorkspaceConfig(
            share_host_home=True,
            controlled_mounts=(ControlledMount(Path(".claude"), read_only=False),),
        ),
    )
    monkeypatch.setattr("controlled_dev_machine.runtime.os.chown", lambda *_args: None)

    _prepare_directories(config)

    seeded = _controlled_mount_source(config, config.workspace.controlled_mounts[0])
    assert (seeded / "settings.json").read_text(encoding="utf-8") == "{\"fixture\": true}\n"


def test_host_password_hash_selects_only_target_user(tmp_path: Path) -> None:
    shadow = tmp_path / "shadow"
    shadow.write_text(
        "root:$y$root-hash:1:2:3:4:5:6:7\n"
        "alice:$y$alice-hash:1:2:3:4:5:6:7\n",
        encoding="utf-8",
    )

    assert _host_password_hash("alice", shadow) == "$y$alice-hash"


def test_host_password_hash_rejects_locked_account(tmp_path: Path) -> None:
    shadow = tmp_path / "shadow"
    shadow.write_text("alice:!:1:2:3:4:5:6:7\n", encoding="utf-8")

    with pytest.raises(DeploymentError, match="没有可用于容器 sudo 的密码"):
        _host_password_hash("alice", shadow)


def test_prepare_directories_accepts_file_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _host_config(tmp_path)
    credential = tmp_path / "git-credentials"
    credential.write_text("fixture\n", encoding="utf-8")
    config = replace(
        config,
        mounts=(
            *config.mounts,
            ProjectMount(
                host_path=credential,
                container_path=config.target.home / ".git-credentials",
                read_only=True,
            ),
        ),
    )
    monkeypatch.setattr("controlled_dev_machine.runtime.os.chown", lambda *_args: None)
    _prepare_directories(config)


def test_prepare_directories_accepts_owned_shared_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _host_config(tmp_path)
    config.target.home.joinpath(".claude").mkdir()
    config = replace(
        config,
        target=replace(config.target, uid=os.getuid(), gid=os.getgid()),
        paths=replace(
            config.paths,
            state=tmp_path / "state",
            audit=tmp_path / "audit",
        ),
        workspace=WorkspaceConfig(share_host_home=True),
    )

    monkeypatch.setattr("controlled_dev_machine.runtime.os.chown", lambda *_args: None)
    _prepare_directories(config)


def test_bpftrace_cgroup_id_falls_back_to_cgroup_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del tmp_path
    cgroup_path = Path("/sys/fs/cgroup")
    expected = cgroup_path.stat().st_ino
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["bpftrace"], 255, "", "BEGIN_trigger missing"
        ),
    )

    assert _bpftrace_cgroup_id(str(cgroup_path)) == expected


def test_strict_runtime_resolves_public_domains(
    tmp_path: Path,
) -> None:
    config = _host_config(tmp_path)
    manifest = _manifest(config, tmp_path)

    assert _dns_policy_args(manifest) == ["--allow-public-domains"]


def test_daily_runtime_resolves_public_domains(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    policy_path = Path("policies/daily/0001-public-web.yaml").resolve()
    policy = load_policy(policy_path)
    manifest = replace(
        _manifest(config, tmp_path),
        policy_snapshot_path=str(policy_path),
        policy_digest=policy.digest(),
    )

    assert _dns_policy_args(manifest) == ["--allow-public-domains"]


def test_dns_public_resolution_is_independent_of_web_rules(
    tmp_path: Path, monkeypatch
) -> None:
    config = _host_config(tmp_path)
    manifest = _manifest(config, tmp_path)
    rules = (
        SimpleNamespace(action="block", domain_kind="suffix", domain="blocked.example"),
        SimpleNamespace(action="allow", domain_kind="exact", domain="api.example"),
        SimpleNamespace(action="review", domain_kind="suffix", domain="review.example"),
    )
    policy = SimpleNamespace(
        digest=lambda: manifest.policy_digest,
        web_default="review",
        rules=rules,
    )
    monkeypatch.setattr("controlled_dev_machine.runtime.load_policy", lambda _path: policy)

    assert _dns_policy_args(manifest) == ["--allow-public-domains"]


def test_target_and_canary_do_not_share_a_network(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    compose = render_closed_compose(config, _manifest(config, tmp_path))
    services = compose["services"]
    assert set(services["target"]["networks"]) == {"target_net"}
    assert set(services["canary"]["networks"]) == {"canary_net"}
    assert set(services["gateway"]["networks"]) == {"target_net", "canary_net"}
    assert all(network["internal"] for network in compose["networks"].values())


def test_gateway_is_lazy_and_records_plaintext(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    compose = render_closed_compose(config, _manifest(config, tmp_path))
    gateway = compose["services"]["gateway"]
    assert gateway["user"] == "1000:1000"
    command = gateway["command"]
    assert "transparent" in command
    assert "regular" not in command
    assert "connection_strategy=lazy" in command
    assert "rawtcp=false" in command
    assert "/audit/plaintext/flows.mitm" in command
    assert gateway["dns"] == ["172.28.0.4"]
    assert gateway["depends_on"] == {
        "canary": {"condition": "service_healthy"},
        "dns": {"condition": "service_healthy"},
    }
    assert gateway["environment"]["CDM_EXPECTED_POLICY_DIGEST"] == _manifest(
        config, tmp_path
    ).policy_digest
    assert gateway["environment"]["CDM_GATEWAY_BUILD_DIGEST"] == "b" * 64
    assert gateway["environment"]["CDM_CANARY_ADDRESS"] == "172.28.0.19"
    assert gateway["build"]["provenance"] is False
    assert gateway["build"]["sbom"] is False
    assert gateway["build"]["args"]["GATEWAY_BUILD_DIGEST"] == "b" * 64
    assert gateway["healthcheck"]["test"] == [
        "CMD",
        "python",
        "-m",
        "controlled_dev_machine.gateway_health",
    ]
    assert gateway["healthcheck"]["retries"] == 3
    assert gateway["healthcheck"]["start_period"] == "20s"


def test_user_profile_has_no_automatic_single_file_binds(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    config = replace(
        config,
        profile=replace(
            config.profile,
            gitconfig=config.target.home / ".gitconfig",
            tmux_config=config.target.home / ".tmux.conf",
        ),
    )
    compose = render_closed_compose(config, _manifest(config, tmp_path))
    volumes = compose["services"]["target"]["volumes"]
    user_files = {
        config.target.home / name
        for name in (".claude/CLAUDE.md", ".bashrc", ".profile", ".gitconfig", ".tmux.conf")
    }
    assert not any(Path(item["target"]) in user_files for item in volumes)
    assert not any("generated/current/profile" in item["source"] for item in volumes)


def test_python_trust_uses_system_bundle_without_binding_over_package_files(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    conda = config.target.home / "conda"
    package_files = [
        base / name
        for base in (conda, conda / "envs/dev")
        for name in ("ssl/cacert.pem", "lib/python3.10/site-packages/certifi/cacert.pem")
    ]
    for path in package_files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("original package data\n")
    config = replace(config, profile=replace(
        config.profile, conda_root=conda, default_conda_env="dev",
    ))
    target = render_closed_compose(config, _manifest(config, tmp_path))["services"]["target"]
    targets = {Path(item["target"]) for item in target["volumes"]}
    assert not targets.intersection(package_files)
    assert not any(
        path.is_relative_to(config.target.home) and path.name == "cacert.pem"
        for path in targets
    )
    system = next(
        item for item in target["volumes"]
        if item["target"] == "/etc/ssl/certs/ca-certificates.crt"
    )
    assert system["read_only"] is True
    assert system["source"] == str(config.paths.state / "target-trust/ca-certificates.crt")
    assert target["environment"]["SSL_CERT_FILE"] == system["target"]
    assert target["environment"]["REQUESTS_CA_BUNDLE"] == system["target"]
    for path in package_files:
        assert path.read_text() == "original package data\n"
        replacement = path.with_name("atomic-package-save.tmp")
        replacement.write_text("updated package data\n")
        replacement.replace(path)
        assert path.read_text() == "updated package data\n"


def test_explicit_user_mount_is_not_duplicated_by_profile_generation(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    host_prompt = config.target.home / "claude_code_config" / "CLAUDE.md"
    config = replace(
        config,
        mounts=(
            ProjectMount(
                host_path=host_prompt,
                container_path=config.target.home / ".claude" / "CLAUDE.md",
                read_only=False,
            ),
        ),
    )

    target = render_closed_compose(config, _manifest(config, tmp_path))["services"][
        "target"
    ]
    instructions = [
        item
        for item in target["volumes"]
        if item["target"] == str(config.target.home / ".claude" / "CLAUDE.md")
    ]

    assert instructions == [
        {
            "type": "bind",
            "source": str(host_prompt),
            "target": str(config.target.home / ".claude" / "CLAUDE.md"),
            "read_only": False,
            "bind": {"create_host_path": False},
        }
    ]


def test_host_profile_is_merged_without_overriding_sandbox_network(
    tmp_path: Path,
) -> None:
    config = _host_config(tmp_path)
    config = replace(
        config,
        target=replace(config.target, uid=os.getuid(), gid=os.getgid()),
    )
    host_prompt = config.target.home / ".claude" / "CLAUDE.md"
    host_prompt.parent.mkdir()
    host_bashrc = config.target.home / ".bashrc"
    conda_executable = config.target.home / "conda" / "bin" / "conda"
    conda_executable.parent.mkdir(parents=True)
    conda_executable.write_text("#!/bin/sh\n", encoding="utf-8")
    conda_executable.chmod(0o755)
    host_prompt.write_text("# Host instructions\n\nUse Chinese.\n", encoding="utf-8")
    host_bashrc.write_text(
        "export HTTPS_PROXY=http://127.0.0.1:26930\n"
        "conda activate host-env\n",
        encoding="utf-8",
    )
    config = replace(
        config,
        profile=HostProfile(
            claude_instructions=host_prompt,
            bashrc=host_bashrc,
            login_profile=None,
            gitconfig=None,
            tmux_config=None,
            conda_root=config.target.home / "conda",
            default_conda_env="sandbox-env",
            timezone="Etc/UTC",
        ),
    )
    files, source_digest = _profile_bundle(config, Path.cwd())
    assert "# Host instructions" in files["CLAUDE.md"]
    assert "# Controlled development environment" in files["CLAUDE.md"]
    assert "127.0.0.1:26930" not in files[".bashrc"]
    assert "conda activate host-env" in files[".bashrc"]
    assert "unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY" in files[".bashrc"]
    assert "conda activate \"$CDM_DEFAULT_CONDA_ENV\"" in files[".bashrc"]
    assert "$CDM_CONDA_ROOT/etc/profile.d/conda.sh" in files[".bashrc"]
    assert "$HOME/miniconda3" not in files[".bashrc"]
    for name in (".bashrc", ".profile"):
        assert "unset REQUESTS_CA_BUNDLE SSL_CERT_FILE" not in files[name]
    assert "Controlled development workstation" in files[".bashrc"]
    assert "System identity: Ubuntu container, devbox, Etc/UTC, en_US.UTF-8" in files[".bashrc"]
    assert "CDM_SHELL_NOTICE_SHOWN" not in files[".bashrc"]
    assert len(source_digest) == 64

    compose = render_closed_compose(config, _manifest(config, tmp_path))
    target = compose["services"]["target"]
    assert target["environment"]["CDM_DEFAULT_CONDA_ENV"] == "sandbox-env"
    assert target["environment"]["TZ"] == "Etc/UTC"
    assert target["build"]["args"]["TARGET_TIMEZONE"] == "Etc/UTC"
    assert target["environment"]["CDM_CONDA_ROOT"] == str(
        config.target.home / "conda"
    )
    profile_targets = {item["target"] for item in target["volumes"]}
    assert str(config.target.home / ".bashrc") not in profile_targets
    assert str(config.target.home / ".profile") not in profile_targets


def _claude_prompt_profile(tmp_path: Path):
    config = _host_config(tmp_path)
    source = config.target.home / "claude_code_config" / "CLAUDE.md"
    source.parent.mkdir()
    template_root = tmp_path / "template"
    managed = template_root / "config" / "claude" / "CLAUDE.md"
    managed.parent.mkdir(parents=True)
    suffix = "# Managed sandbox instructions\n\nUse Codex for independent review.\n"
    managed.write_text(suffix, encoding="utf-8")
    config = replace(
        config,
        target=replace(config.target, uid=os.getuid(), gid=os.getgid()),
        profile=replace(config.profile, claude_instructions=source),
    )
    return config, source, template_root, suffix


def test_long_original_claude_prompt_precedes_managed_suffix_without_truncation(
    tmp_path: Path,
) -> None:
    config, source, template_root, suffix = _claude_prompt_profile(tmp_path)
    original = "# 原提示\n\n" + "保留原始推理与工程约束。\n" * 2400 + "原提示末尾标记\n"
    assert len(original.encode("utf-8")) > 58000
    source.write_text(original, encoding="utf-8")

    files, _ = _profile_bundle(config, template_root)

    assert files["CLAUDE.md"] == original.rstrip() + "\n\n" + suffix.rstrip() + "\n"
    assert source.read_text(encoding="utf-8") == original


def test_claude_prompt_rereads_original_source_without_creating_a_second_baseline(
    tmp_path: Path,
) -> None:
    config, source, template_root, suffix = _claude_prompt_profile(tmp_path)
    source.write_text("# Original prompt\n", encoding="utf-8")
    existing_paths = set(tmp_path.rglob("*"))
    first, first_digest = _profile_bundle(config, template_root)
    revised = "# Revised original prompt\n\nKeep the new requirement.\n"
    source.write_text(revised, encoding="utf-8")

    second, second_digest = _profile_bundle(config, template_root)

    assert second["CLAUDE.md"] == revised.rstrip() + "\n\n" + suffix.rstrip() + "\n"
    assert second["CLAUDE.md"] != first["CLAUDE.md"]
    assert second_digest != first_digest
    assert config.profile.claude_instructions == source
    assert source.read_text(encoding="utf-8") == revised
    assert set(tmp_path.rglob("*")) == existing_paths


def _shared_profile(tmp_path: Path):
    config, source, template_root, suffix = _claude_prompt_profile(tmp_path)
    source.write_text("# Shared instructions\n", encoding="utf-8")
    config = replace(
        config,
        paths=replace(config.paths, persistent_home=tmp_path / "private-home"),
        workspace=WorkspaceConfig(
            share_host_home=True,
            controlled_mounts=(ControlledMount(Path(".claude"), read_only=False, seed="never"),),
        ),
    )
    private = _controlled_mount_source(config, config.workspace.controlled_mounts[0])
    private.mkdir(parents=True)
    return config, source, template_root, suffix, private


def test_shared_profile_seeds_regular_import_and_separate_private_rules(tmp_path: Path) -> None:
    config, source, template_root, suffix, private = _shared_profile(tmp_path)
    files, _ = _profile_bundle(config, template_root)
    _initialize_user_profile(config, files)

    loader = private / "CLAUDE.md"
    rules = private / "rules/controlled-environment.md"
    assert loader.is_file() and not loader.is_symlink()
    assert loader.read_text().splitlines()[0] == f"@{source}"
    assert "append local instructions here" in loader.read_text()
    assert "# Shared instructions" not in loader.read_text()
    assert rules.read_text() == suffix
    assert rules.is_file() and not rules.is_symlink()
    assert loader.stat().st_uid == config.target.uid
    assert rules.stat().st_uid == config.target.uid
    assert loader.stat().st_mode & 0o200
    assert rules.stat().st_mode & 0o200
    assert rules.parent.stat().st_uid == config.target.uid
    assert not (config.target.home / ".claude/CLAUDE.md").exists()


def test_nonshared_profile_seeds_full_prompt_in_persistent_home(tmp_path: Path) -> None:
    config, source, template_root, suffix = _claude_prompt_profile(tmp_path)
    source.write_text("# Original instructions\n", encoding="utf-8")
    config.paths.persistent_home.mkdir(parents=True)
    files, _ = _profile_bundle(config, template_root)
    _initialize_user_profile(config, files)
    prompt = config.paths.persistent_home / ".claude/CLAUDE.md"
    assert prompt.read_text() == "# Original instructions\n\n" + suffix
    assert not prompt.is_symlink()
    assert not (config.paths.persistent_home / ".claude/rules/controlled-environment.md").exists()


def test_seed_resolves_longest_visible_mount_parent(tmp_path: Path) -> None:
    config, _, template_root, suffix, private = _shared_profile(tmp_path)
    shared_rules = config.target.home / "shared-rules"
    shared_rules.mkdir()
    config = replace(
        config,
        mounts=(*config.mounts, ProjectMount(
            host_path=shared_rules,
            container_path=config.target.home / ".claude/rules",
            read_only=False,
        )),
    )
    expected = runtime._ProfileLocation(private, Path("CLAUDE.md"), False)
    assert _profile_host_location(config, config.target.home / ".claude/CLAUDE.md") == expected
    assert _profile_host_location(
        config, config.target.home / ".claude/rules/controlled-environment.md",
    ) == runtime._ProfileLocation(shared_rules, Path("controlled-environment.md"), False)
    files, _ = _profile_bundle(config, template_root)
    _initialize_user_profile(config, files)
    assert (shared_rules / "controlled-environment.md").read_text() == suffix
    assert not (private / "rules").exists()


def test_shared_import_rejects_source_hidden_by_private_mount(tmp_path: Path) -> None:
    config, _, template_root, _, _ = _shared_profile(tmp_path)
    hidden = config.target.home / ".claude/CLAUDE.md"
    hidden.parent.mkdir()
    hidden.write_text("# Host-only prompt\n")
    config = replace(config, profile=replace(config.profile, claude_instructions=hidden))
    with pytest.raises(DeploymentError, match="未被私有挂载覆盖"):
        _profile_bundle(config, template_root)


def test_profile_reinitialization_preserves_atomic_user_edits_and_private_auth(
    tmp_path: Path,
) -> None:
    config, source, template_root, _, private = _shared_profile(tmp_path)
    host_claude = config.target.home / ".claude"
    host_claude.mkdir()
    (host_claude / "credentials.json").write_text("host-only fixture")
    account = private / "credentials.json"
    account.write_text("private account fixture")
    history = private / "history.jsonl"
    history.write_text("private history fixture")
    files, old_digest = _profile_bundle(config, template_root)
    _initialize_user_profile(config, files)
    loader = private / "CLAUDE.md"
    temporary = private / "editor-save.tmp"
    temporary.write_text("# User-edited local instructions\n")
    temporary.replace(loader)
    rules = private / "rules/controlled-environment.md"
    rules.write_text("# User-edited environment instructions\n")
    bashrc = config.target.home / ".bashrc"
    bashrc.write_text("export EDITOR=vim\n")
    source.write_text("# New shared instructions\n")

    updated, new_digest = _profile_bundle(config, template_root)
    _initialize_user_profile(config, updated)
    _initialize_user_profile(config, updated)

    assert new_digest != old_digest
    assert loader.read_text() == "# User-edited local instructions\n"
    assert rules.read_text() == "# User-edited environment instructions\n"
    assert bashrc.read_text() == "export EDITOR=vim\n"
    assert account.read_text() == "private account fixture"
    assert history.read_text() == "private history fixture"
    assert (host_claude / "credentials.json").read_text() == "host-only fixture"


def test_existing_empty_user_files_and_broken_links_are_not_reowned_or_replaced(
    tmp_path: Path, monkeypatch,
) -> None:
    config, _, template_root, _, _ = _shared_profile(tmp_path)
    files, _ = _profile_bundle(config, template_root)
    targets = {
        "CLAUDE.md": config.target.home / ".claude/CLAUDE.md",
        "controlled-environment.md": config.target.home / ".claude/rules/controlled-environment.md",
    }
    for name in files:
        target = targets.get(name, config.target.home / name)
        location = _profile_host_location(config, target)
        path = location.root / location.relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
        path.chmod(0o600)
    profile = config.target.home / ".profile"
    profile.unlink()
    profile.symlink_to(config.target.home / "missing-user-profile")

    def must_not_reown(*args):
        pytest.fail("existing user files and parents must not be reowned")

    monkeypatch.setattr(runtime.os, "fchown", must_not_reown)
    monkeypatch.setattr(runtime.os, "chown", must_not_reown)
    _initialize_user_profile(config, files)
    assert profile.is_symlink()
    assert (config.target.home / ".bashrc").read_text() == ""
    location = _profile_host_location(config, config.target.home / ".claude/CLAUDE.md")
    assert (location.root / location.relative).read_text() == ""
    assert (location.root / location.relative).stat().st_mode & 0o777 == 0o600


def test_seed_does_not_follow_user_parent_symlink(tmp_path: Path) -> None:
    config, _, template_root, _, private = _shared_profile(tmp_path)
    outside = tmp_path / "outside-user-view"
    outside.mkdir()
    (private / "rules").symlink_to(outside)
    files, _ = _profile_bundle(config, template_root)
    with pytest.raises(DeploymentError, match="无法初始化用户 profile"):
        _initialize_user_profile(config, files)
    assert not (outside / "controlled-environment.md").exists()


def test_seed_rejects_symlink_ancestor_of_its_data_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    (outside / "existing/leaf").mkdir(parents=True)
    alias = tmp_path / "root-alias"
    alias.symlink_to(outside, target_is_directory=True)
    with pytest.raises(DeploymentError, match="无法初始化用户 profile"):
        runtime._seed_profile_file(
            alias / "existing/leaf", Path("CLAUDE.md"), "must not escape\n",
            os.getuid(), os.getgid(),
        )
    assert list((outside / "existing/leaf").iterdir()) == []


def test_seed_temporary_collision_never_deletes_existing_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(runtime.uuid, "uuid4", lambda: SimpleNamespace(hex="collision"))
    existing = tmp_path / ".cdm-seed-collision"
    existing.write_text("user-owned existing file")
    with pytest.raises(DeploymentError, match="无法初始化用户 profile"):
        runtime._seed_profile_file(
            tmp_path, Path("test.md"), "must not publish", os.geteuid(), os.getegid(),
        )
    assert existing.read_text() == "user-owned existing file"
    assert not (tmp_path / "test.md").exists()


@pytest.mark.parametrize("kind", ["controlled", "project"])
def test_readonly_profile_mapping_is_never_seeded(tmp_path: Path, kind) -> None:
    config, _, _, _, private = _shared_profile(tmp_path)
    if kind == "controlled":
        config = replace(config, workspace=replace(
            config.workspace,
            controlled_mounts=(ControlledMount(Path(".claude"), read_only=True, seed="never"),),
        ))
        protected = private / "rules"
    else:
        protected = config.target.home / "readonly-rules"
        protected.mkdir()
        config = replace(config, mounts=(*config.mounts, ProjectMount(
            host_path=protected,
            container_path=config.target.home / ".claude/rules",
            read_only=True,
        )))
    location = _profile_host_location(
        config, config.target.home / ".claude/rules/controlled-environment.md",
    )
    assert location.read_only
    _initialize_user_profile(config, {"controlled-environment.md": "do not seed\n"})
    assert not (protected / "controlled-environment.md").exists()
    assert not (private / "rules/controlled-environment.md").exists()
    if kind == "controlled":
        assert not protected.exists()


def test_directory_replaced_between_mkdir_and_open_is_not_reowned(
    tmp_path: Path, monkeypatch,
) -> None:
    root = tmp_path / "data"
    root.mkdir()
    existing = tmp_path / "existing-directory"
    existing.mkdir()
    other_group = next((gid for gid in os.getgroups() if gid != os.getgid()), os.getgid())
    os.chown(existing, -1, other_group)
    metadata = existing.stat()
    original_mkdir = os.mkdir
    replaced = []

    def replace_after_creation(path, *args, **kwargs):
        original_mkdir(path, *args, **kwargs)
        if path == "rules":
            os.rmdir(path, dir_fd=kwargs["dir_fd"])
            os.rename(existing, path, dst_dir_fd=kwargs["dir_fd"])
            replaced.append(path)

    def must_not_chown(*args, **kwargs):
        pytest.fail("a raced-in existing directory must never be chowned")

    monkeypatch.setattr(runtime.os, "mkdir", replace_after_creation)
    monkeypatch.setattr(runtime.os, "chown", must_not_chown)
    monkeypatch.setattr(runtime.os, "fchown", must_not_chown)
    runtime._seed_profile_file(
        root, Path("rules/test.md"), "seed\n", os.geteuid(), os.getegid(),
    )
    assert replaced == ["rules"]
    preserved = (root / "rules").stat()
    assert (preserved.st_ino, preserved.st_uid, preserved.st_gid) == (
        metadata.st_ino, metadata.st_uid, metadata.st_gid,
    )
    assert (root / "rules/test.md").read_text() == "seed\n"


def _simulate_profile_root_identity(monkeypatch):
    state = {"uid": 0, "gid": 41, "groups": [41, 42]}
    monkeypatch.setattr(runtime.os, "geteuid", lambda: state["uid"])
    monkeypatch.setattr(runtime.os, "getegid", lambda: state["gid"])
    monkeypatch.setattr(runtime.os, "getgroups", lambda: list(state["groups"]))
    monkeypatch.setattr(runtime.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name="target"))
    monkeypatch.setattr(runtime.os, "getgrouplist", lambda name, gid: [gid, 51])
    monkeypatch.setattr(runtime.os, "seteuid", lambda uid: state.update(uid=uid))
    monkeypatch.setattr(runtime.os, "setegid", lambda gid: state.update(gid=gid))
    monkeypatch.setattr(runtime.os, "setgroups", lambda groups: state.update(groups=list(groups)))
    return state


@pytest.mark.parametrize("fail", [False, True])
def test_profile_identity_is_restored_after_success_or_write_failure(monkeypatch, fail) -> None:
    state = _simulate_profile_root_identity(monkeypatch)
    try:
        with runtime._profile_user_identity(1234, 50):
            assert state == {"uid": 1234, "gid": 50, "groups": [50, 51]}
            if fail:
                raise OSError("simulated write failure")
    except OSError:
        assert fail
    assert state == {"uid": 0, "gid": 41, "groups": [41, 42]}


@pytest.mark.parametrize("setter", ["setgroups", "setegid", "seteuid"])
def test_identity_switch_failure_cannot_create_seed_and_restores_identity(
    tmp_path: Path, monkeypatch, setter,
) -> None:
    root = tmp_path / "data"
    root.mkdir()
    state = _simulate_profile_root_identity(monkeypatch)
    original = getattr(runtime.os, setter)
    target = {"setgroups": [50, 51], "setegid": 50, "seteuid": 1234}[setter]

    def denied(value):
        if value == target:
            raise PermissionError("simulated identity denial")
        original(value)

    monkeypatch.setattr(runtime.os, setter, denied)
    with pytest.raises(DeploymentError, match="无法初始化用户 profile"):
        runtime._seed_profile_file(root, Path("test.md"), "must not publish", 1234, 50)
    assert list(root.iterdir()) == []
    assert state == {"uid": 0, "gid": 41, "groups": [41, 42]}


def test_unprivileged_cross_uid_seed_fails_closed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 1234)
    monkeypatch.setattr(runtime.os, "getegid", lambda: 50)
    with pytest.raises(DeploymentError, match="无权切换"):
        runtime._seed_profile_file(tmp_path, Path("test.md"), "must not publish", 1235, 50)
    assert not (tmp_path / "test.md").exists()


@pytest.mark.parametrize("relative", [Path("../escape"), Path("/tmp/escape"), Path(".")])
def test_seed_rejects_paths_outside_opened_data_root(tmp_path: Path, relative) -> None:
    with pytest.raises(DeploymentError, match="必须位于数据根之下"):
        runtime._seed_profile_file(
            tmp_path, relative, "must not publish", os.geteuid(), os.getegid(),
        )


def test_group_writable_atomic_source_edit_is_a_valid_initialization_seed(tmp_path: Path) -> None:
    config, source, template_root, _ = _claude_prompt_profile(tmp_path)
    source.write_text("# Original\n")
    source.chmod(0o664)
    _profile_bundle(config, template_root)
    replacement = source.with_name("editor-save.tmp")
    replacement.write_text("# Edited source\n")
    replacement.chmod(0o664)
    replacement.replace(source)
    files, _ = _profile_bundle(config, template_root)
    assert "# Edited source" in files["CLAUDE.md"]


def test_root_seed_snapshot_is_still_verified_independently_of_user_edits(
    tmp_path: Path, monkeypatch,
) -> None:
    config = _host_config(tmp_path)
    manifest = _manifest(config, tmp_path)
    files = {"CLAUDE.md": "# Immutable seed snapshot\n"}
    manifest = replace(
        manifest,
        profile_digest=runtime._profile_digest(files),
        policy_snapshot_path=str(
            config.paths.state / "policies" / f"{manifest.policy_digest}.yaml"
        ),
    )
    generation = config.paths.state / "generated/current"
    snapshot = generation / "profile"
    snapshot.mkdir(parents=True)
    (snapshot / "CLAUDE.md").write_text(files["CLAUDE.md"])
    (generation / "runtime.json").write_text(json.dumps(asdict(manifest)))
    monkeypatch.setattr(runtime, "_require_current_generation", lambda _: None)
    assert runtime.load_runtime(config) == manifest
    (config.target.home / ".bashrc").write_text("# User may edit this\n")
    assert runtime.load_runtime(config) == manifest
    (snapshot / "CLAUDE.md").write_text("# Corrupted root snapshot\n")
    with pytest.raises(DeploymentError, match="运行 profile 与运行清单摘要不一致"):
        runtime.load_runtime(config)


def test_profile_skips_missing_optional_shell_initializers(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    config = replace(
        config,
        target=replace(config.target, uid=os.getuid(), gid=os.getgid()),
    )
    host_bashrc = config.target.home / ".bashrc"
    optional_initializer = config.target.home / ".deno" / "env"
    host_bashrc.write_text(
        f"""export EDITOR=vim
# >>> conda initialize >>>
__conda_setup="$('/home/alice/miniconda3/bin/conda' 'shell.bash' 'hook')"
# <<< conda initialize <<<
conda activate pthgnn
. \"{optional_initializer}\"
""",
        encoding="utf-8",
    )
    config = replace(config, profile=replace(config.profile, bashrc=host_bashrc))

    files, digest_without_initializer = _profile_bundle(config, Path.cwd())

    assert "export EDITOR=vim" in files[".bashrc"]
    assert "conda initialize" not in files[".bashrc"]
    assert "conda activate pthgnn" not in files[".bashrc"]
    assert ".deno/env" not in files[".bashrc"]

    optional_initializer.parent.mkdir()
    optional_initializer.write_text("export DENO_INSTALL=ready\n", encoding="utf-8")
    updated_files, digest_with_initializer = _profile_bundle(config, Path.cwd())

    assert str(optional_initializer) in updated_files[".bashrc"]
    assert digest_with_initializer != digest_without_initializer


def test_start_does_not_recheck_edited_profile_sources(tmp_path: Path, monkeypatch) -> None:
    config = _host_config(tmp_path)
    config = replace(
        config,
        target=replace(config.target, uid=os.getuid(), gid=os.getgid()),
    )
    host_bashrc = config.target.home / ".bashrc"
    host_bashrc.write_text("export EDITOR=vim\n", encoding="utf-8")
    config = replace(
        config,
        profile=replace(config.profile, bashrc=host_bashrc),
    )
    _, source_digest = _profile_bundle(config, Path.cwd())
    manifest = replace(
        _manifest(config, tmp_path),
        profile_source_digest=source_digest,
    )

    host_bashrc.write_text("export EDITOR=nvim\n", encoding="utf-8")
    monkeypatch.setattr(runtime, "load_runtime", lambda _: manifest)
    monkeypatch.setattr(runtime, "_require_root", lambda: None)
    monkeypatch.setattr(runtime, "_require_policy_files", lambda _: None)
    monkeypatch.setattr(runtime, "_require_target_image", lambda *_: None)
    monkeypatch.setattr(runtime, "_require_gateway_image", lambda *_: None)
    monkeypatch.setattr(runtime, "_check_gpu_cdi", lambda _: None)
    monkeypatch.setattr(runtime, "_service_container_id", lambda *_: None)

    def no_profile_reread(*args):
        pytest.fail("start must not reread mutable profile sources")

    class ReachedHostSetup(Exception):
        pass

    def reached_host_setup(*args):
        raise ReachedHostSetup

    monkeypatch.setattr(runtime, "_profile_bundle", no_profile_reread)
    monkeypatch.setattr(runtime, "_install_host_parent_guard", reached_host_setup)
    with pytest.raises(ReachedHostSetup):
        compose_start_closed(config)


def test_profile_sources_must_be_owned_regular_files_inside_target_home(
    tmp_path: Path,
) -> None:
    config = _host_config(tmp_path)
    outside = tmp_path / "outside"
    outside.write_text("outside\n", encoding="utf-8")
    config = replace(
        config,
        profile=replace(config.profile, bashrc=outside),
    )
    with pytest.raises(DeploymentError, match="目标用户 Home"):
        _profile_bundle(config, Path.cwd())

    inside = config.target.home / ".bashrc.real"
    inside.write_text("inside\n", encoding="utf-8")
    link = config.target.home / ".bashrc"
    link.symlink_to(inside)
    config = replace(
        config,
        profile=replace(config.profile, bashrc=link),
    )
    with pytest.raises(DeploymentError, match="符号链接"):
        _profile_bundle(config, Path.cwd())


def test_profile_sources_reject_unsafe_permissions_and_wrong_owner(
    tmp_path: Path,
) -> None:
    config = _host_config(tmp_path)
    config = replace(
        config,
        target=replace(config.target, uid=os.getuid(), gid=os.getgid()),
    )
    bashrc = config.target.home / ".bashrc"
    bashrc.write_text("export EDITOR=vim\n", encoding="utf-8")
    config = replace(
        config,
        profile=replace(config.profile, bashrc=bashrc),
    )

    bashrc.chmod(0o666)
    with pytest.raises(DeploymentError, match="其他用户写入"):
        _profile_bundle(config, Path.cwd())

    bashrc.chmod(0o644)
    config = replace(
        config,
        target=replace(config.target, uid=config.target.uid + 1),
    )
    with pytest.raises(DeploymentError, match="所有者不是目标用户"):
        _profile_bundle(config, Path.cwd())


def test_target_dns_queries_only_reach_project_dns(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    compose = render_closed_compose(config, _manifest(config, tmp_path))
    target = compose["services"]["target"]
    assert "dns" not in target
    resolver = next(
        item for item in target["volumes"] if item["target"] == "/etc/resolv.conf"
    )
    assert resolver["source"].endswith("/generated/current/target-resolv.conf")
    assert resolver["read_only"] is True
    dns = compose["services"]["dns"]
    assert set(dns["networks"]) == {"target_net"}
    assert "canary_net" not in dns["networks"]


def test_project_path_is_identical_inside_and_outside(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    compose = render_closed_compose(config, _manifest(config, tmp_path))
    mounts = compose["services"]["target"]["volumes"]
    project = next(item for item in mounts if item["source"].endswith("/project"))
    assert project["source"] == project["target"]
    assert project["read_only"] is False


def test_http_upstream_is_gateway_only(tmp_path: Path) -> None:
    config = replace(
        _host_config(tmp_path),
        upstream=UpstreamConfig(
            kind="http",
            host="127.0.0.1",
            port=26940,
            config_path=None,
            expected_exit_cidr="8.0.0.0/8",
        ),
    )
    compose = render_closed_compose(config, _manifest(config, tmp_path))
    target = compose["services"]["target"]
    gateway = compose["services"]["gateway"]
    dns = compose["services"]["dns"]

    assert set(target["networks"]) == {"target_net"}
    assert set(gateway["networks"]) == {"target_net", "canary_net", "upstream_net"}
    assert set(dns["networks"]) == {"target_net", "upstream_net"}
    assert compose["networks"]["upstream_net"]["internal"] is True
    assert compose["networks"]["upstream_net"]["ipam"]["config"] == [
        {"subnet": "172.28.0.32/28", "gateway": "172.28.0.33"}
    ]
    assert gateway["networks"]["upstream_net"]["ipv4_address"] == "172.28.0.34"
    assert dns["networks"]["upstream_net"]["ipv4_address"] == "172.28.0.35"
    assert gateway["environment"]["CDM_UPSTREAM_HOST"] == "upstream.cdm.test"
    assert gateway["environment"]["CDM_UPSTREAM_PORT"] == "26940"
    assert "upstream.cdm.test:172.28.0.33" in gateway["extra_hosts"]
    assert "upstream.cdm.test:172.28.0.33" in dns["extra_hosts"]
    assert "--doh-address" in dns["command"]
    assert "1.1.1.1" in dns["command"]
    assert dns["pids_limit"] == 128


def test_upstream_exit_must_match_host_configured_range(tmp_path: Path, monkeypatch) -> None:
    config = replace(
        _host_config(tmp_path),
        upstream=UpstreamConfig(
            kind="http",
            host="127.0.0.1",
            port=26940,
            config_path=None,
            expected_exit_cidr="8.0.0.0/8",
        ),
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 0, stdout="8.8.8.8\n", stderr=""
        ),
    )
    assert _check_upstream(config) == "8.8.8.8"

    monkeypatch.setattr(
        "controlled_dev_machine.runtime._run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 0, stdout="9.9.9.9\n", stderr=""
        ),
    )
    with pytest.raises(DeploymentError, match="不在声明范围"):
        _check_upstream(config)


def test_host_parent_guard_allows_only_project_infrastructure(
    tmp_path: Path, monkeypatch
) -> None:
    config = replace(
        _host_config(tmp_path),
        upstream=UpstreamConfig(
            kind="http", host="127.0.0.1", port=26940, config_path=None
        ),
    )
    manifest = _manifest(config, tmp_path)
    scripts: list[tuple[str, str]] = []

    monkeypatch.setattr(
        "controlled_dev_machine.runtime._upstream_bridge_name",
        lambda _config, _manifest: "br-123456789012",
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._apply_host_nft",
        lambda table, script: scripts.append((table, script)),
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 0, stdout="tcp dport 26940 drop\n"
        ),
    )

    _configure_host_parent_guard(config, manifest)

    table, script = scripts[0]
    assert table == _host_parent_table(manifest)
    assert 'iifname "lo" tcp dport 26940 accept' in script
    assert (
        'iifname "br-123456789012" ip saddr { 172.28.0.34, 172.28.0.35 } '
        "tcp dport 26940 accept"
    ) in script
    assert 'iifname "br-123456789012" drop' in script
    assert "tcp dport 26940 drop" in script


def test_stopped_parent_guard_keeps_the_parent_proxy_loopback_only(tmp_path: Path) -> None:
    config = replace(
        _host_config(tmp_path),
        upstream=UpstreamConfig(
            kind="http", host="127.0.0.1", port=26940, config_path=None
        ),
    )
    script = _stopped_host_parent_guard_script(config, _manifest(config, tmp_path))

    assert 'iifname "lo" tcp dport 26940 accept' in script
    assert "tcp dport 26940 drop" in script
    assert "172.28.0.34" not in script
    assert "172.28.0.35" not in script


def test_parent_guard_service_reloads_in_one_nft_transaction(tmp_path: Path) -> None:
    initial = tmp_path / "guard.nft"
    reload = tmp_path / "guard.reload.nft"
    script = _host_parent_guard_runner_script(
        "/usr/sbin/nft", "cdm_parent_test", initial, reload
    )

    assert "delete table" not in script
    assert f"exec $NFT -f {reload}" in script
    assert f"exec $NFT -f {initial}" in script


def test_repeated_start_exits_before_changing_host_state(
    tmp_path: Path, monkeypatch
) -> None:
    config = _host_config(tmp_path)
    manifest = _manifest(config, tmp_path)
    touched: list[str] = []
    monkeypatch.setattr("controlled_dev_machine.runtime.load_runtime", lambda _config: manifest)
    monkeypatch.setattr("controlled_dev_machine.runtime._require_root", lambda: None)
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._require_policy_files", lambda _manifest: None
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._require_gateway_image",
        lambda _config, _manifest: None,
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._require_target_image",
        lambda _config, _manifest: None,
    )
    monkeypatch.setattr("controlled_dev_machine.runtime._check_gpu_cdi", lambda _config: None)
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._service_container_id",
        lambda _config, _manifest, _service: "running",
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._install_host_parent_guard",
        lambda _config, _manifest: touched.append("guard"),
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._check_upstream",
        lambda _config: touched.append("upstream"),
    )

    with pytest.raises(DeploymentError, match="环境已经运行"):
        compose_start_closed(config)
    assert touched == []


def _audit_state() -> dict[str, object]:
    identity = {"executable_path": "/bin/true", "executable_device": 1, "executable_inode": 2}
    return {
        "run_id": "run-test",
        "entries": [
            {"kind": kind, "pid": index, "starttime": index, "identity": identity}
            for index, kind in enumerate(
                (
                    "target-pcap",
                    "gateway-pcap",
                    "dns-pcap",
                    "target-connect-ebpf",
                    "network-watchdog",
                ),
                start=10,
            )
        ],
        "namespaces": [
            {"name": name, "pid": index, "starttime": index, "identity": identity}
            for index, name in enumerate(("target", "gateway", "dns"), start=20)
        ],
    }


def test_audit_status_requires_exact_probe_and_namespace_sets(
    tmp_path: Path, monkeypatch
) -> None:
    config = _host_config(tmp_path)
    path = config.paths.state / "audit-active.json"
    path.parent.mkdir(parents=True)
    monkeypatch.setattr("controlled_dev_machine.runtime._require_root", lambda: None)
    monkeypatch.setattr(
        "controlled_dev_machine.runtime.process_matches", lambda *_args, **_kwargs: True
    )
    state = _audit_state()
    path.write_text(json.dumps(state), encoding="utf-8")
    assert audit_status(config)["active"] is True

    entries = state["entries"]
    assert isinstance(entries, list)
    entries[-1]["kind"] = "target-pcap"
    path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(DeploymentError, match="探针集合不完整"):
        audit_status(config)

    state = _audit_state()
    namespaces = state["namespaces"]
    assert isinstance(namespaces, list)
    namespaces[-1]["name"] = "target"
    path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(DeploymentError, match="网络命名空间集合不完整"):
        audit_status(config)

    relay_config = replace(
        config,
        service_ports=ServicePorts(bind_address="127.0.0.1", start=25600, end=25700),
    )
    state = _audit_state()
    entries = state["entries"]
    assert isinstance(entries, list)
    entries.insert(
        -1,
        {
            "kind": "service-relay",
            "pid": 30,
            "starttime": 30,
            "identity": {
                "executable_path": "/bin/true",
                "executable_device": 1,
                "executable_inode": 2,
            },
        },
    )
    path.write_text(json.dumps(state), encoding="utf-8")
    assert audit_status(relay_config)["active"] is True


def test_audit_probe_requires_an_explicit_ready_marker(tmp_path: Path) -> None:
    class Process:
        def poll(self):
            return None

    error_log = tmp_path / "probe.log"
    error_log.write_text("tcpdump: listening on any\n", encoding="utf-8")

    _wait_audit_probe_ready(
        "target-pcap",
        Process(),  # type: ignore[arg-type]
        error_log=error_log,
        timeout_seconds=0.1,
    )

    error_log.write_text("service relay ready\n", encoding="utf-8")
    _wait_audit_probe_ready(
        "service-relay",
        Process(),  # type: ignore[arg-type]
        error_log=error_log,
        timeout_seconds=0.1,
    )

    error_log.write_text("", encoding="utf-8")
    with pytest.raises(DeploymentError, match="未在期限内就绪"):
        _wait_audit_probe_ready(
            "target-pcap",
            Process(),  # type: ignore[arg-type]
            error_log=error_log,
            timeout_seconds=0.01,
        )


def test_ebpf_readiness_requires_observed_syscall_canaries(
    tmp_path: Path, monkeypatch
) -> None:
    class Process:
        returncode = 0

        def poll(self):
            return None

        def communicate(self, timeout=None):
            return "", ""

        def kill(self):
            return None

    config = _host_config(tmp_path)
    capture_path = tmp_path / "connect.log"
    error_log = tmp_path / "bpftrace.log"
    capture_path.write_text("", encoding="utf-8")
    error_log.write_text("", encoding="utf-8")
    markers = "\n".join(
        (
            "CDM_EXEC|",
            "CDM_CONNECT_BEGIN|",
            "CDM_CONNECT_END|",
            "CDM_SENDTO_BEGIN|",
            "CDM_SENDTO_END|",
            "CDM_SENDMSG_BEGIN|",
            "CDM_SENDMSG_END|",
        )
    )

    def run_canary(*_args, **_kwargs):
        capture_path.write_text(markers, encoding="utf-8")
        return Process()

    monkeypatch.setattr("controlled_dev_machine.runtime.compose_exec_async", run_canary)
    _wait_target_ebpf_ready(
        config,
        Process(),  # type: ignore[arg-type]
        error_log=error_log,
        capture_path=capture_path,
        timeout_seconds=0.1,
    )

    capture_path.write_text("CDM_EXEC|\n", encoding="utf-8")
    monkeypatch.setattr(
        "controlled_dev_machine.runtime.compose_exec_async", lambda *_args, **_kwargs: Process()
    )
    with pytest.raises(DeploymentError, match="未确认全部探针附着"):
        _wait_target_ebpf_ready(
            config,
            Process(),  # type: ignore[arg-type]
            error_log=error_log,
            capture_path=capture_path,
            timeout_seconds=0.01,
        )


def test_transparent_firewalls_allow_only_the_controlled_paths(
    tmp_path: Path, monkeypatch
) -> None:
    config = replace(
        _host_config(tmp_path),
        upstream=UpstreamConfig(
            kind="http", host="127.0.0.1", port=26940, config_path=None
        ),
        service_ports=ServicePorts(bind_address="0.0.0.0", start=25600, end=25700),
    )
    manifest = _manifest(config, tmp_path)
    pids = {"gateway": 101, "dns": 102, "target": 103}
    scripts: dict[int, str] = {}
    commands: list[list[str]] = []
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._service_pid",
        lambda _config, _manifest, service: pids[service],
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._container_host_address",
        lambda _pid, _host: "172.30.0.1",
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._apply_nft",
        lambda pid, script: scripts.__setitem__(pid, script),
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._verify_nft_table", lambda _pid: None
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._transparent_tcp_ports",
        lambda _manifest: (80, 443, 18680),
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._run",
        lambda command, **_kwargs: commands.append(command),
    )

    _configure_infrastructure_network(config, manifest)
    _configure_target_network(config, manifest)
    _enable_target_route(config, manifest)

    gateway = scripts[101]
    assert "tcp dport { 80, 443, 18680 } redirect to :8080" in gateway
    assert "chain forward" in gateway and "policy drop" in gateway
    assert "ip daddr @audit_parent_addresses tcp dport 26940 accept" in gateway
    assert "ip daddr @audit_canary_addresses tcp dport { 80, 443 } accept" in gateway
    gateway_output = gateway.split("chain output", 1)[1]
    assert "    ct state established,related accept" not in gateway_output
    assert "udp dport 53 accept" not in gateway

    dns = scripts[102]
    assert "ip daddr @audit_parent_addresses tcp dport 26940 accept" in dns
    assert "ip saddr @audit_target_addresses udp dport 53 accept" in dns
    assert "policy drop" in dns

    target = scripts[103]
    assert "ip daddr @audit_dns_addresses udp dport 53 accept" in target
    assert "tcp dport @audit_tcp_ports accept" in target
    assert "tcp dport 25600-25700 accept" not in target
    assert "policy drop" in target
    assert any(command[-3:] == ["default", "via", "172.28.0.2"] for command in commands)


def test_host_ssh_is_narrowly_allowed_and_target_network_gets_host_gateway(
    tmp_path: Path, monkeypatch
) -> None:
    config = replace(
        _host_config(tmp_path),
        host_ssh=HostSshConfig(enabled=True, port=10090),
    )
    manifest = _manifest(config, tmp_path)
    scripts: dict[int, str] = {}
    host_scripts: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._service_pid",
        lambda *_args: 103,
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._apply_nft",
        lambda pid, script: scripts.__setitem__(pid, script),
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._verify_nft_table", lambda _pid: None
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._apply_host_nft",
        lambda table, script: host_scripts.append((table, script)),
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout=""),
    )

    _configure_target_network(config, manifest)
    _configure_host_ssh_guard(config, manifest)

    assert "ip daddr 172.28.0.1 tcp dport 10090 accept" in scripts[103]
    assert "tcp dport 22 accept" not in scripts[103]
    assert len(host_scripts) == 1
    assert "ip saddr 172.28.0.3 ip daddr 172.28.0.1 tcp dport 10090 accept" in host_scripts[0][1]
    assert "ip daddr 172.28.0.1 tcp dport 10090 drop" in host_scripts[0][1]
    stopped = _stopped_host_ssh_guard_script(config, manifest)
    assert "172.28.0.3" not in stopped.split("tcp dport", 1)[0]


def test_host_access_network_mode_is_nat_only_when_enabled(tmp_path: Path) -> None:
    disabled_config = _host_config(tmp_path)
    disabled = render_closed_compose(disabled_config, _manifest(disabled_config, tmp_path))
    enabled_config = replace(
        disabled_config, host_ssh=HostSshConfig(enabled=True, port=10090)
    )
    enabled = render_closed_compose(enabled_config, _manifest(enabled_config, tmp_path))
    disabled_mode = disabled["networks"]["target_net"]["driver_opts"][
        "com.docker.network.bridge.gateway_mode_ipv4"
    ]
    enabled_mode = enabled["networks"]["target_net"]["driver_opts"][
        "com.docker.network.bridge.gateway_mode_ipv4"
    ]
    assert disabled_mode == "isolated"
    assert enabled_mode == "nat"


def _gateway_source_tree(root: Path) -> None:
    files = {
        "images/target/Dockerfile": "FROM scratch\n",
        "images/gateway/Dockerfile": "FROM scratch\n",
        "gateway/mitmproxy/cdm_addon.py": "addons = []\n",
        "gateway/mitmproxy/entrypoint.sh": "#!/bin/sh\n",
        "target/entrypoint.sh": "#!/bin/sh\n",
        "config/claude/CLAUDE.md": "Use the current project.\n",
        "src/controlled_dev_machine/connect.bt": "tracepoint:syscalls:sys_enter_execve {}\n",
        "src/controlled_dev_machine/example.py": "VALUE = 1\n",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def test_gateway_build_digest_covers_gateway_and_controller_sources(tmp_path: Path) -> None:
    _gateway_source_tree(tmp_path)
    original = _gateway_build_digest(tmp_path)
    source = tmp_path / "src/controlled_dev_machine/example.py"
    source.write_text("VALUE = 2\n", encoding="utf-8")
    assert _gateway_build_digest(tmp_path) != original

    _gateway_source_tree(tmp_path)
    audit_source = tmp_path / "src/controlled_dev_machine/connect.bt"
    audit_source.write_text("tracepoint:syscalls:sys_enter_connect {}\n", encoding="utf-8")
    assert _gateway_build_digest(tmp_path) != original


def test_gateway_image_label_must_match_current_sources(tmp_path: Path, monkeypatch) -> None:
    _gateway_source_tree(tmp_path)
    config = _host_config(tmp_path)
    digest = _gateway_build_digest(tmp_path)
    manifest = replace(
        _manifest(config, tmp_path),
        repo_root=str(tmp_path),
        gateway_build_digest=digest,
        gateway_image=f"cdm-u1000-main-gateway:{digest[:16]}",
    )

    def inspect_ok(*_args, **_kwargs):
        return subprocess.CompletedProcess([], 0, stdout=digest + "\n", stderr="")

    monkeypatch.setattr("controlled_dev_machine.runtime._docker", inspect_ok)
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._require_pinned_image_id",
        lambda *_args, **_kwargs: None,
    )
    _require_gateway_image(config, manifest)

    def inspect_old(*_args, **_kwargs):
        return subprocess.CompletedProcess([], 0, stdout="old\n", stderr="")

    monkeypatch.setattr("controlled_dev_machine.runtime._docker", inspect_old)
    with pytest.raises(DeploymentError, match="构建摘要不符"):
        _require_gateway_image(config, manifest)


def test_gateway_source_change_requires_reinitialization(tmp_path: Path, monkeypatch) -> None:
    _gateway_source_tree(tmp_path)
    config = _host_config(tmp_path)
    digest = _gateway_build_digest(tmp_path)
    manifest = replace(
        _manifest(config, tmp_path),
        repo_root=str(tmp_path),
        gateway_build_digest=digest,
    )
    (tmp_path / "gateway/mitmproxy/cdm_addon.py").write_text(
        "addons = ['changed']\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._docker",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout="", stderr=""),
    )
    with pytest.raises(DeploymentError, match="源码已变化"):
        _require_gateway_image(config, manifest)


def test_target_image_tag_and_label_match_build_inputs(tmp_path: Path, monkeypatch) -> None:
    _gateway_source_tree(tmp_path)
    config = _host_config(tmp_path)
    digest = _target_build_digest(config, tmp_path)
    manifest = replace(
        _manifest(config, tmp_path),
        repo_root=str(tmp_path),
        target_build_digest=digest,
        target_image=f"cdm-u1000-main-target:{digest[:16]}",
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._docker",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 0, stdout=digest + "\n", stderr=""
        ),
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._require_pinned_image_id",
        lambda *_args, **_kwargs: None,
    )
    _require_target_image(config, manifest)

    (tmp_path / "images/target/Dockerfile").write_text("FROM scratch\nRUN true\n")
    with pytest.raises(DeploymentError, match="构建输入已变化"):
        _require_target_image(config, manifest)


@pytest.mark.parametrize("setting", ["_BUILD_PROVENANCE", "_BUILD_SBOM"])
def test_target_build_digest_covers_attestation_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, setting: str
) -> None:
    _gateway_source_tree(tmp_path)
    config = _host_config(tmp_path)
    original = _target_build_digest(config, tmp_path)

    monkeypatch.setattr(f"controlled_dev_machine.runtime.{setting}", True)

    assert _target_build_digest(config, tmp_path) != original


def test_compose_build_disables_attestations_at_command_level(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _host_config(tmp_path)
    manifest = _manifest(config, tmp_path)
    compose_calls: list[tuple[str, ...]] = []
    monkeypatch.setattr("controlled_dev_machine.runtime.load_runtime", lambda _config: manifest)
    monkeypatch.setattr("controlled_dev_machine.runtime._require_root", lambda: None)
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._require_instance_stopped",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr("controlled_dev_machine.runtime.sync_base_images", lambda _config: None)
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._compose",
        lambda _config, _manifest, *args: compose_calls.append(args),
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._pin_built_images",
        lambda _config, _manifest: None,
    )

    compose_build.__wrapped__(config)

    assert compose_calls == [
        ("build", "--provenance=false", "--sbom=false", "target", "gateway")
    ]


@pytest.mark.parametrize(
    ("root", "expected_user"),
    [(False, "1000:1000"), (True, "0:0")],
)
def test_compose_shell_forwards_terminal_capabilities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    root: bool,
    expected_user: str,
) -> None:
    config = _host_config(tmp_path)
    manifest = _manifest(config, tmp_path)
    compose_calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
    monkeypatch.setenv("TERM", "screen-256color")
    monkeypatch.setenv("COLORTERM", "truecolor")
    monkeypatch.setattr("controlled_dev_machine.runtime.load_runtime", lambda _config: manifest)
    monkeypatch.setattr("controlled_dev_machine.runtime._require_root", lambda: None)
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._compose",
        lambda _config, _manifest, *args, **kwargs: (
            compose_calls.append((args, kwargs))
            or subprocess.CompletedProcess(args, 0)
        ),
    )

    assert compose_shell(config, root=root) == 0
    assert compose_calls == [
        (
            (
                "exec",
                "--env",
                "TERM=screen-256color",
                "--env",
                "COLORTERM=truecolor",
                "--user",
                expected_user,
                "target",
                "bash",
            ),
            {"check": False},
        )
    ]


@pytest.mark.parametrize("term", [None, "", "dumb", "unknown", "xterm"])
def test_compose_shell_uses_builtin_256_color_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, term: str | None
) -> None:
    config = _host_config(tmp_path)
    manifest = _manifest(config, tmp_path)
    compose_calls: list[tuple[str, ...]] = []
    if term is None:
        monkeypatch.delenv("TERM", raising=False)
    else:
        monkeypatch.setenv("TERM", term)
    monkeypatch.delenv("COLORTERM", raising=False)
    monkeypatch.setattr("controlled_dev_machine.runtime.load_runtime", lambda _config: manifest)
    monkeypatch.setattr("controlled_dev_machine.runtime._require_root", lambda: None)
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._compose",
        lambda _config, _manifest, *args, **_kwargs: (
            compose_calls.append(args) or subprocess.CompletedProcess(args, 0)
        ),
    )

    assert compose_shell(config, root=False) == 0
    assert compose_calls == [
        (
            "exec",
            "--env",
            "TERM=xterm-256color",
            "--user",
            "1000:1000",
            "target",
            "bash",
        )
    ]


def test_built_image_ids_are_pinned_and_rechecked(tmp_path: Path, monkeypatch) -> None:
    config = _host_config(tmp_path)
    manifest = _manifest(config, tmp_path)
    image_ids = {
        manifest.target_image: "sha256:" + "1" * 64,
        manifest.gateway_image: "sha256:" + "2" * 64,
    }
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._mkdir",
        lambda path, _mode, _uid, _gid: path.mkdir(parents=True, exist_ok=True),
    )
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._inspect_image_id",
        lambda _config, image: image_ids[image],
    )

    _pin_built_images(config, manifest)
    _require_pinned_image_id(config, manifest, "target", manifest.target_image)

    image_ids[manifest.target_image] = "sha256:" + "3" * 64
    with pytest.raises(DeploymentError, match="已经登记了不同"):
        _pin_built_images(config, manifest)
    with pytest.raises(DeploymentError, match="内容 ID 已变化"):
        _require_pinned_image_id(config, manifest, "target", manifest.target_image)


def test_lifecycle_lock_is_global_for_the_user(tmp_path: Path, monkeypatch) -> None:
    config = _host_config(tmp_path)
    alternate = replace(config, instance="second")
    lock_root = tmp_path / "locks"
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._LIFECYCLE_LOCK_ROOT", lock_root
    )
    with (
        _lifecycle_lock(config),
        pytest.raises(DeploymentError, match="生命周期操作"),
        _lifecycle_lock(alternate),
    ):
        assert lock_root.stat().st_mode & 0o777 == 0o700
        assert (lock_root / f"u{config.target.uid}.lock").stat().st_mode & 0o777 == 0o600


def test_init_and_build_reject_a_running_instance(tmp_path: Path, monkeypatch) -> None:
    config = _host_config(tmp_path)
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._docker",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 0, stdout="container-id\n", stderr=""
        ),
    )
    with pytest.raises(DeploymentError, match="先运行 sandboxctl stop"):
        _require_instance_stopped(config, operation="build")


def _generation(config, name: str, marker: str) -> Path:
    path = config.paths.state / "generated" / "generations" / name
    path.mkdir(parents=True)
    for filename in (
        "runtime.json",
        "compose.closed.yaml",
        "policy.active.yaml",
        "target-resolv.conf",
        "target-password-hash",
    ):
        (path / filename).write_text(f"{marker}:{filename}\n", encoding="utf-8")
    return path


def test_generation_switch_changes_the_complete_bundle_with_one_pointer(
    tmp_path: Path,
) -> None:
    config = _host_config(tmp_path)
    first = _generation(config, "first", "one")
    second = _generation(config, "second", "two")
    _activate_generation(config, first)
    current = config.paths.state / "generated" / "current"
    assert current.is_symlink()
    assert {item.read_text()[:3] for item in current.iterdir()} == {"one"}

    _activate_generation(config, second)
    assert {item.read_text()[:3] for item in current.iterdir()} == {"two"}


def test_failed_generation_pointer_replace_keeps_previous_bundle(
    tmp_path: Path, monkeypatch
) -> None:
    config = _host_config(tmp_path)
    first = _generation(config, "first", "one")
    second = _generation(config, "second", "two")
    _activate_generation(config, first)
    current = config.paths.state / "generated" / "current"
    original_replace = os.replace

    def fail_current(source, target):
        if Path(target) == current:
            raise OSError("simulated pointer failure")
        return original_replace(source, target)

    monkeypatch.setattr("controlled_dev_machine.runtime.os.replace", fail_current)
    with pytest.raises(OSError, match="pointer failure"):
        _activate_generation(config, second)
    assert {item.read_text()[:3] for item in current.iterdir()} == {"one"}


def test_runtime_requires_matching_snapshot_and_active_policy(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    policy_text = Path("policies/strict/0001-bootstrap.yaml").read_text(encoding="utf-8")
    active = tmp_path / "policy.active.yaml"
    snapshot = tmp_path / "policy.snapshot.yaml"
    active.write_text(policy_text, encoding="utf-8")
    snapshot.write_text(policy_text, encoding="utf-8")
    digest = load_policy(active).digest()
    manifest = replace(
        _manifest(config, tmp_path),
        policy_path=str(active),
        policy_snapshot_path=str(snapshot),
        policy_digest=digest,
    )
    _require_policy_files(manifest)
    active.write_text(policy_text.replace("revision: 1", "revision: 2"), encoding="utf-8")
    with pytest.raises(DeploymentError, match="活动策略副本"):
        _require_policy_files(manifest)


def test_test_only_policy_is_not_deployable(tmp_path: Path) -> None:
    path = tmp_path / "test-only.yaml"
    path.write_text(
        """
schema_version: 1
policy_id: test-only
revision: 1
mode: strict
created_at: "2026-08-05T00:00:00Z"
parent_digest:
deployment: test_only
web_default: review
rules: []
""".lstrip(),
        encoding="utf-8",
    )
    policy = load_policy(path)
    with pytest.raises(DeploymentError, match="不能部署"):
        _require_deployable_policy(policy)


def test_daily_policy_is_deployable() -> None:
    policy = load_policy(Path("policies/daily/0001-public-web.yaml"))
    _require_deployable_policy(policy)


def test_legacy_stop_accepts_only_the_instances_fixed_compose_path(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    runtime_path = config.paths.state / "runtime.json"
    runtime_path.parent.mkdir(parents=True)
    expected = config.paths.state / "generated" / "compose.closed.yaml"
    raw = {
        "schema_version": 2,
        "instance": config.instance,
        "resource_prefix": config.resource_prefix,
        "compose_path": str(expected),
    }
    runtime_path.write_text(json.dumps(raw), encoding="utf-8")
    assert _legacy_compose_path_for_stop(config) == expected

    raw["compose_path"] = str(tmp_path / "other.yaml")
    runtime_path.write_text(json.dumps(raw), encoding="utf-8")
    assert _legacy_compose_path_for_stop(config) is None
