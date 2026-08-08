import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from controlled_dev_machine.config import (
    HostProfile,
    ProjectMount,
    UpstreamConfig,
    load_host_config,
)
from controlled_dev_machine.errors import DeploymentError
from controlled_dev_machine.policy import load_policy
from controlled_dev_machine.runtime import (
    RuntimeManifest,
    _activate_generation,
    _check_upstream,
    _configure_host_parent_guard,
    _configure_infrastructure_network,
    _configure_target_network,
    _dns_policy_args,
    _enable_target_route,
    _gateway_build_digest,
    _host_parent_guard_runner_script,
    _host_parent_table,
    _host_password_hash,
    _legacy_compose_path_for_stop,
    _lifecycle_lock,
    _pin_built_images,
    _prepare_directories,
    _profile_bundle,
    _require_deployable_policy,
    _require_gateway_image,
    _require_instance_stopped,
    _require_pinned_image_id,
    _require_policy_files,
    _require_profile_sources,
    _require_target_image,
    _stopped_host_parent_guard_script,
    _target_build_digest,
    _wait_audit_probe_ready,
    _wait_target_ebpf_ready,
    audit_status,
    compose_shell,
    compose_start_closed,
    render_closed_compose,
)


@pytest.fixture(autouse=True)
def _use_test_lifecycle_lock(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._LIFECYCLE_LOCK_ROOT", tmp_path / "locks"
    )


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
    assert target["build"]["args"]["TARGET_BUILD_DIGEST"] == "c" * 64
    assert "CDM_TARGET_UID" not in target["environment"]
    assert "CDM_TARGET_GID" not in target["environment"]
    assert target["environment"]["NODE_USE_SYSTEM_CA"] == "1"
    assert not any("PROXY" in name or "proxy" in name for name in target["environment"])
    assert "SSL_CERT_FILE" not in target["environment"]
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
    assert gateway["build"]["args"]["GATEWAY_BUILD_DIGEST"] == "b" * 64
    assert gateway["healthcheck"]["test"] == [
        "CMD",
        "python",
        "-m",
        "controlled_dev_machine.gateway_health",
    ]
    assert gateway["healthcheck"]["retries"] == 3
    assert gateway["healthcheck"]["start_period"] == "20s"


def test_claude_runtime_instructions_are_read_only(tmp_path: Path) -> None:
    config = _host_config(tmp_path)
    compose = render_closed_compose(config, _manifest(config, tmp_path))
    target = compose["services"]["target"]
    instruction = next(
        item for item in target["volumes"] if item["target"].endswith("/.claude/CLAUDE.md")
    )
    assert instruction["source"].endswith("/generated/current/profile/CLAUDE.md")
    assert instruction["read_only"] is True


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
    host_prompt.write_text("# Host instructions\n\nUse Chinese.\n", encoding="utf-8")
    host_bashrc.write_text(
        "export HTTPS_PROXY=http://127.0.0.1:11430\n", encoding="utf-8"
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
    assert "127.0.0.1:11430" not in files[".bashrc"]
    assert "unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY" in files[".bashrc"]
    assert "conda activate \"$CDM_DEFAULT_CONDA_ENV\"" in files[".bashrc"]
    assert "$CDM_CONDA_ROOT/etc/profile.d/conda.sh" in files[".bashrc"]
    assert "$HOME/miniconda3" not in files[".bashrc"]
    assert "unset REQUESTS_CA_BUNDLE SSL_CERT_FILE" in files[".profile"]
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
    assert str(config.target.home / ".bashrc") in profile_targets
    assert str(config.target.home / ".profile") in profile_targets


def test_start_rejects_profile_source_changed_after_init(tmp_path: Path) -> None:
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

    _require_profile_sources(config, manifest)
    host_bashrc.write_text("export EDITOR=nvim\n", encoding="utf-8")
    with pytest.raises(DeploymentError, match="宿主 profile 已变化"):
        _require_profile_sources(config, manifest)


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
            port=11440,
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
    assert gateway["environment"]["CDM_UPSTREAM_PORT"] == "11440"
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
            port=11440,
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
            kind="http", host="127.0.0.1", port=11440, config_path=None
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
            [], 0, stdout="tcp dport 11440 drop\n"
        ),
    )

    _configure_host_parent_guard(config, manifest)

    table, script = scripts[0]
    assert table == _host_parent_table(manifest)
    assert 'iifname "lo" tcp dport 11440 accept' in script
    assert (
        'iifname "br-123456789012" ip saddr { 172.28.0.34, 172.28.0.35 } '
        "tcp dport 11440 accept"
    ) in script
    assert 'iifname "br-123456789012" drop' in script
    assert "tcp dport 11440 drop" in script


def test_stopped_parent_guard_keeps_the_parent_proxy_loopback_only(tmp_path: Path) -> None:
    config = replace(
        _host_config(tmp_path),
        upstream=UpstreamConfig(
            kind="http", host="127.0.0.1", port=11440, config_path=None
        ),
    )
    script = _stopped_host_parent_guard_script(config, _manifest(config, tmp_path))

    assert 'iifname "lo" tcp dport 11440 accept' in script
    assert "tcp dport 11440 drop" in script
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
    monkeypatch.setattr(
        "controlled_dev_machine.runtime._require_profile_sources",
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
            kind="http", host="127.0.0.1", port=11440, config_path=None
        ),
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
    assert "ip daddr @audit_parent_addresses tcp dport 11440 accept" in gateway
    assert "ip daddr @audit_canary_addresses tcp dport { 80, 443 } accept" in gateway
    gateway_output = gateway.split("chain output", 1)[1]
    assert "    ct state established,related accept" not in gateway_output
    assert "udp dport 53 accept" not in gateway

    dns = scripts[102]
    assert "ip daddr @audit_parent_addresses tcp dport 11440 accept" in dns
    assert "ip saddr @audit_target_addresses udp dport 53 accept" in dns
    assert "policy drop" in dns

    target = scripts[103]
    assert "ip daddr @audit_dns_addresses udp dport 53 accept" in target
    assert "tcp dport @audit_tcp_ports accept" in target
    assert "policy drop" in target
    assert any(command[-3:] == ["default", "via", "172.28.0.2"] for command in commands)


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


def test_compose_shell_omits_unset_terminal_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _host_config(tmp_path)
    manifest = _manifest(config, tmp_path)
    compose_calls: list[tuple[str, ...]] = []
    monkeypatch.delenv("TERM", raising=False)
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
    assert compose_calls == [("exec", "--user", "1000:1000", "target", "bash")]


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
