from pathlib import Path
from types import SimpleNamespace

import pytest

from controlled_dev_machine.config import (
    ConfigError,
    create_host_config,
    ensure_invoking_target,
    load_host_config,
)


def _config(tmp_path: Path, *, mounts: str = "mounts: []") -> Path:
    path = tmp_path / "host.yaml"
    path.write_text(
        f"""
schema_version: 1
instance: main
target:
  name: alice
  uid: 1000
  gid: 1000
  home: /home/alice
docker:
  socket: /var/run/docker.sock
paths:
  persistent_home: ~/.local/share/controlled-dev-machine/home
  state: ~/.local/state/controlled-dev-machine/runtime
  audit: ~/.local/state/controlled-dev-machine/audit
storage:
  root:
    min_free_gib: 50
    min_free_percent: 5
  audit:
    min_free_gib: 200
    min_free_percent: 10
  pcap_limit_gib: 100
  plaintext_limit_gib: 50
  structured_limit_gib: 10
upstream:
  kind: unset
{mounts}
""".lstrip(),
        encoding="utf-8",
    )
    return path


def test_paths_resolve_against_target_home_not_process_home(tmp_path: Path) -> None:
    config = load_host_config(_config(tmp_path))
    assert config.paths.audit == Path("/home/alice/.local/state/controlled-dev-machine/audit")
    assert config.resource_prefix == "cdm-u1000-main"
    assert config.gpu.mode == "all"
    assert config.profile.claude_instructions is None
    assert config.profile.conda_root is None
    assert config.profile.default_conda_env is None
    assert config.profile.timezone == "UTC"
    assert config.workspace.share_host_home is False
    assert config.service_ports is None
    assert config.host_ssh.enabled is False
    assert config.host_ssh.port == 22
    assert config.target.hostname == "devbox"
    assert config.target.mac_address is None


def test_target_hostname_is_explicit_and_persistent(tmp_path: Path) -> None:
    path = _config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "  home: /home/alice", "  home: /home/alice\n  hostname: workstation-a24f"
        ),
        encoding="utf-8",
    )
    assert load_host_config(path).target.hostname == "workstation-a24f"
    assert load_host_config(path).target.hostname == "workstation-a24f"


@pytest.mark.parametrize("hostname", ["-host", "host-", "host.name", "host_name", "a" * 64])
def test_target_hostname_rejects_invalid_labels(tmp_path: Path, hostname: str) -> None:
    path = _config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "  home: /home/alice", f"  home: /home/alice\n  hostname: {hostname}"
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="target.hostname"):
        load_host_config(path)


def test_target_mac_address_is_explicit_and_persistent(tmp_path: Path) -> None:
    path = _config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "  home: /home/alice", "  home: /home/alice\n  mac_address: 02:7b:3c:4d:5e:6f"
        ),
        encoding="utf-8",
    )
    assert load_host_config(path).target.mac_address == "02:7b:3c:4d:5e:6f"
    assert load_host_config(path).target.mac_address == "02:7b:3c:4d:5e:6f"


@pytest.mark.parametrize("address", [
    "00:7b:3c:4d:5e:6f", "03:7b:3c:4d:5e:6f", "ff:ff:ff:ff:ff:ff",
    "02:7B:3C:4D:5E:6F", "02-7b-3c-4d-5e-6f", "2:7b:3c:4d:5e:6f",
    "02:7b:3c:4d:5e", "not-a-mac",
])
def test_target_mac_address_rejects_noncanonical_or_invalid_bits(
    tmp_path: Path, address: str,
) -> None:
    path = _config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "  home: /home/alice", f"  home: /home/alice\n  mac_address: {address}"
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="target.mac_address"):
        load_host_config(path)


def test_host_ssh_port_is_explicit_and_validated(tmp_path: Path) -> None:
    path = _config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8") + "\nhost_ssh:\n  enabled: true\n  port: 10090\n",
        encoding="utf-8",
    )
    config = load_host_config(path)
    assert config.host_ssh.enabled is True
    assert config.host_ssh.port == 10090


def test_shared_home_and_service_port_range_are_explicit(tmp_path: Path) -> None:
    path = _config(tmp_path)
    content = path.read_text(encoding="utf-8")
    path.write_text(
        content.replace(
            "state: ~/.local/state/controlled-dev-machine/runtime",
            f"state: {tmp_path}/runtime",
        ).replace(
            "audit: ~/.local/state/controlled-dev-machine/audit",
            f"audit: {tmp_path}/audit",
        )
        + """
workspace:
  share_host_home: true
service_ports:
  bind_address: 0.0.0.0
  start: 25600
  end: 25700
""",
        encoding="utf-8",
    )

    config = load_host_config(path)

    assert config.workspace.share_host_home is True
    assert config.service_ports is not None
    assert config.service_ports.bind_address == "0.0.0.0"
    assert (config.service_ports.start, config.service_ports.end) == (25600, 25700)


def test_controlled_mounts_are_relative_and_seedable(tmp_path: Path) -> None:
    path = _config(tmp_path)
    content = path.read_text(encoding="utf-8")
    path.write_text(
        content.replace(
            "persistent_home: ~/.local/share/controlled-dev-machine/home",
            f"persistent_home: {tmp_path}/managed-home",
        ).replace(
            "state: ~/.local/state/controlled-dev-machine/runtime",
            f"state: {tmp_path}/runtime",
        ).replace(
            "audit: ~/.local/state/controlled-dev-machine/audit",
            f"audit: {tmp_path}/audit",
        )
        + """
workspace:
  share_host_home: true
  controlled_mounts:
    - path: .claude
      access: rw
      seed: copy-if-empty
    - path: .codex
      access: ro
      seed: never
""",
        encoding="utf-8",
    )

    config = load_host_config(path)

    assert [item.relative_path for item in config.workspace.controlled_mounts] == [
        Path(".claude"),
        Path(".codex"),
    ]
    assert config.workspace.controlled_mounts[0].seed == "copy-if-empty"
    assert config.workspace.controlled_mounts[1].read_only is True


@pytest.mark.parametrize("value", ("../outside", "/absolute", "."))
def test_controlled_mount_path_cannot_escape_home(tmp_path: Path, value: str) -> None:
    path = _config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8")
        + f"""
workspace:
  share_host_home: true
  controlled_mounts:
    - path: {value}
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="相对目录"):
        load_host_config(path)


def test_controlled_mounts_cannot_be_used_without_shared_home(tmp_path: Path) -> None:
    path = _config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8")
        + """
workspace:
  controlled_mounts:
    - path: .claude
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="share_host_home"):
        load_host_config(path)


def test_mount_propagation_is_limited_to_private_or_slave(tmp_path: Path) -> None:
    path = _config(
        tmp_path,
        mounts="""
mounts:
  - host_path: /data
    container_path: /data
    access: rw
    propagation: rslave
""".strip(),
    )

    config = load_host_config(path)
    assert config.mounts[0].propagation == "rslave"


def test_controlled_mounts_cannot_overlap_declared_home_mount(tmp_path: Path) -> None:
    path = _config(
        tmp_path,
        mounts="""
mounts:
  - host_path: /data
    container_path: /home/alice
    access: rw
""".strip(),
    )
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace(
            "persistent_home: ~/.local/share/controlled-dev-machine/home",
            f"persistent_home: {tmp_path}/managed-home",
        )
        .replace(
            "state: ~/.local/state/controlled-dev-machine/runtime",
            f"state: {tmp_path}/runtime",
        )
        .replace(
            "audit: ~/.local/state/controlled-dev-machine/audit",
            f"audit: {tmp_path}/audit",
        )
        + """
workspace:
  share_host_home: true
  controlled_mounts:
    - path: .claude
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="不能被 mounts 目标路径覆盖"):
        load_host_config(path)


def test_controlled_mounts_allow_explicit_nested_mount(tmp_path: Path) -> None:
    skills = tmp_path / "skills"
    skills.mkdir()
    path = _config(
        tmp_path,
        mounts=f"""
mounts:
  - host_path: {skills}
    container_path: /home/alice/.claude/skills
    access: rw
""".strip(),
    )
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace(
            "persistent_home: ~/.local/share/controlled-dev-machine/home",
            f"persistent_home: {tmp_path}/managed-home",
        )
        .replace(
            "state: ~/.local/state/controlled-dev-machine/runtime",
            f"state: {tmp_path}/runtime",
        )
        .replace(
            "audit: ~/.local/state/controlled-dev-machine/audit",
            f"audit: {tmp_path}/audit",
        )
        + """
workspace:
  share_host_home: true
  controlled_mounts:
    - path: .claude
""",
        encoding="utf-8",
    )

    config = load_host_config(path)

    assert config.mounts[0].container_path == Path("/home/alice/.claude/skills")


def test_shared_home_requires_control_paths_outside_target_home(tmp_path: Path) -> None:
    path = _config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8")
        + """
workspace:
  share_host_home: true
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="paths.state, paths.audit.*target.home 之外"):
        load_host_config(path)


@pytest.mark.parametrize(
    ("start", "end", "message"),
    ((80, 100, "非特权"), (25700, 25600, "有序"), (20000, 22000, "1024")),
)
def test_service_port_range_is_bounded(
    tmp_path: Path, start: int, end: int, message: str
) -> None:
    path = _config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8")
        + f"""
service_ports:
  bind_address: 127.0.0.1
  start: {start}
  end: {end}
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match=message):
        load_host_config(path)


def test_gpu_mode_cannot_disable_required_gpu_visibility(tmp_path: Path) -> None:
    path = _config(tmp_path).read_text(encoding="utf-8")
    invalid = tmp_path / "invalid-gpu.yaml"
    invalid.write_text(
        path.replace("docker:\n", "gpu:\n  mode: none\n\ndocker:\n"), encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="gpu.mode"):
        load_host_config(invalid)


def test_only_one_fixed_instance_is_supported_per_user(tmp_path: Path) -> None:
    content = _config(tmp_path).read_text(encoding="utf-8")
    alternate = tmp_path / "alternate.yaml"
    alternate.write_text(content.replace("instance: main", "instance: second"), encoding="utf-8")

    with pytest.raises(ConfigError, match="instance 必须为 main"):
        load_host_config(alternate)


def test_explicit_config_cannot_select_another_invoking_account(
    tmp_path: Path, monkeypatch
) -> None:
    config = load_host_config(_config(tmp_path))
    account = SimpleNamespace(
        pw_name="bob", pw_uid=2000, pw_gid=2000, pw_dir="/home/bob"
    )
    monkeypatch.setattr("controlled_dev_machine.config.invoking_account", lambda: account)

    with pytest.raises(ConfigError, match="不能管理其他用户"):
        ensure_invoking_target(config)


def test_project_mount_cannot_expose_audit_tree(tmp_path: Path) -> None:
    path = _config(
        tmp_path,
        mounts="""
mounts:
  - host_path: ~/.local/state
    container_path: /home/alice/state
    access: rw
""".strip(),
    )
    with pytest.raises(ConfigError, match="不能暴露控制或审计目录"):
        load_host_config(path)


def test_project_paths_can_stay_identical(tmp_path: Path) -> None:
    path = _config(
        tmp_path,
        mounts="""
mounts:
  - host_path: ~/project
    container_path: /home/alice/project
    access: rw
""".strip(),
    )
    config = load_host_config(path)
    assert config.mounts[0].host_path == config.mounts[0].container_path


def test_file_mounts_are_supported(tmp_path: Path) -> None:
    credential = tmp_path / "git-credentials"
    credential.write_text("https://user:token@example.invalid\n", encoding="utf-8")
    path = _config(
        tmp_path,
        mounts=f"""
mounts:
  - host_path: {credential}
    container_path: /home/alice/.git-credentials
    access: ro
""".strip(),
    )
    config = load_host_config(path)
    assert config.mounts[0].host_path == credential
    assert config.mounts[0].container_path == Path("/home/alice/.git-credentials")
    assert config.mounts[0].read_only is True


def test_host_profile_paths_and_default_environment_are_host_specific(
    tmp_path: Path,
) -> None:
    path = _config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8")
        + """
profile:
  timezone: Etc/UTC
  claude_instructions: ~/.claude/CLAUDE.md
  bashrc: ~/.bashrc
  conda_root: ~/miniconda3
  default_conda_env: sandbox-env
""",
        encoding="utf-8",
    )
    config = load_host_config(path)
    assert config.profile.claude_instructions == Path(
        "/home/alice/.claude/CLAUDE.md"
    )
    assert config.profile.bashrc == Path("/home/alice/.bashrc")
    assert config.profile.conda_root == Path("/home/alice/miniconda3")
    assert config.profile.default_conda_env == "sandbox-env"
    assert config.profile.timezone == "Etc/UTC"


def test_timezone_must_be_an_installed_iana_name(tmp_path: Path) -> None:
    path = _config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8")
        + """
profile:
  timezone: ../private-zone
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="IANA 时区"):
        load_host_config(path)


def test_default_environment_rejects_shell_syntax(tmp_path: Path) -> None:
    path = _config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8")
        + """
profile:
  default_conda_env: "sandbox-env; touch /tmp/unexpected"
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="default_conda_env"):
        load_host_config(path)


def test_config_init_uses_invoking_identity_and_existing_common_files(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home" / "alice"
    (home / ".config" / "git").mkdir(parents=True)
    (home / ".ssh").mkdir()
    ssh_config = home / ".ssh" / "config"
    ssh_config.write_text("Host fixture\n  HostName fixture.invalid\n", encoding="utf-8")
    ssh_config.chmod(0o600)
    (home / ".claude" / "skills").mkdir(parents=True)
    (home / ".claude" / "agents").mkdir()
    (home / ".agents" / "skills").mkdir(parents=True)
    (home / ".condarc").write_text("channels: [defaults]\n", encoding="utf-8")
    (home / ".bashrc").write_text("export EDITOR=vim\n", encoding="utf-8")
    account = SimpleNamespace(pw_name="alice", pw_uid=1000, pw_gid=1000, pw_dir=str(home))
    monkeypatch.setattr(
        "controlled_dev_machine.config.invoking_account", lambda: account
    )
    monkeypatch.setattr(
        "controlled_dev_machine.config._safe_profile_candidate",
        lambda path, _uid, _gid: path == home / ".bashrc",
    )

    output = tmp_path / "config" / "host.yaml"
    create_host_config(output)
    generated = output.read_text(encoding="utf-8")
    assert "expected_exit_cidr: null" in generated
    output.write_text(
        generated.replace("expected_exit_cidr: null", "expected_exit_cidr: 8.8.8.8/32"),
        encoding="utf-8",
    )
    config = load_host_config(output)

    assert output.stat().st_mode & 0o777 == 0o600
    assert config.target.name == "alice"
    assert config.target.home == home
    assert config.profile.bashrc == home / ".bashrc"
    assert config.profile.claude_instructions is None
    assert config.profile.timezone == "UTC"
    assert config.upstream.expected_exit_cidr == "8.8.8.8/32"
    mounts = {mount.host_path: mount.read_only for mount in config.mounts}
    assert mounts[home / ".config" / "git"] is False
    assert mounts[home / ".ssh"] is False
    assert home / ".ssh" / "config" not in mounts
    assert ssh_config.read_text(encoding="utf-8") == "Host fixture\n  HostName fixture.invalid\n"
    assert ssh_config.stat().st_mode & 0o777 == 0o600
    assert mounts[home / ".claude" / "skills"] is False
    assert mounts[home / ".claude" / "agents"] is False
    assert mounts[home / ".agents" / "skills"] is False
    assert mounts[home / ".codex"] is False
    assert mounts[home / ".condarc"] is False
    assert (home / ".codex").is_dir()

    with pytest.raises(ConfigError, match="拒绝覆盖"):
        create_host_config(output)


def test_http_upstream_exit_range_is_configurable(tmp_path: Path) -> None:
    path = _config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "upstream:\n  kind: unset",
            "upstream:\n  kind: http\n  host: 127.0.0.1\n  port: 26940\n"
            "  expected_exit_cidr: 8.8.8.8/32",
        ),
        encoding="utf-8",
    )
    config = load_host_config(path)
    assert config.upstream.expected_exit_cidr == "8.8.8.8/32"

    path.write_text(
        path.read_text(encoding="utf-8").replace("8.8.8.8/32", "127.0.0.1/32"),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="公网"):
        load_host_config(path)


def test_http_upstream_requires_an_explicit_exit_range(tmp_path: Path) -> None:
    path = _config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "upstream:\n  kind: unset",
            "upstream:\n  kind: http\n  host: 127.0.0.1\n  port: 26940",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="必须显式填写"):
        load_host_config(path)
