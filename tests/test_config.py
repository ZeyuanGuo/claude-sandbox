from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

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
    generated_config = yaml.safe_load(generated)
    assert generated_config["upstream"]["port"] == 11450
    assert generated_config["storage"]["root"] == {
        "min_free_gib": 50,
        "min_free_percent": 5,
    }
    assert generated_config["storage"]["audit"] == {
        "min_free_gib": 200,
        "min_free_percent": 10,
    }
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
    assert mounts[home / ".ssh"] is True
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
            "upstream:\n  kind: http\n  host: 127.0.0.1\n  port: 11440\n"
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
            "upstream:\n  kind: http\n  host: 127.0.0.1\n  port: 11440",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="必须显式填写"):
        load_host_config(path)
