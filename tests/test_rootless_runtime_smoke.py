from pathlib import Path

from rootless_runtime_smoke import _target_script


def test_runtime_smoke_covers_daily_files_python_and_offline_tools() -> None:
    script = _target_script(require_ml=True, require_gpu=False)

    for marker in (
        "mkdir -p \"$tmp/nested/.hidden\"",
        "ln -s nested/.hidden/value \"$tmp/value-link\"",
        "chmod 600",
        "command -v python3",
        "printf 'smoke\\n' > \"$claude_probe\"",
        "project_probe=/home/gzy/newdfm/.cdm-rootless-smoke-$$",
        "python-training=pass",
        "git --version",
        "node --version",
        "claude --version",
        "claude --help",
        "codex --version",
        "codex --help",
        "/home/gzy/miniconda3/envs/pthgnn/bin/python",
        "torch.nn.Linear",
        "cuda-training=pass",
        "/proc/net/route",
    ):
        assert marker in script


def test_runtime_smoke_never_attempts_auth_or_unreviewed_network() -> None:
    script = _target_script(require_ml=False, require_gpu=False)
    lowered = script.lower()
    for forbidden in ("claude login", "claude auth", "codex login", "curl ",
                      "wget ", "requests.", "socket.", "http://", "https://"):
        assert forbidden not in lowered


def test_runtime_smoke_requires_the_stable_persistent_paths() -> None:
    script = _target_script(require_ml=True, require_gpu=True)
    assert '"${HOME}" = /home/gzy' in script
    assert '"${CLAUDE_CONFIG_DIR}" = /home/gzy/.claude' in script
    assert '[ "required" = required ]' in script
    assert '[ "$cuda" != true ]' in script
