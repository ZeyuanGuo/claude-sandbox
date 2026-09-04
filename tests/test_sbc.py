from pathlib import Path


def test_sbc_wrapper_resolves_repository_and_defaults_to_shell() -> None:
    script = Path("bin/sbc").read_text(encoding="utf-8")

    assert "while [ -L \"$SCRIPT_PATH\" ]" in script
    assert 'if [ "$#" -eq 0 ]; then' in script
    assert "set -- shell" in script
    assert 'sbd) set -- doctor "$@"' in script
    assert 'sbr) set -- recover "$@"' in script
    assert 'sba) set -- audit restart "$@"' in script
    assert 'exec sudo "$REPO_ROOT/bin/sandboxctl" "$@"' in script
