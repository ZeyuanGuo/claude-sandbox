from pathlib import Path


def test_target_image_pins_claude_and_codex_installers() -> None:
    dockerfile = (Path(__file__).parents[1] / "images/target/Dockerfile").read_text(
        encoding="utf-8"
    )

    assert "npm install --global @anthropic-ai/claude-code@2.1.220" in dockerfile
    assert "CODEX_VERSION=0.147.0" in dockerfile
    assert 'npm install --global "@openai/codex@${CODEX_VERSION}"' in dockerfile
