from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


def test_hook_logger_hashes_session_id(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    session_id = "fixture-session-id"
    script = (
        Path(__file__).parent
        / "fixtures"
        / "claude_features"
        / "hook_logger.py"
    )

    subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(
            {
                "cwd": str(tmp_path),
                "hook_event_name": "SessionStart",
                "session_id": session_id,
            }
        ),
        check=True,
        text=True,
    )

    raw_log = (tmp_path / ".claude" / "hook-events.jsonl").read_text()
    record = json.loads(raw_log)
    assert session_id not in raw_log
    assert "session_id" not in record
    assert record["session_sha256"] == hashlib.sha256(session_id.encode()).hexdigest()
