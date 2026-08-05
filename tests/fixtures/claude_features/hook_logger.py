#!/usr/bin/env python3
"""Record only minimal Claude Code hook metadata for feature verification."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path


def main() -> int:
    payload = json.load(sys.stdin)
    cwd = Path(str(payload.get("cwd", "."))).resolve()
    log_path = cwd / ".claude" / "hook-events.jsonl"
    session_id = str(payload.get("session_id", ""))
    record = {
        "time": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "event": payload.get("hook_event_name"),
        "tool": payload.get("tool_name"),
        "session_sha256": hashlib.sha256(session_id.encode()).hexdigest(),
    }
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
