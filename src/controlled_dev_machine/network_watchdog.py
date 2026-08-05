from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

_SET_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")


def _proc_state_and_starttime(pid: int) -> tuple[str, int]:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = raw.rsplit(") ", 1)[1].split()
    return fields[0], int(fields[19])


def process_identity(pid: int) -> dict[str, object]:
    executable = Path(f"/proc/{pid}/exe")
    link = os.readlink(executable)
    metadata = executable.stat()
    return {
        "executable_path": link,
        "executable_device": metadata.st_dev,
        "executable_inode": metadata.st_ino,
    }


def process_matches(
    pid: int,
    starttime: int,
    identity: object,
    *,
    allow_stopped: bool = False,
) -> bool:
    try:
        state, observed_starttime = _proc_state_and_starttime(pid)
        if not allow_stopped and state in {"T", "t", "X", "x", "Z"}:
            return False
        return observed_starttime == starttime and process_identity(pid) == identity
    except (OSError, IndexError, ValueError):
        return False


def _element(value: object, kind: str) -> str:
    if kind == "port":
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
            raise ValueError("watchdog port value is invalid")
        return str(value)
    if kind == "ipv4":
        if not isinstance(value, str):
            raise ValueError("watchdog IPv4 value is invalid")
        parsed = ipaddress.ip_address(value)
        if not isinstance(parsed, ipaddress.IPv4Address):
            raise ValueError("watchdog address must be IPv4")
        return str(parsed)
    raise ValueError("watchdog set kind is invalid")


def render_refresh(namespace: dict[str, object], timeout_seconds: int) -> str:
    sets = namespace.get("sets")
    if not isinstance(sets, list) or not sets:
        raise ValueError("watchdog namespace has no sets")
    commands: list[str] = []
    for item in sets:
        if not isinstance(item, dict):
            raise ValueError("watchdog set entry is invalid")
        name = item.get("name")
        kind = item.get("kind")
        values = item.get("values")
        if not isinstance(name, str) or _SET_NAME.fullmatch(name) is None:
            raise ValueError("watchdog set name is invalid")
        if not isinstance(kind, str) or not isinstance(values, list) or not values:
            raise ValueError("watchdog set fields are invalid")
        elements = ", ".join(
            f"{_element(value, kind)} timeout {timeout_seconds}s" for value in values
        )
        commands.append(f"flush set inet cdm_control {name}")
        commands.append(f"add element inet cdm_control {name} {{ {elements} }}")
    return "\n".join(commands) + "\n"


def _refresh(namespace: dict[str, object], timeout_seconds: int) -> None:
    pid = namespace.get("pid")
    starttime = namespace.get("starttime")
    if not isinstance(pid, int) or not isinstance(starttime, int):
        raise ValueError("watchdog namespace process fields are invalid")
    identity = namespace.get("identity")
    if not process_matches(pid, starttime, identity):
        raise RuntimeError(f"network namespace process is gone: {pid}")
    result = subprocess.run(
        [
            "nsenter",
            "--target",
            str(pid),
            "--net",
            "--",
            "nft",
            "-f",
            "-",
        ],
        input=render_refresh(namespace, timeout_seconds),
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"nft watchdog refresh failed: {detail[-1000:]}")


def run(config_path: Path, ready_path: Path) -> int:
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if config.get("schema_version") != 2:
            raise ValueError("watchdog schema version is invalid")
        probes = config.get("probes")
        namespaces = config.get("namespaces")
        if not isinstance(probes, list) or not probes:
            raise ValueError("watchdog has no audit probes")
        if not isinstance(namespaces, list) or len(namespaces) != 3:
            raise ValueError("watchdog must control three network namespaces")
        timeout_seconds = config.get("lease_seconds")
        if not isinstance(timeout_seconds, int) or not 3 <= timeout_seconds <= 30:
            raise ValueError("watchdog lease duration is invalid")
        interval = min(1.0, timeout_seconds / 3)
        ready_path.unlink(missing_ok=True)
        while True:
            for probe in probes:
                if not isinstance(probe, dict):
                    raise ValueError("watchdog probe entry is invalid")
                pid = probe.get("pid")
                starttime = probe.get("starttime")
                identity = probe.get("identity")
                if (
                    not isinstance(pid, int)
                    or not isinstance(starttime, int)
                    or not isinstance(identity, dict)
                ):
                    raise ValueError("watchdog probe fields are invalid")
                if not process_matches(pid, starttime, identity):
                    raise RuntimeError(f"audit probe is gone: {pid}")
            for namespace in namespaces:
                if not isinstance(namespace, dict):
                    raise ValueError("watchdog namespace entry is invalid")
                _refresh(namespace, timeout_seconds)
            if not ready_path.exists():
                descriptor = os.open(
                    ready_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                os.close(descriptor)
            time.sleep(interval)
    except Exception as exc:
        print(f"network watchdog stopped: {exc}", file=sys.stderr, flush=True)
        return 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.config, args.ready))


if __name__ == "__main__":
    main()
