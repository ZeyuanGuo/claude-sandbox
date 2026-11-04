"""Configuration-driven exact-exit verification; any failed probe revokes access."""
from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import ipaddress
import json
import math
import os
from pathlib import Path
import subprocess
import time
import urllib.parse
import uuid


def validate_exit_config(config: dict) -> dict:
    result = dict(config)
    expected = result.get("expected_exit")
    if not isinstance(expected, str) or str(ipaddress.IPv4Address(expected)) != expected:
        raise ValueError("expected_exit must be one canonical IPv4 address, not a range")
    parent = urllib.parse.urlsplit(result.get("parent_proxy", ""))
    if parent.scheme != "http" or parent.username or parent.password or not parent.hostname or not parent.port:
        raise ValueError("parent_proxy must be an explicit credential-free HTTP parent")
    if parent.path not in ("", "/") or parent.query or parent.fragment:
        raise ValueError("parent_proxy must not contain a path, query or fragment")
    ipaddress.IPv4Address(parent.hostname)
    endpoints = result.get("probe_urls")
    if not isinstance(endpoints, list) or not endpoints or len(endpoints) > 4:
        raise ValueError("one to four explicit HTTPS exit probes are required")
    for endpoint in endpoints:
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("exit probes must be credential-free HTTPS URLs")
    for key, default, upper in (("lease_seconds", 15.0, 15.0), ("probe_timeout", 8.0, 10.0),
                                ("interval_seconds", 2.0, 5.0)):
        value = result.get(key, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= upper:
            raise ValueError(f"invalid {key}")
        result[key] = float(value)
    result["parent_host"], result["parent_port"] = parent.hostname, parent.port
    return result


def probe(config: dict, endpoint: str) -> dict:
    started = time.monotonic()
    result = subprocess.run(
        ["curl", "-4", "--fail", "--silent", "--show-error", "--proxy", config["parent_proxy"],
         "--noproxy", "", "--connect-timeout", "4", "--max-time", str(config["probe_timeout"]), endpoint],
        capture_output=True, text=True, timeout=config["probe_timeout"] + 2,
    )
    if result.returncode:
        return {"endpoint": endpoint, "ok": False, "error": f"curl-exit-{result.returncode}"}
    try:
        text = result.stdout.strip()
        if len(text) > 4096:
            raise ValueError("oversized reply")
        if text.startswith("{"):
            text = json.loads(text)["ip"]
        observed = str(ipaddress.IPv4Address(text))
    except (ValueError, KeyError, TypeError):
        return {"endpoint": endpoint, "ok": False, "error": "invalid-ipv4-reply"}
    return {"endpoint": endpoint, "ok": observed == config["expected_exit"], "observed": observed,
            "seconds": round(time.monotonic() - started, 3)}


def atomic_json(path: Path, value: dict, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), mode)
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def refresh(config: dict, *, probe_fn=probe, publish=None, boot_id: str | None = None) -> dict:
    config = validate_exit_config(config)
    if boot_id is None:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    results = []
    failed = False
    round_id = uuid.uuid4().hex

    def record(ok: bool) -> dict:
        now = time.monotonic()
        return {"schema_version": 1, "ok": ok, "parent_host": config["parent_host"],
                "parent_port": config["parent_port"], "expected_exit": config["expected_exit"],
                "observed_exit": config["expected_exit"] if ok else None, "boot_id": boot_id,
                "checked_monotonic": now, "expires_monotonic": now + config["lease_seconds"],
                "checked_at": datetime.now(timezone.utc).isoformat(), "round_id": round_id,
                "reason": "all-probes-matched" if ok else "probe-failed", "probes": list(results)}

    if config.get("readiness_path"):
        try:
            ready = json.loads(Path(config["readiness_path"]).read_text())
            if ready.get("ok") is not True or ready.get("config_sha256") != config.get("required_config_sha256"):
                raise ValueError("runtime not ready")
        except (OSError, ValueError, TypeError):
            result = record(False)
            result["reason"] = "runtime-not-ready"
            if publish is not None:
                publish(result)
            return result
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(config["probe_urls"])) as pool:
        pending = {pool.submit(probe_fn, config, url): url for url in config["probe_urls"]}
        for future in concurrent.futures.as_completed(pending):
            try:
                result = future.result()
            except Exception as error:
                result = {"endpoint": pending[future], "ok": False, "error": type(error).__name__}
            valid = result.get("ok") is True and result.get("observed") == config["expected_exit"]
            results.append(result)
            if not valid:
                failed = True
                # Invalidate as soon as a failure completes, before waiting for another probe.
                if publish is not None:
                    publish(record(False))
    final = record(not failed and len(results) == len(config["probe_urls"]))
    if publish is not None:
        publish(final)
    return final


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    config = validate_exit_config(json.loads(args.config.read_text()))
    lease = Path(config["exit_lease"])
    while True:
        try:
            value = refresh(config, publish=lambda record: atomic_json(lease, record))
        except Exception:
            lease.unlink(missing_ok=True)
            raise
        print(json.dumps({"ok": value["ok"], "reason": value["reason"], "expected_exit": value["expected_exit"]}), flush=True)
        if args.once:
            return 0 if value["ok"] else 1
        time.sleep(config["interval_seconds"])


if __name__ == "__main__":
    raise SystemExit(main())
