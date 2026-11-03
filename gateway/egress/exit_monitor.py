"""Refresh a root-owned short lease from a direct check through the fixed parent."""
import argparse
import ipaddress
import http.client
import json
import os
import ssl
from pathlib import Path
import time


def observe(config):
    host = str(ipaddress.ip_address(config["parent_host"]))
    port = config["parent_port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid parent port")
    # Explicit TCP parent plus CONNECT cannot be bypassed by NO_PROXY.
    connection=http.client.HTTPSConnection(host,port,timeout=6,context=ssl.create_default_context())
    try:
        connection.set_tunnel('api.ipify.org',443)
        connection.request('GET','/?format=json',headers={'Host':'api.ipify.org'})
        response=connection.getresponse()
        if response.status!=200:
            raise ValueError('exit probe did not return HTTP 200')
        payload=response.read(4097)
    finally:
        connection.close()
    if len(payload) > 4096:
        raise ValueError("oversized exit response")
    return str(ipaddress.ip_address(json.loads(payload)["ip"]))


def refresh(config, *, probe=observe):
    path = Path(config["exit_lease"])
    record = {"schema_version": 1, "parent_host": config["parent_host"],
              "parent_port": config["parent_port"], "expected_exit": config["expected_exit"],
              "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
    try:
        record["observed_exit"] = probe(config)
        record["ok"] = record["observed_exit"] == config["expected_exit"]
    except Exception as error:
        record.update(ok=False, observed_exit=None, error=type(error).__name__)
    record["checked_monotonic"] = time.monotonic()
    record["expires_monotonic"] = record["checked_monotonic"] + 15
    path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    with temporary.open("w") as stream:
        json.dump(record, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o644)
    temporary.replace(path)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    ipaddress.ip_address(config["expected_exit"])
    while True:
        record = refresh(config)
        if args.once:
            print(json.dumps({"ok": record["ok"], "observed_exit": record["observed_exit"]}))
            return 0 if record["ok"] else 1
        time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
