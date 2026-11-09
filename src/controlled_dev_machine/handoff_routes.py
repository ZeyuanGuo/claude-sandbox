"""Reconcile registered SYN-only relay routes after namespace replacement.

The caller holds the sandbox lifecycle lock. Existing conntrack entries and
relay containers are retained; only missing, fully validated routes are added.
"""
from contextlib import ExitStack
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import uuid

from .exit_monitor import atomic_json


def expected_expression(original, destination):
    return [
        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": original}},
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8080}},
        {"match": {"op": "==", "left": {"&": [{"payload": {"protocol": "tcp", "field": "flags"}}, ["syn", "ack"]]}, "right": "syn"}},
        {"dnat": {"addr": destination, "port": 8080}},
    ]


def route_present(document, table, original, destination):
    entries = document["nftables"]
    tables = [e["table"] for e in entries if "table" in e and e["table"].get("name") == table]
    if not tables:
        return False
    chains = [e["chain"] for e in entries if "chain" in e and e["chain"].get("table") == table]
    rules = [e["rule"] for e in entries if "rule" in e and e["rule"].get("table") == table]
    if (len(tables) != 1 or tables[0].get("family") != "ip" or len(chains) != 1 or len(rules) != 1
            or any(chains[0].get(k) != v for k, v in {"name": "output", "type": "nat", "hook": "output", "prio": -110, "policy": "accept"}.items())
            or rules[0].get("chain") != "output"
            or rules[0].get("expr") != expected_expression(original, destination)):
        raise RuntimeError("registered handoff table has unexpected rules")
    return True


def reconcile_active_handoffs(app):
    registrations = []
    for path in sorted((app.private / "configs").glob("egress-capacity-hotfix-*.json")):
        data = json.loads(path.read_text())
        if data.get("applied") and re.fullmatch(r"cdm_egress_resume_[0-9]{8}", data.get("table", "")):
            registrations.append((path, data))
    if not registrations:
        return {"registered": False, "restored": []}
    path, data = registrations[-1]
    if not data.get("route_active") or data.get("stage") != "active":
        raise RuntimeError("latest handoff is incomplete; inspect its recorded state")
    table = data["table"]
    def inspect(name):
        value = json.loads(app.run(app.docker + ["inspect", name]).stdout)[0]
        if not value["State"]["Running"]:
            raise RuntimeError("registered handoff component is not running")
        return value
    current = {r: inspect(app.project + "-" + r + "-1") for r in ("gateway", "dns", "egress")}
    for info in current.values():
        if (info["Config"].get("Labels") or {}).get("com.docker.compose.project") != app.project:
            raise RuntimeError("handoff component ownership changed")
    pin = app.config["exit"]
    if any(data.get(k) != pin[k] for k in ("expected_exit", "parent_host", "parent_port")):
        raise RuntimeError("registered handoff exit or parent changed")
    network = next(n for n in current["egress"]["NetworkSettings"]["Networks"]
                   if n in current["gateway"]["NetworkSettings"]["Networks"])
    net = json.loads(app.run(app.docker + ["network", "inspect", network]).stdout)[0]
    if not net["Internal"] or net.get("EnableIPv6"):
        raise RuntimeError("handoff network must remain internal and IPv4-only")
    original = str(ipaddress.IPv4Address(current["egress"]["NetworkSettings"]["Networks"][network]["IPAddress"]))
    plans = []
    with ExitStack() as stack:
        for role, relay_role in (("gateway", "web"), ("dns", "dns")):
            peer = current[role]
            relay = inspect(data["new_containers"][relay_role]["id"])
            if relay["Image"] != data["image"]:
                raise RuntimeError("registered handoff relay image changed")
            destination = str(ipaddress.IPv4Address(relay["NetworkSettings"]["Networks"][network]["IPAddress"]))
            peer_ip = peer["NetworkSettings"]["Networks"][network]["IPAddress"]
            mount = next(m for m in relay["Mounts"] if m["Destination"] == "/run/cdm-relay.json")
            config_path = Path(mount["Source"])
            if config_path.parent != app.state / "config" or mount["RW"]:
                raise RuntimeError("registered relay configuration mount changed")
            config = json.loads(config_path.read_text())
            if (any(config.get(k) != pin[k] for k in ("expected_exit", "parent_host", "parent_port"))
                    or peer_ip not in config.get("trusted_gateway_ips" if role == "gateway" else "trusted_dns_ips", [])):
                raise RuntimeError("current namespace is not trusted by the registered relay")
            pid = peer["State"]["Pid"]
            uf, nf = [stack.enter_context(open(f"/proc/{pid}/ns/{kind}", "rb", buffering=0)).fileno() for kind in ("user", "net")]
            def nft(args, text=None, uf=uf, nf=nf):
                result = subprocess.run(["nsenter", f"--user=/proc/self/fd/{uf}", f"--net=/proc/self/fd/{nf}",
                                         "--", "/usr/sbin/nft", *args], input=text, text=True,
                                        capture_output=True, pass_fds=(uf, nf))
                if result.returncode:
                    raise RuntimeError("handoff namespace nft command failed: " + result.stderr[:250])
                return result.stdout
            before = nft(["-j", "list", "ruleset"])
            present = route_present(json.loads(before), table, original, destination)
            script = (f"add table ip {table}\n"
                      f"add chain ip {table} output {{ type nat hook output priority -110; policy accept; }}\n"
                      f"add rule ip {table} output ip daddr {original} tcp dport 8080 tcp flags & (syn | ack) == syn dnat to {destination}:8080\n")
            if not present:
                nft(["-c", "-f", "-"], script)
            plans.append((role, peer, nft, before, script, present, destination))
        missing = [p for p in plans if not p[5]]
        active = {r: {"id": peer["Id"], "pid": peer["State"]["Pid"], "destination": dest}
                  for r, peer, _, _, _, _, dest in plans}
        if missing:
            backup = app.private / "backups" / ("handoff-reconcile-" + uuid.uuid4().hex)
            backup.mkdir(mode=0o700, parents=True)
            atomic_json(backup / "registration.json", data)
            for role, _, _, before, _, _, _ in plans:
                atomic_json(backup / (role + "-before.json"), json.loads(before))
        applied = []
        try:
            for role, peer, nft, _, script, present, dest in plans:
                fresh = inspect(peer["Id"])
                if fresh["State"]["Pid"] != peer["State"]["Pid"]:
                    raise RuntimeError("handoff namespace changed during reconciliation")
                if not present:
                    nft(["-f", "-"], script)
                    applied.append((role, nft))
                if not route_present(json.loads(nft(["-j", "list", "ruleset"])), table, original, dest):
                    raise RuntimeError("handoff route validation failed")
            if missing or data.get("active_namespaces") != active:
                data["active_namespaces"] = active
                data.setdefault("reconciliations", []).append({"at": datetime.now(timezone.utc).isoformat(),
                    "restored": [r for r, _ in applied], "namespaces": active,
                    "backup": str(backup) if missing else None})
                atomic_json(path, data)
        except Exception:
            for _, nft in reversed(applied):
                nft(["delete", "table", "ip", table])
            raise
    return {"registered": True, "restored": [r for r, _ in applied], "namespaces": active}
