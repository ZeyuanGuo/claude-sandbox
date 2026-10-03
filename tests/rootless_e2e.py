"""Credential-free rootless acceptance using an entirely internal fake parent."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

import yaml

from controlled_dev_machine.degraded_topology import build_compose


def _remap_network(document: dict, prefix: str) -> None:
    """Give the fixture private networks a collision-free address range."""
    if not prefix or prefix.count(".") != 1:
        raise ValueError("CDM_ROOTLESS_E2E_NETWORK_PREFIX must look like 172.32")
    old = "172.31."
    new = prefix.rstrip(".") + "."

    def replace(value):
        if isinstance(value, str):
            return value.replace(old, new)
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        return value

    original = dict(document)
    document.clear()
    document.update(replace(original))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--certs", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    stage = args.state.resolve()
    certs = args.certs.resolve()
    stage.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in ("runtime/home", "runtime/miniconda3", "audit/review", "audit/plaintext",
                 "audit/dns", "audit/egress", "dns-control", "proxy-ca", "trust"):
        (stage / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    policy = stage / "canary-policy.yaml"
    policy.write_text('''schema_version: 1
policy_id: local-canary
revision: 1
mode: strict
created_at: "2026-10-04T00:00:00Z"
parent_digest:
web_default: review
rules:
  - id: offline-fixture
    priority: 1
    action: allow
    purpose: credential-free internal acceptance
    domain_kind: exact
    domain: fixture.example
    schemes: [http, https]
    ports: [80, 443]
    methods: [GET]
    path_prefixes: [/canary]
    content_types: []
    body_max_bytes: 0
    tls_identity_required: true
    plaintext_required: true
    evidence: internal-fixture
''')
    digest = "raw:" + hashlib.sha256(policy.read_bytes()).hexdigest()
    document = build_compose(root=root, runtime=stage / "runtime", state=stage,
                             target_image="cdm-degraded-target:5090-rootfs",
                             gateway_image="cdm-degraded-gateway:5090", policy=policy,
                             policy_digest=digest, upstream_host="172.31.1.11",
                             upstream_port="18081", dns_suffixes=("fixture.example",))
    # The production degraded stack may stay up while this credential-free
    # fixture runs.  Use a separate internal subnet to avoid Docker pool
    # overlap; no host or public network is added.
    _remap_network(document, os.environ.get("CDM_ROOTLESS_E2E_NETWORK_PREFIX", "172.32"))
    # The fixture has no external bridge, DNS, or host ports and an empty Home.
    document["networks"].pop("egress_net")
    document["services"]["egress"]["networks"].pop("egress_net")
    document["services"]["dns"]["volumes"].append(
        {"type": "bind", "source": str(certs), "target": "/fixture", "read_only": True})
    document["services"]["dns"]["environment"] = {"SSL_CERT_FILE": "/fixture/ca.pem"}
    document["services"]["gateway"]["volumes"].append(
        {"type": "bind", "source": str(certs), "target": "/fixture", "read_only": True})
    document["services"]["gateway"]["command"] += ["--set", "ssl_verify_upstream_trusted_ca=/fixture/ca.pem"]
    document["services"]["fixture"] = {
        "image": "cdm-degraded-gateway:5090", "entrypoint": [], "user": "0:0",
        "command": ["python3", "/test/rootless_fixture.py"],
        "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
        "networks": {"upstream_net": {"ipv4_address": "172.31.1.11"}},
        "volumes": [{"type": "bind", "source": str(certs), "target": "/fixture"},
                    {"type": "bind", "source": str(root / "tests/rootless_fixture.py"),
                     "target": "/test/rootless_fixture.py", "read_only": True}],
    }
    (stage / "trust/ca-certificates.crt").touch()
    config = stage / "compose.yaml"
    config.write_text(yaml.safe_dump(document, sort_keys=False))
    command = ["docker", "compose", "-p", "cdm-rootless-e2e", "-f", str(config)]

    def call(*argv, check=True):
        result = subprocess.run(command + list(argv), text=True, capture_output=True, check=check)
        if result.returncode:
            print(result.stdout, result.stderr)
        return result

    report = {"public_network": False, "user_credentials": False, "checks": []}
    try:
        call("config", "--quiet")
        call("up", "-d", "fixture", "egress", "dns", "gateway")
        for _ in range(20):
            if call("exec", "-T", "gateway", "python3", "-m", "controlled_dev_machine.gateway_health", check=False).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("real addon health gate failed")
        ca = call("exec", "-T", "gateway", "cat", "/ca/mitmproxy-ca-cert.pem").stdout
        (stage / "trust/ca-certificates.crt").write_text(ca)
        call("up", "-d", "target")
        for scheme in ("http", "https"):
            response = call("exec", "-T", "target", "curl", "--max-time", "20", "--fail",
                            "--silent", "--show-error", scheme + "://fixture.example/canary").stdout
            assert response == "rootless-canary-ok\n", response
            report["checks"].append(scheme + "-positive")
        for url, reason in (("http://1.1.1.1/", "invalid-destination"),
                            ("https://fixture.example:8443/", "invalid-connect")):
            result = call("exec", "-T", "target", "curl", "--max-time", "5", "-sS", "-D", "-", url, check=False)
            assert "x-cdm-block-reason: " + reason in result.stdout, result.stdout
            report["checks"].append(reason)
        target = call("exec", "-T", "target", "cat", "/proc/net/route").stdout
        assert "00000000" not in [line.split()[1] for line in target.splitlines()[1:]], target
        records = [json.loads(line) for line in (certs / "events.jsonl").read_text().splitlines()]
        authorities = [item["target"] for item in records if item["kind"] == "connect"]
        assert "1.1.1.1:443" in authorities
        assert "9.9.9.9:80" in authorities and "9.9.9.9:443" in authorities
        assert all("fixture.example" not in value for value in authorities)
        assert all(item.get("host") == "fixture.example" for item in records if item["kind"] == "origin")
        report["checks"] += ["dns-validated", "parent-ip-pinning", "original-host-preserved", "target-no-default-route"]
        bypass = call("exec", "-T", "target", "curl", "--noproxy", "*", "--max-time", "3",
                      "--resolve", "fixture.example:443:9.9.9.9", "https://fixture.example/canary", check=False)
        assert bypass.returncode != 0
        report["checks"].append("proxy-env-bypass-blocked")
        raw_probe = call("exec", "-T", "target", "python3", "-c",
                         "import socket; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)", check=False)
        assert raw_probe.returncode != 0 and "PermissionError" in raw_probe.stderr
        report["checks"].append("raw-packet-spoofing-blocked")
        for address, port in (("172.31.1.10", 8080), ("1.1.1.1", 53)):
            blocked = call("exec", "-T", "target", "python3", "-c",
                           f"import socket;s=socket.socket();s.settimeout(2);assert s.connect_ex(({address!r},{port})) != 0")
            assert blocked.returncode == 0
        report["checks"].append("relay-and-external-dns-unreachable-from-target")
        original_policy = policy.read_text()
        policy.write_text(original_policy + "\n# digest fault injection\n")
        bad_policy = call("exec", "-T", "target", "curl", "--max-time", "5", "-sS", "-D", "-",
                          "http://fixture.example/canary")
        assert "x-cdm-block-reason: policy-unavailable" in bad_policy.stdout
        policy.write_text(original_policy)
        report["checks"].append("policy-drift-fail-closed")
        call("stop", "egress")
        failed_relay = call("exec", "-T", "target", "curl", "--max-time", "4", "--fail",
                            "http://fixture.example/canary", check=False)
        assert failed_relay.returncode != 0
        report["checks"].append("relay-down-fail-closed")
        call("start", "egress")
        call("stop", "gateway")
        failed = call("exec", "-T", "target", "curl", "--max-time", "3", "--fail", "http://fixture.example/canary", check=False)
        assert failed.returncode != 0
        report["checks"].append("gateway-down-fail-closed")
        report["passed"] = True
        print(json.dumps(report, indent=2))
        return 0
    finally:
        (stage / "report.json").write_text(json.dumps(report, indent=2))
        call("down", "--remove-orphans", check=False)


if __name__ == "__main__":
    raise SystemExit(main())
