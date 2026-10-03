"""Topology verifier for generated rootless degraded Compose files.

This is intentionally a structural check.  It never starts Compose and does
not contact an upstream.  The expected topology is four services: a target,
an audited DNS gateway, the regular proxy gateway, and the fixed-parent
egress relay.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml


def verify(path: Path, upstream: bool) -> None:
    document = yaml.safe_load(path.read_text())
    services = document["services"]
    assert set(services) == {"dns", "gateway", "egress", "target"}
    networks = document["networks"]
    assert networks["target_net"]["internal"] is True
    assert networks["target_net"].get("enable_ipv6") is False
    assert networks["upstream_net"]["internal"] is True
    assert networks["upstream_net"].get("enable_ipv6") is False

    target = services["target"]
    assert target["user"] == "0:0"
    assert set(target["networks"]) == {"target_net"}
    assert "ports" not in target
    assert target["command"] == ["sleep", "infinity"]
    assert target["hostname"] == "devbox"
    assert target["working_dir"] == "/home/gzy"
    assert target["environment"]["TZ"] == "America/Los_Angeles"
    assert target["environment"]["LANG"] == "en_US.UTF-8"
    assert target["environment"]["LC_ALL"] == "en_US.UTF-8"
    assert target["environment"]["HTTP_PROXY"] == "http://172.31.0.3:8080"
    assert target["environment"]["HTTPS_PROXY"] == "http://172.31.0.3:8080"
    assert target["environment"]["NO_PROXY"] == "127.0.0.1,localhost"

    dns = services["dns"]
    assert dns["networks"] == {
        "target_net": {"ipv4_address": "172.31.0.2"},
        "upstream_net": {"ipv4_address": "172.31.1.2"},
    }
    assert dns["dns"] == ["127.0.0.1"]
    dns_command = dns["command"]
    assert dns_command[:2] == ["python3", "/opt/cdm/dns_gateway.py"]
    assert dns_command[dns_command.index("--proxy-host") + 1] == "172.31.1.10"
    assert dns_command[dns_command.index("--proxy-port") + 1] == "8080"
    assert dns_command[dns_command.index("--lease-socket") + 1] == "/run/cdm-dns/lease.sock"
    # An external parent must never be enabled together with the permissive
    # public-domain fallback.  Offline/no-parent fixtures may retain it since
    # they cannot send any packet outside the internal networks.
    if upstream:
        assert "--allow-public-domains" not in dns_command

    gateway = services["gateway"]
    assert set(gateway["networks"]) == {"target_net", "upstream_net"}
    assert "ports" not in services["gateway"]
    assert gateway["networks"]["target_net"] == {"ipv4_address": "172.31.0.3"}
    assert gateway["networks"]["upstream_net"] == {"ipv4_address": "172.31.1.3"}
    assert gateway["dns"] == ["172.31.0.2"]
    assert gateway["command"][0:2] == ["--mode", "regular@8080"]
    assert "mitmdump" not in gateway["command"]
    assert gateway["environment"]["CDM_DEGRADED_MODE"] == "1"
    assert gateway["environment"]["CDM_DNS_LEASE_SOCKET"] == "/run/cdm-dns/lease.sock"
    assert gateway["environment"]["CDM_UPSTREAM_HOST"] == "172.31.1.10"
    assert gateway["environment"]["CDM_UPSTREAM_PORT"] == "8080"

    relay = services["egress"]
    assert relay["entrypoint"] == []
    assert relay["command"] == ["python3", "-m", "controlled_dev_machine.degraded_egress"]
    assert relay["dns"] == ["127.0.0.1"]
    assert relay["networks"]["upstream_net"] == {"ipv4_address": "172.31.1.10"}
    assert "ports" not in relay
    relay_environment = relay["environment"]
    assert relay_environment["CDM_RELAY_AUDIT"] == "/audit/egress/events.jsonl"

    if upstream:
        assert "egress_net" in relay["networks"]
        assert relay["networks"]["egress_net"] == {}
        assert relay_environment["CDM_RELAY_UPSTREAM_HOST"]
        assert relay_environment["CDM_RELAY_UPSTREAM_PORT"]
        assert networks["egress_net"]["internal"] is False
        assert networks["egress_net"].get("enable_ipv6") is False
    else:
        assert "egress_net" not in relay["networks"]
        assert relay_environment["CDM_RELAY_UPSTREAM_HOST"] == ""
        assert relay_environment["CDM_RELAY_UPSTREAM_PORT"] == ""
        assert "egress_net" not in networks
    print(f"compose topology PASS upstream={upstream}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("compose", type=Path)
    parser.add_argument("--upstream", action="store_true")
    args = parser.parse_args()
    verify(args.compose, args.upstream)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
