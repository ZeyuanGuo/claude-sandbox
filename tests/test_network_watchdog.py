from __future__ import annotations

import pytest

from controlled_dev_machine.network_watchdog import process_matches, render_refresh


def test_watchdog_refresh_is_an_atomic_set_replacement() -> None:
    script = render_refresh(
        {
            "sets": [
                {"name": "audit_tcp_ports", "kind": "port", "values": [80, 443]},
                {
                    "name": "audit_dns_addresses",
                    "kind": "ipv4",
                    "values": ["172.28.0.4"],
                },
            ]
        },
        5,
    )
    assert "flush set inet cdm_control audit_tcp_ports" in script
    assert "80 timeout 5s, 443 timeout 5s" in script
    assert "172.28.0.4 timeout 5s" in script


def test_watchdog_rejects_untrusted_set_input() -> None:
    with pytest.raises(ValueError):
        render_refresh(
            {"sets": [{"name": "bad; flush ruleset", "kind": "port", "values": [80]}]},
            5,
        )


def test_watchdog_rejects_stopped_or_replaced_probe(monkeypatch) -> None:
    expected = {
        "executable_path": "/usr/bin/tcpdump",
        "executable_device": 8,
        "executable_inode": 42,
    }
    monkeypatch.setattr(
        "controlled_dev_machine.network_watchdog._proc_state_and_starttime",
        lambda _pid: ("T", 42),
    )
    monkeypatch.setattr(
        "controlled_dev_machine.network_watchdog.process_identity",
        lambda _pid: expected,
    )
    assert not process_matches(100, 42, expected)

    monkeypatch.setattr(
        "controlled_dev_machine.network_watchdog._proc_state_and_starttime",
        lambda _pid: ("S", 42),
    )
    assert not process_matches(100, 42, {**expected, "executable_inode": 99})
    assert process_matches(100, 42, expected)
    assert process_matches(100, 42, expected, allow_stopped=True)
