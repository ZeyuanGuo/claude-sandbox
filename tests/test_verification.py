from types import SimpleNamespace

import pytest

import controlled_dev_machine.verification as verification
from controlled_dev_machine.errors import DeploymentError


def test_live_audit_accepts_the_supervised_service_relay() -> None:
    kinds = (
        "target-pcap",
        "gateway-pcap",
        "dns-pcap",
        "target-connect-ebpf",
        "service-relay",
        "network-watchdog",
    )
    audit = {
        "active": True,
        "processes": [{"kind": kind, "alive": True} for kind in kinds],
    }

    verification._require_live_audit(audit)

    audit["processes"].append({"kind": "unexpected-probe", "alive": True})
    with pytest.raises(DeploymentError, match="全部抓包"):
        verification._require_live_audit(audit)


def test_strict_public_web_probe_approves_its_own_review(monkeypatch) -> None:
    config = SimpleNamespace(
        upstream=SimpleNamespace(
            kind="http",
            port=11440,
            expected_exit_cidr="204.1.123.50/32",
        )
    )
    audit = {"observed_upstream_ip": "204.1.123.50"}
    process = SimpleNamespace(returncode=None, poll=lambda: None)
    record = SimpleNamespace(request_id="review-id")
    final = SimpleNamespace(state="completed")
    approved: list[tuple[str, int, str]] = []
    capture_options: list[dict[str, object]] = []

    class Store:
        def approve_once(self, request_id, *, ttl_seconds, reason):
            approved.append((request_id, ttl_seconds, reason))

        def get(self, request_id):
            assert request_id == record.request_id
            return final

    def start_capture(*_args, **kwargs):
        capture_options.append(kwargs)
        return object()

    monkeypatch.setattr(verification, "_start_gateway_capture", start_capture)
    monkeypatch.setattr(verification, "compose_exec_async", lambda *_args, **_kw: process)
    monkeypatch.setattr(verification, "_wait_pending", lambda _store, _path, _timeout: record)
    def communicate(_process, _timeout):
        process.returncode = 0
        return "204.1.123.50\n", ""

    monkeypatch.setattr(verification, "_communicate", communicate)
    monkeypatch.setattr(
        verification,
        "_finish_gateway_capture",
        lambda *_args, **_kwargs: {"packets": 1},
    )

    result = verification._run_public_web_via_parent(
        config,
        audit,
        Store(),
        timeout_seconds=15,
        require_review=True,
    )

    assert result["returned_ip"] == "204.1.123.50"
    assert approved == [("review-id", 30, "封闭门禁公网出口回归")]
    assert final.state == "completed"
    assert capture_options[0].get("direction") is None
    assert capture_options[0].get("packet_limit") == 1
