"""Offline unit checks for the rootless degraded gateway contract."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace


REPO = Path(__file__).parents[1]


def load_addon(monkeypatch, policy_path: Path):
    """Load the addon with a tiny mitmproxy stub; no daemon or network needed."""
    mitmproxy = ModuleType("mitmproxy")
    mitmproxy.ctx = SimpleNamespace(
        options=SimpleNamespace(connection_strategy="lazy", rawtcp=False, upstream_cert=False,
                                mode=["regular@8080"])
    )
    mitmproxy.http = SimpleNamespace()
    mitmproxy.tcp = SimpleNamespace()
    monkeypatch.setitem(sys.modules, "mitmproxy", mitmproxy)
    monkeypatch.setenv("CDM_DEGRADED_MODE", "1")
    monkeypatch.setenv("CDM_POLICY_PATH", str(policy_path))
    monkeypatch.setenv(
        "CDM_EXPECTED_POLICY_DIGEST",
        "raw:" + hashlib.sha256(policy_path.read_bytes()).hexdigest(),
    )
    monkeypatch.setenv("CDM_REVIEW_DIR", str(policy_path.parent / "review"))
    monkeypatch.setenv("CDM_CANARY_ADDRESS", "127.0.0.1")
    monkeypatch.setenv("CDM_DNS_LEASE_SOCKET", str(policy_path.parent / "lease.sock"))
    path = REPO / "gateway/mitmproxy/cdm_addon.py"
    spec = importlib.util.spec_from_file_location("degraded_addon_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, module.ControlledReviewAddon()


def flow(
    host: str,
    scheme: str = "http",
    port: int = 80,
    sni: str | None = None,
    peer: tuple[str, int] = ("172.31.0.4", 40000),
):
    return SimpleNamespace(
        request=SimpleNamespace(pretty_host=host, host=host, scheme=scheme, port=port),
        client_conn=SimpleNamespace(sni=sni, peername=peer),
        metadata={},
    )


def test_degraded_destination_matrix(monkeypatch):
    policy = REPO / "policies/strict/0001-bootstrap.yaml"
    addon_module, addon = load_addon(monkeypatch, policy)
    assert addon.degraded is True
    assert addon._verify_degraded_destination(flow("example.com"), "example.com") is None
    assert (
        addon._verify_degraded_destination(flow("1.1.1.1"), "1.1.1.1")
        == "degraded proxy requires a canonical hostname"
    )
    assert (
        addon._verify_degraded_destination(flow("example.com", port=22), "example.com")
        == "degraded proxy permits only ports 80 and 443"
    )
    assert (
        addon._verify_degraded_destination(
            flow("example.com", "https", 443, "other.example"), "example.com"
        )
        == "HTTPS request hostname does not match client SNI"
    )
    assert (
        addon._verify_degraded_destination(
            flow("example.com", "https", 443, "example.com"), "example.com"
        )
        is None
    )
    addon._load_verified_policy()
    assert addon_module.ControlledReviewAddon


def test_degraded_running_rejects_transparent_mode(monkeypatch):
    policy = REPO / "policies/strict/0001-bootstrap.yaml"
    mitmproxy_module, addon = load_addon(monkeypatch, policy)
    mitmproxy_module.ctx.options.mode = ["transparent"]
    try:
        addon.running()
    except RuntimeError as exc:
        assert "regular proxy mode" in str(exc)
    else:
        raise AssertionError("transparent mode must be rejected in degraded mode")
