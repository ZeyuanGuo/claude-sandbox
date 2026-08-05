from __future__ import annotations

import asyncio
import importlib.util
import sys
import threading
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


def _load_addon(monkeypatch):
    mitmproxy = ModuleType("mitmproxy")
    mitmproxy.ctx = SimpleNamespace()
    mitmproxy.http = SimpleNamespace()
    mitmproxy.tcp = SimpleNamespace()
    monkeypatch.setitem(sys.modules, "mitmproxy", mitmproxy)
    monkeypatch.setenv("CDM_POLICY_PATH", "/tmp/policy.yaml")
    monkeypatch.setenv("CDM_EXPECTED_POLICY_DIGEST", "a" * 64)
    monkeypatch.setenv("CDM_REVIEW_DIR", "/tmp/review")
    monkeypatch.setenv("CDM_CANARY_ADDRESS", "172.28.0.19")
    monkeypatch.setenv("CDM_DNS_LEASE_SOCKET", "/tmp/lease.sock")

    path = Path(__file__).parents[1] / "gateway/mitmproxy/cdm_addon.py"
    spec = importlib.util.spec_from_file_location("cdm_addon_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ControlledReviewAddon()


def _flow(
    client,
    address: str = "93.184.216.34",
    *,
    host: str = "api.example.com",
    scheme: str = "https",
    port: int = 443,
):
    request = SimpleNamespace(
        scheme=scheme,
        port=port,
        pretty_host=host,
    )
    server = SimpleNamespace(address=(address, port))
    return SimpleNamespace(
        request=request,
        client_conn=client,
        server_conn=server,
        metadata={},
    )


def _verify(addon, flow, host: str):
    return asyncio.run(addon._verify_original_destination(flow, host))


def test_addon_reuses_client_binding_after_upstream_reconnect_and_ttl_expiry(monkeypatch) -> None:
    addon = _load_addon(monkeypatch)

    class Client:
        sni = "api.example.com"

    client = Client()
    lookups = 0

    def lease_lookup(_hostname: str, _address: str) -> str | None:
        nonlocal lookups
        lookups += 1
        return "a" * 32 if lookups == 1 else None

    monkeypatch.setattr(addon, "_dns_lease", lease_lookup)
    first = _flow(client)
    assert _verify(addon, first, "api.example.com") is None

    second = _flow(client)
    assert _verify(addon, second, "api.example.com") is None
    assert lookups == 1
    assert second.metadata["cdm_dns_lease_id"] == "a" * 32


def test_addon_rejects_new_destination_on_existing_client_connection(monkeypatch) -> None:
    addon = _load_addon(monkeypatch)

    class Client:
        sni = "api.example.com"

    client = Client()
    monkeypatch.setattr(addon, "_dns_lease", lambda _hostname, _address: "a" * 32)

    assert _verify(addon, _flow(client), "api.example.com") is None
    changed = _flow(client, address="1.1.1.1")
    assert (
        _verify(addon, changed, "api.example.com")
        == "transparent destination changed on an existing client connection"
    )


def test_addon_rechecks_dns_for_a_new_host_on_same_http_connection(monkeypatch) -> None:
    addon = _load_addon(monkeypatch)

    class Client:
        sni = None

    client = Client()
    lookups = 0

    def lease_lookup(_hostname: str, _address: str) -> str | None:
        nonlocal lookups
        lookups += 1
        return "a" * 32 if lookups == 1 else None

    monkeypatch.setattr(addon, "_dns_lease", lease_lookup)
    assert _verify(
        addon, _flow(client, scheme="http", port=80), "api.example.com"
    ) is None
    assert (
        _verify(
            addon,
            _flow(client, scheme="http", port=80, host="other.example.com"),
            "other.example.com",
        )
        == "transparent destination has no matching DNS lease"
    )
    assert lookups == 2


def test_addon_shares_concurrent_lease_lookup_for_one_connection(monkeypatch) -> None:
    addon = _load_addon(monkeypatch)

    class Client:
        sni = "api.example.com"

    client = Client()
    lookups = 0

    def lease_lookup(_hostname: str, _address: str) -> str | None:
        nonlocal lookups
        lookups += 1
        return "a" * 32

    monkeypatch.setattr(addon, "_dns_lease", lease_lookup)

    async def run_both():
        return await asyncio.gather(
            addon._verify_original_destination(_flow(client), "api.example.com"),
            addon._verify_original_destination(_flow(client), "api.example.com"),
        )

    assert asyncio.run(run_both()) == [None, None]
    assert lookups == 1


def test_addon_rejects_concurrent_new_destination_on_one_connection(monkeypatch) -> None:
    addon = _load_addon(monkeypatch)

    class Client:
        sni = None

    client = Client()
    barrier = threading.Barrier(2)

    def lease_lookup(_hostname: str, _address: str) -> str | None:
        barrier.wait(timeout=2)
        return "a" * 32

    monkeypatch.setattr(addon, "_dns_lease", lease_lookup)

    async def run_both():
        first = asyncio.create_task(
            addon._verify_original_destination(
                _flow(client, address="93.184.216.34", scheme="http", port=80),
                "api.example.com",
            )
        )
        await asyncio.sleep(0)
        second = asyncio.create_task(
            addon._verify_original_destination(
                _flow(client, address="1.1.1.1", scheme="http", port=80),
                "other.example.com",
            )
        )
        return await asyncio.gather(first, second)

    results = asyncio.run(run_both())
    assert sorted(results, key=lambda value: value is not None) == [
        None,
        "transparent destination changed on an existing client connection",
    ]


def test_addon_retries_a_transient_lease_socket_failure(monkeypatch) -> None:
    addon = _load_addon(monkeypatch)
    attempts = 0
    lease_id = "a" * 32

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def settimeout(self, _timeout):
            return None

        def connect(self, _path):
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise BlockingIOError("lease socket queue busy")

        def sendall(self, _request):
            return None

        def recv(self, _size):
            return (
                '{"allowed":true,"lease_id":"' + lease_id + '"}\n'
            ).encode("ascii")

    socket_module = addon._dns_lease.__globals__["socket"]
    monkeypatch.setattr(socket_module, "socket", lambda *_args: Connection())

    assert addon._dns_lease("api.example.com", "93.184.216.34") == lease_id
    assert attempts == 3


def test_addon_classifies_a_malformed_lease_response_as_service_failure(monkeypatch) -> None:
    addon = _load_addon(monkeypatch)
    attempts = 0

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def settimeout(self, _timeout):
            return None

        def connect(self, _path):
            nonlocal attempts
            attempts += 1

        def sendall(self, _request):
            return None

        def recv(self, _size):
            return b"[]\n"

    socket_module = addon._dns_lease.__globals__["socket"]
    unavailable = addon._dns_lease.__globals__["LeaseServiceUnavailable"]
    monkeypatch.setattr(socket_module, "socket", lambda *_args: Connection())

    with pytest.raises(unavailable, match="root is not an object"):
        addon._dns_lease("api.example.com", "93.184.216.34")
    assert attempts == 3


def test_health_success_does_not_clear_a_sticky_audit_fault(monkeypatch) -> None:
    addon = _load_addon(monkeypatch)
    addon.audit_fault = "review outcome could not be recorded"
    monkeypatch.setattr(
        addon, "_verified_policy_or_block", lambda _flow: SimpleNamespace(digest=lambda: "a" * 64)
    )
    addon._request_checked.__globals__["ctx"].log = SimpleNamespace(error=lambda *_args: None)
    monkeypatch.setitem(
        addon._request_checked.__globals__,
        "_blocked",
        lambda reason, detail: SimpleNamespace(reason=reason, detail=detail),
    )

    class Headers:
        def get(self, name, default=None):
            return {
                "host": "health.cdm.invalid",
                "connection": "",
            }.get(name, default)

        def __contains__(self, _name):
            return False

    flow = SimpleNamespace(
        request=SimpleNamespace(
            scheme="http",
            port=80,
            pretty_host="health.cdm.invalid",
            method="GET",
            path="/__cdm_gateway_health",
            headers=Headers(),
            raw_content=b"",
        ),
        client_conn=SimpleNamespace(peername=("127.0.0.1", 12345)),
        metadata={},
        response=None,
    )
    monkeypatch.setattr(addon.review_store, "probe_writable", lambda: None)

    asyncio.run(addon._request_checked(flow))

    assert addon.audit_fault == "review outcome could not be recorded"
    assert flow.response.reason == "audit-state-fault"


def test_addon_streams_every_normal_response_without_buffering(monkeypatch) -> None:
    addon = _load_addon(monkeypatch)

    for status_code in (200, 302, 404, 500):
        response = SimpleNamespace(status_code=status_code, stream=False)
        flow = SimpleNamespace(response=response, metadata={})

        addon.responseheaders(flow)

        assert response.stream is True


def test_allowed_request_does_not_wait_for_a_review_store_fsync(monkeypatch) -> None:
    addon = _load_addon(monkeypatch)
    policy = SimpleNamespace(digest=lambda: "a" * 64)
    monkeypatch.setattr(addon, "_verified_policy_or_block", lambda _flow: policy)

    async def destination_allowed(*_args):
        return None

    monkeypatch.setattr(addon, "_verify_original_destination", destination_allowed)
    monkeypatch.setattr(
        addon.review_store,
        "probe_writable",
        lambda: pytest.fail("normal requests must not probe the review store"),
    )
    monkeypatch.setitem(
        addon._request_checked.__globals__,
        "evaluate_http_request",
        lambda *_args: SimpleNamespace(action="allow", rule_id="daily", reason=""),
    )

    class Headers:
        def __contains__(self, _name):
            return False

        def items(self, *, multi=False):
            assert multi is True
            return []

        def get(self, _name, default=None):
            return default

    request = SimpleNamespace(
        scheme="http",
        port=80,
        pretty_host="api.example.com",
        method="GET",
        path="/",
        headers=Headers(),
        raw_content=b"",
    )
    flow = SimpleNamespace(
        request=request,
        client_conn=SimpleNamespace(peername=("172.28.0.3", 12345)),
        server_conn=SimpleNamespace(via=None),
        metadata={},
        response=None,
    )

    asyncio.run(addon._request_checked(flow))

    assert flow.response is None


def test_streamed_review_response_is_completed_after_flow_finishes(monkeypatch) -> None:
    addon = _load_addon(monkeypatch)
    completed: list[str] = []
    addon.review_store = SimpleNamespace(
        get=lambda request_id: SimpleNamespace(state="authorized"),
        mark_completed=lambda request_id: completed.append(request_id),
    )
    response = SimpleNamespace(status_code=200, stream=False)
    flow = SimpleNamespace(
        response=response,
        metadata={"cdm_review_request_id": "request-1"},
    )

    addon.responseheaders(flow)
    assert response.stream is True
    assert completed == []

    addon.response(flow)
    assert completed == ["request-1"]
