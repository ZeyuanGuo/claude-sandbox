"""The local transport preserves bytes while a same-parent exit lease is valid."""

from contextlib import contextmanager
from dataclasses import replace
import json
from pathlib import Path
import socket
import socketserver
import sys
import threading
import time

import pytest


EGRESS = Path(__file__).resolve().parents[1] / "gateway/egress"
sys.path.insert(0, str(EGRESS))
try:
    from exit_monitor import refresh
    from pinned_relay import RelayConfig, exit_lease_valid
    from transport import TransportServer
finally:
    sys.path.remove(str(EGRESS))


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.connected.set()
        self.server.connections += 1
        self.request.settimeout(2)
        try:
            while piece := self.request.recv(65536):
                self.request.sendall(piece)
        except OSError:
            pass


@contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01},
                              daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def parent():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    server.daemon_threads = True
    server.connected = threading.Event()
    server.connections = 0
    with running(server):
        yield server


@pytest.fixture
def config(tmp_path, parent):
    return RelayConfig(
        audit_path=tmp_path / "transport.jsonl",
        expected_exit="209.227.56.87", exit_lease=tmp_path / "lease.json",
        upstream_host="127.0.0.1", upstream_port=parent.server_address[1],
        gateway_source="127.0.0.2", dns_source="127.0.0.3",
        header_timeout=0.5, idle_timeout=2,
    )


def write_lease(config, **changes):
    checked = time.monotonic()
    lease = {
        "schema_version": 1, "ok": True,
        "expected_exit": config.expected_exit, "observed_exit": config.expected_exit,
        "parent_host": config.upstream_host, "parent_port": config.upstream_port,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "checked_monotonic": checked, "expires_monotonic": checked + 15,
    }
    lease.update(changes)
    temporary = config.exit_lease.with_suffix(".tmp")
    temporary.write_text(json.dumps(lease), encoding="utf-8")
    temporary.replace(config.exit_lease)
    return lease


def receive_exact(connection, count):
    result = bytearray()
    while len(result) < count:
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise AssertionError("Transport closed before all expected bytes arrived")
        result.extend(chunk)
    return bytes(result)


def connect(server, source=None):
    connection = socket.socket()
    connection.settimeout(2)
    if source:
        connection.bind((source, 0))
    connection.connect(server.server_address)
    return connection


@pytest.mark.parametrize("changes", [
    {"expected_exit": None, "exit_lease": None},
    {"upstream_host": None, "upstream_port": None},
])
def test_transport_requires_pin_and_parent(config, changes):
    with pytest.raises(ValueError, match="requires"):
        TransportServer(replace(config, **changes), ("127.0.0.1", 0))


@pytest.mark.parametrize("invalid", [
    "missing", "malformed", "wrong-exit", "wrong-parent", "wrong-boot",
    "expired", "future", "false", "nonfinite",
])
def test_bad_lease_never_connects_to_parent(config, parent, invalid):
    with TransportServer(config, ("127.0.0.1", 0)) as server:
        now = time.monotonic()
        changes = {
            "wrong-exit": {"observed_exit": "203.0.113.7"},
            "wrong-parent": {"parent_port": config.upstream_port + 1},
            "wrong-boot": {"boot_id": "different-boot"},
            "expired": {"checked_monotonic": now - 20, "expires_monotonic": now - 5},
            "future": {"checked_monotonic": now + 1, "expires_monotonic": now + 15},
            "false": {"ok": False},
            "nonfinite": {"expires_monotonic": float("inf")},
        }
        if invalid == "malformed":
            config.exit_lease.write_text("not-json", encoding="utf-8")
        elif invalid != "missing":
            write_lease(config, **changes[invalid])
        with running(server), connect(server) as client:
            assert b"503 Service Unavailable" in client.recv(4096)
        assert parent.connections == 0


def test_lease_from_before_server_start_is_rejected(config):
    write_lease(config)
    with TransportServer(config, ("127.0.0.1", 0)) as server:
        assert not exit_lease_valid(config, newer_than=server.lease_started)


def test_transparent_hostname_connect_and_fragmented_bytes(config):
    with TransportServer(config, ("127.0.0.1", 0)) as server:
        write_lease(config)
        with running(server), connect(server) as client:
            pieces = [b"CON", b"NECT api.example.test:443 HTTP/1.1\r\n",
                      b"Host: api.example.test:443\r\n\r\n", b"\x00\xff\x10payload"]
            for piece in pieces:
                client.sendall(piece)
                assert receive_exact(client, len(piece)) == piece


def test_untrusted_source_cannot_connect_parent(config, parent):
    with TransportServer(config, ("127.0.0.1", 0)) as server:
        write_lease(config)
        with running(server), connect(server, "127.0.0.4") as client:
            assert b"503 Service Unavailable" in client.recv(4096)
        assert parent.connections == 0


@pytest.mark.parametrize("source", ["127.0.0.1", "127.0.0.2", "127.0.0.3"])
def test_only_configured_sources_and_host_loopback_are_allowed(config, source):
    with TransportServer(config, ("127.0.0.1", 0)) as server:
        write_lease(config)
        with running(server), connect(server, source) as client:
            client.sendall(b"source-check")
            assert receive_exact(client, 12) == b"source-check"


@pytest.mark.parametrize("reason", ["revoked", "expired", "monitor-error"])
def test_active_connection_is_closed_when_lease_becomes_invalid(config, reason):
    with TransportServer(config, ("127.0.0.1", 0)) as server:
        write_lease(config)
        with running(server), connect(server) as client:
            client.sendall(b"before")
            assert receive_exact(client, 6) == b"before"
            started = time.monotonic()
            if reason == "revoked":
                write_lease(config, ok=False)
            elif reason == "expired":
                write_lease(config, checked_monotonic=started - 20,
                            expires_monotonic=started - 5)
            else:
                mapping = {"parent_host": config.upstream_host,
                           "parent_port": config.upstream_port,
                           "expected_exit": config.expected_exit,
                           "exit_lease": str(config.exit_lease)}
                def fail_probe(_):
                    raise OSError("local test probe failed")
                assert refresh(mapping, probe=fail_probe)["ok"] is False
            assert client.recv(1) == b""
            assert time.monotonic() - started < 1


def test_audit_failure_never_opens_parent(config, parent):
    config = replace(config, audit_path=config.audit_path.parent / "missing/audit.jsonl")
    with TransportServer(config, ("127.0.0.1", 0)) as server:
        write_lease(config)
        with running(server), connect(server) as client:
            assert client.recv(1) == b""
        assert server.audit.failed
        assert parent.connections == 0


def test_latched_audit_failure_closes_active_stream(config):
    with TransportServer(config, ("127.0.0.1", 0)) as server:
        write_lease(config)
        with running(server), connect(server) as client:
            client.sendall(b"before")
            assert receive_exact(client, 6) == b"before"
            server.audit.failed = True
            assert client.recv(1) == b""


def test_session_limit_rejects_without_connecting_another_parent(config, parent):
    config = replace(config, max_sessions=1)
    with TransportServer(config, ("127.0.0.1", 0)) as server:
        write_lease(config)
        with running(server), connect(server) as first:
            first.sendall(b"first")
            assert receive_exact(first, 5) == b"first"
            with connect(server) as second:
                assert b"503 Service Unavailable" in second.recv(4096)
            assert parent.connections == 1


@pytest.mark.parametrize("observed,raises", [("209.227.56.87", False),
                                             ("203.0.113.7", False), (None, True)])
def test_monitor_publishes_success_mismatch_or_exception(config, observed, raises):
    mapping = {"parent_host": config.upstream_host, "parent_port": config.upstream_port,
               "expected_exit": config.expected_exit, "exit_lease": str(config.exit_lease)}
    def probe(_):
        if raises:
            raise OSError("fixture probe unavailable")
        return observed
    record = refresh(mapping, probe=probe)
    assert record["ok"] is (not raises and observed == config.expected_exit)
    assert exit_lease_valid(config) is record["ok"]
    assert json.loads(config.exit_lease.read_text())["ok"] is record["ok"]
