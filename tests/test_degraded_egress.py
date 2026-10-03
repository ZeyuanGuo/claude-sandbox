from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import socket
import tempfile
import threading
import unittest
import json
import os
import queue
import subprocess
import sys
import time
from unittest.mock import patch


class FakeParent:
    def __init__(self, audit, response=b"HTTP/1.1 200 Connection Established\r\n\r\n", echo=True):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(5)
        self.listener.settimeout(0.1)
        self.address = self.listener.getsockname()
        self.audit = audit
        self.response = response
        self.echo = echo
        self.frames = queue.Queue()
        self.stopped = threading.Event()
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(1)
                frame = b""
                while b"\r\n\r\n" not in frame:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    frame += chunk
                records = [json.loads(line) for line in self.audit.read_text().splitlines()] if self.audit.is_file() else []
                self.frames.put((frame, records))
                if not self.response:
                    continue
                connection.sendall(self.response)
                if self.echo:
                    while not self.stopped.is_set():
                        try:
                            payload = connection.recv(4096)
                        except socket.timeout:
                            continue
                        if not payload:
                            break
                        connection.sendall(payload)

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.worker.join(timeout=2)

try:
    from controlled_dev_machine.degraded_egress import RelayConfig, serve
except ModuleNotFoundError as exc:
    if exc.name != "controlled_dev_machine":
        raise
    from degraded_egress import RelayConfig, serve

MODULE_PATH = Path(sys.modules[RelayConfig.__module__].__file__)


@contextmanager
def running_relay(config: RelayConfig):
    with serve(config, ("127.0.0.1", 0)) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield server.server_address
        finally:
            server.shutdown()
            worker.join(timeout=2)


def connect_request(address, request: bytes, source="127.0.0.2") -> bytes:
    with socket.socket() as connection:
        connection.settimeout(2)
        connection.bind((source, 0))
        connection.connect(address)
        connection.sendall(request)
        return connection.recv(4096)


class RelayBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.audit = Path(self.temporary.name) / "egress.jsonl"

    def config(self, **overrides):
        values = dict(audit_path=self.audit, gateway_source="127.0.0.2",
                      dns_source="127.0.0.3", header_timeout=0.3,
                      idle_timeout=0.3, session_timeout=1.0)
        values.update(overrides)
        return RelayConfig(**values)

    def test_unconfigured_parent_returns_503_without_direct_fallback(self):
        with running_relay(self.config()) as address:
            response = connect_request(address, b"CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n")
        self.assertTrue(response.startswith(b"HTTP/1.1 503 "), response)

    def test_untrusted_source_is_rejected_even_without_a_parent(self):
        with running_relay(self.config()) as address:
            response = connect_request(address, b"CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n", source="127.0.0.4")
        self.assertTrue(response.startswith(b"HTTP/1.1 403 "), response)
        records = [json.loads(line) for line in self.audit.read_text().splitlines()]
        self.assertEqual(records[0]["reason"], "untrusted-source")

    def test_parent_hostname_cannot_use_host_dns(self):
        with self.assertRaises(ValueError):
            self.config(upstream_host="parent.example.com", upstream_port=8080)

    def test_connect_is_audited_before_parent_contact_and_bytes_are_unmodified(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        config = self.config(upstream_host=parent.address[0], upstream_port=parent.address[1])
        with running_relay(config) as address:
            with socket.socket() as connection:
                connection.settimeout(2)
                connection.bind(("127.0.0.2", 0))
                connection.connect(address)
                connection.sendall(b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
                self.assertEqual(connection.recv(4096), b"HTTP/1.1 200 Connection Established\r\n\r\n")
                payload = b"\x16\x03\x01\x00\x05\x00\xff\x00\x01\x02"
                connection.sendall(payload)
                self.assertEqual(connection.recv(4096), payload)
        frame, records = parent.frames.get(timeout=1)
        self.assertEqual(frame, b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\nConnection: close\r\n\r\n")
        self.assertEqual(records[0]["result"], "allow")
        self.assertEqual(records[0]["target"], "8.8.8.8:443")

    def test_dns_peer_can_only_connect_the_fixed_doh_address(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1])) as address:
            for target in ("8.8.8.8:443", "1.1.1.1:80"):
                with self.subTest(target=target):
                    response = connect_request(address, f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode(), source="127.0.0.3")
                    self.assertTrue(response.startswith(b"HTTP/1.1 403 "), response)
            response = connect_request(address, b"CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n", source="127.0.0.3")
            self.assertTrue(response.startswith(b"HTTP/1.1 200 "), response)
        frame, _ = parent.frames.get(timeout=1)
        self.assertTrue(frame.startswith(b"CONNECT 1.1.1.1:443 "), frame)
        self.assertTrue(parent.frames.empty())

    def test_gateway_rejects_hostname_private_and_special_targets(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1])) as address:
            forbidden = ("example.com:443", "127.0.0.1:443", "10.0.0.1:80", "172.31.1.1:443", "169.254.169.254:80", "224.0.0.1:443", "[::1]:443", "[::ffff:8.8.8.8]:443", "[fe80::1%eth0]:443", "8.8.8.8:22", "8.8.8.8:0443")
            for target in forbidden:
                with self.subTest(target=target):
                    response = connect_request(address, f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                    self.assertTrue(response.startswith(b"HTTP/1.1 403 "), response)
        self.assertTrue(parent.frames.empty())

    def test_malformed_or_ambiguous_connect_headers_never_reach_parent(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1])) as address:
            forbidden = (
                b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
                b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n",
                b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\nHost: 8.8.8.8:443\r\n\r\n",
                b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\nContent-Length: 8\r\n\r\n",
                b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\nTransfer-Encoding: chunked\r\n\r\n",
                b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\nProxy-Authorization: secret\r\n\r\n",
                b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\nConnection: upgrade\r\n\r\n",
            )
            for request in forbidden:
                with self.subTest(request=request):
                    response = connect_request(address, request)
                    self.assertTrue(response.startswith(b"HTTP/1.1 403 "), response)
        self.assertTrue(parent.frames.empty())

    def test_audit_failure_blocks_before_parent_contact(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        self.audit.mkdir()
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1])) as address:
            response = connect_request(address, b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
            self.assertTrue(response.startswith(b"HTTP/1.1 503 "), response)
            self.audit.rmdir()
            response = connect_request(address, b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
            self.assertTrue(response.startswith(b"HTTP/1.1 503 "), response)
        self.assertTrue(parent.frames.empty())

    def test_parent_disconnect_is_a_502_without_direct_fallback(self):
        parent = FakeParent(self.audit, response=b"")
        self.addCleanup(parent.close)
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1])) as address:
            response = connect_request(address, b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
            self.assertTrue(response.startswith(b"HTTP/1.1 502 "), response)

    def test_fsync_failure_blocks_before_parent_contact(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1])) as address:
            with patch("os.fsync", side_effect=OSError("storage unavailable")):
                response = connect_request(address, b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
            self.assertTrue(response.startswith(b"HTTP/1.1 503 "), response)
        self.assertTrue(parent.frames.empty())

    def test_idle_tunnel_is_closed_at_the_configured_bound(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1])) as address:
            with socket.socket() as connection:
                connection.settimeout(2)
                connection.bind(("127.0.0.2", 0))
                connection.connect(address)
                connection.sendall(b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
                self.assertTrue(connection.recv(4096).startswith(b"HTTP/1.1 200 "))
                self.assertEqual(connection.recv(4096), b"")

    def test_parent_cannot_smuggle_framed_body_into_the_tunnel(self):
        parent = FakeParent(self.audit, response=b"HTTP/1.1 200 Connection Established\r\nContent-Length: 3\r\n\r\nbad", echo=False)
        self.addCleanup(parent.close)
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1])) as address:
            response = connect_request(address, b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
            self.assertTrue(response.startswith(b"HTTP/1.1 502 "), response)

    def test_json_config_pins_parent_and_trusted_peer_ips(self):
        config = RelayConfig.from_mapping({"parent_host": "127.0.0.1", "parent_port": 12345,
                                           "trusted_dns_ips": ["172.31.1.2"],
                                           "trusted_gateway_ips": ["172.31.1.3"]}, audit_path=self.audit)
        self.assertEqual((config.upstream_host, config.upstream_port), ("127.0.0.1", 12345))
        self.assertEqual((config.dns_source, config.gateway_source), ("172.31.1.2", "172.31.1.3"))

    def test_fixture_target_requires_explicit_test_mode(self):
        with self.assertRaises(ValueError):
            self.config(fixture_targets=(("127.0.0.1", 443),))

    def test_cli_documents_the_config_listen_port_and_audit_contract(self):
        result = subprocess.run([sys.executable, str(MODULE_PATH), "--help"], capture_output=True, text=True, check=True)
        for flag in ("--config", "--listen", "--port", "--audit"):
            self.assertIn(flag, result.stdout)

    def test_cli_environment_parent_hostname_fails_before_listening(self):
        environment = os.environ | {"CDM_RELAY_UPSTREAM_HOST": "parent.example.com", "CDM_RELAY_UPSTREAM_PORT": "8080", "CDM_RELAY_AUDIT": str(self.audit)}
        result = subprocess.run([sys.executable, str(MODULE_PATH), "--listen", "127.0.0.1"], capture_output=True, text=True, env=environment)
        self.assertEqual(result.returncode, 2)
        self.assertIn("parent.example.com", result.stderr)

    def test_test_mode_fixture_exception_is_exact_and_does_not_relax_dns(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1], test_mode=True, fixture_targets=(("127.0.0.8", 12345),))) as address:
            for source, target, status in (("127.0.0.2", "127.0.0.8:12345", 200), ("127.0.0.2", "127.0.0.8:12346", 403), ("127.0.0.3", "127.0.0.8:12345", 403)):
                response = connect_request(address, f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode(), source=source)
                self.assertTrue(response.startswith(f"HTTP/1.1 {status} ".encode()), response)

    def test_trickled_headers_have_an_absolute_deadline(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1], header_timeout=0.15)) as address:
            with socket.socket() as connection:
                connection.settimeout(0.03)
                connection.bind(("127.0.0.2", 0))
                connection.connect(address)
                response = b""
                started = time.monotonic()
                for _ in range(8):
                    try:
                        connection.sendall(b"C")
                    except OSError:
                        break
                    time.sleep(0.04)
                    try:
                        response += connection.recv(4096)
                        if response:
                            break
                    except socket.timeout:
                        continue
                self.assertLess(time.monotonic() - started, 0.4)
                self.assertTrue(response.startswith(b"HTTP/1.1 403 "), response)
        self.assertTrue(parent.frames.empty())

    def test_concurrent_sessions_are_bounded_and_overflow_fails_closed(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1], max_sessions=1, header_timeout=0.8)) as address:
            with socket.socket() as first:
                first.bind(("127.0.0.2", 0))
                first.connect(address)
                first.sendall(b"CONNECT ")
                time.sleep(0.05)
                response = connect_request(address, b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
                self.assertTrue(response.startswith(b"HTTP/1.1 503 "), response)
        self.assertTrue(parent.frames.empty())

    def test_audit_records_do_not_include_tunneled_payload(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1])) as address:
            with socket.socket() as connection:
                connection.settimeout(2)
                connection.bind(("127.0.0.2", 0))
                connection.connect(address)
                connection.sendall(b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
                self.assertTrue(connection.recv(4096).startswith(b"HTTP/1.1 200 "))
                connection.sendall(b"sensitive-fixture-never-log-this")
                self.assertEqual(connection.recv(4096), b"sensitive-fixture-never-log-this")
        self.assertNotIn("sensitive-fixture-never-log-this", self.audit.read_text())
        for line in self.audit.read_text().splitlines():
            self.assertEqual(set(json.loads(line)), {"source", "target", "result", "reason", "created_at"})

    def test_an_audit_fault_closes_already_established_tunnels(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1], idle_timeout=5, session_timeout=5)) as address:
            with socket.socket() as connection:
                connection.settimeout(1)
                connection.bind(("127.0.0.2", 0))
                connection.connect(address)
                connection.sendall(b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
                self.assertTrue(connection.recv(4096).startswith(b"HTTP/1.1 200 "))
                self.audit.unlink()
                self.audit.mkdir()
                response = connect_request(address, b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
                self.assertTrue(response.startswith(b"HTTP/1.1 503 "), response)
                self.assertEqual(connection.recv(4096), b"")

    def test_large_tunnel_and_half_close_preserve_every_byte(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1], idle_timeout=1, session_timeout=3)) as address:
            with socket.socket() as connection:
                connection.settimeout(3)
                connection.bind(("127.0.0.2", 0))
                connection.connect(address)
                connection.sendall(b"CONNECT 8.8.8.8:80 HTTP/1.1\r\nHost: 8.8.8.8:80\r\n\r\n")
                self.assertTrue(connection.recv(4096).startswith(b"HTTP/1.1 200 "))
                payload = bytes(range(256)) * 1024
                connection.sendall(payload)
                connection.shutdown(socket.SHUT_WR)
                received = bytearray()
                while True:
                    piece = connection.recv(65536)
                    if not piece:
                        break
                    received.extend(piece)
                self.assertEqual(bytes(received), payload)

    def test_default_stream_survives_more_than_five_minutes_and_keeps_transferring(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        config = RelayConfig(audit_path=self.audit, upstream_host=parent.address[0],
                             upstream_port=parent.address[1], gateway_source="127.0.0.2",
                             dns_source="127.0.0.3", header_timeout=0.3)
        real_clock = time.monotonic
        elapsed = [0.0]
        with patch("time.monotonic", side_effect=lambda: real_clock() + elapsed[0]):
            with running_relay(config) as address:
                with socket.socket() as connection:
                    connection.settimeout(2)
                    connection.bind(("127.0.0.2", 0))
                    connection.connect(address)
                    connection.sendall(b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
                    self.assertTrue(connection.recv(4096).startswith(b"HTTP/1.1 200 "))
                    connection.sendall(b"stream-start")
                    self.assertEqual(connection.recv(4096), b"stream-start")
                    for _ in range(6):
                        elapsed[0] += 301.0
                        connection.sendall(b"stream-continues")
                        self.assertEqual(connection.recv(4096), b"stream-continues")

    def test_mitmproxy_12_2_3_ipv6_connect_frame_is_canonicalized_for_parent(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1])) as address:
            # Captured from mitmproxy 12.2.3 HttpUpstreamProxy.start_handshake().
            response = connect_request(address, b"CONNECT 2606:4700:4700::1111:443 HTTP/1.1\r\nHost: 2606:4700:4700::1111:443\r\n\r\n")
            self.assertTrue(response.startswith(b"HTTP/1.1 200 "), response)
        frame, _ = parent.frames.get(timeout=1)
        self.assertEqual(frame, b"CONNECT [2606:4700:4700::1111]:443 HTTP/1.1\r\nHost: [2606:4700:4700::1111]:443\r\nConnection: close\r\n\r\n")

    def test_explicit_session_timeout_still_bounds_an_active_stream(self):
        parent = FakeParent(self.audit)
        self.addCleanup(parent.close)
        real_clock = time.monotonic
        elapsed = [0.0]
        with patch("time.monotonic", side_effect=lambda: real_clock() + elapsed[0]):
            with running_relay(self.config(upstream_host=parent.address[0], upstream_port=parent.address[1],
                                           idle_timeout=5.0, session_timeout=0.2)) as address:
                with socket.socket() as connection:
                    connection.settimeout(2)
                    connection.bind(("127.0.0.2", 0))
                    connection.connect(address)
                    connection.sendall(b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
                    self.assertTrue(connection.recv(4096).startswith(b"HTTP/1.1 200 "))
                    connection.sendall(b"active")
                    self.assertEqual(connection.recv(4096), b"active")
                    elapsed[0] = 0.3
                    self.assertEqual(connection.recv(4096), b"")


if __name__ == "__main__":
    unittest.main()
