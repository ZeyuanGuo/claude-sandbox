"""A fixed-parent CONNECT relay for the rootless degraded uplink network."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timezone
import argparse
import ipaddress
import json
import math
import os
import select
import socket
import socketserver
import threading
import time

_MAX_HEADER = 16384
_MAX_BUFFER = 65536


@dataclass(frozen=True)
class RelayConfig:
    audit_path: Path
    upstream_host: str | None = None
    upstream_port: int | None = None
    gateway_source: str = "172.31.1.3"
    dns_source: str = "172.31.1.2"
    header_timeout: float = 5.0
    idle_timeout: float = 1800.0
    # Active Claude/SSE streams and pooled HTTP connections can last hours.
    # Memory, worker count and idle time remain bounded without a hard age cap.
    session_timeout: float | None = None
    max_sessions: int = 64
    test_mode: bool = False
    fixture_targets: tuple[tuple[str, int], ...] = ()

    def __post_init__(self):
        for address in (self.gateway_source, self.dns_source):
            if str(ipaddress.ip_address(address)) != address:
                raise ValueError("trusted source must be a canonical numeric IP")
        if self.gateway_source == self.dns_source:
            raise ValueError("DNS and gateway must have distinct source IPs")
        if bool(self.upstream_host) != (self.upstream_port is not None):
            raise ValueError("parent IP and port must be configured together")
        if self.upstream_host:
            ipaddress.ip_address(self.upstream_host)
            if type(self.upstream_port) is not int or not 1 <= self.upstream_port <= 65535:
                raise ValueError("parent port is invalid")
            parent = ipaddress.ip_address(self.upstream_host)
            if parent.is_multicast or parent.is_unspecified or "%" in str(parent) or getattr(parent, "ipv4_mapped", None):
                raise ValueError("parent address is invalid")
        timeouts = (self.header_timeout, self.idle_timeout)
        if self.session_timeout is not None:
            timeouts += (self.session_timeout,)
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0
               for value in timeouts):
            raise ValueError("timeouts must be finite positive numbers")
        if type(self.max_sessions) is not int or not 1 <= self.max_sessions <= 256:
            raise ValueError("max_sessions must be between 1 and 256")
        if self.fixture_targets and not self.test_mode:
            raise ValueError("fixture targets require explicit test mode")
        for address, port in self.fixture_targets:
            if str(ipaddress.ip_address(address)) != address or type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("fixture must specify an exact numeric IP and port")

    @classmethod
    def from_mapping(cls, mapping: dict, *, audit_path: Path):
        allowed = {"parent_host", "parent_port", "upstream_host", "upstream_port",
                   "trusted_dns_ips", "trusted_gateway_ips", "header_timeout",
                   "idle_timeout", "session_timeout", "max_sessions", "fixture_targets"}
        if not isinstance(mapping, dict) or set(mapping) - allowed:
            raise ValueError("unknown or invalid relay configuration")
        values = {key: mapping[key] for key in ("header_timeout", "idle_timeout", "session_timeout", "max_sessions") if key in mapping}
        for old, new in (("parent_host", "upstream_host"), ("parent_port", "upstream_port")):
            if old in mapping and new in mapping:
                raise ValueError("ambiguous parent configuration")
            values[new] = mapping.get(new, mapping.get(old))
        for key, field in (("trusted_dns_ips", "dns_source"), ("trusted_gateway_ips", "gateway_source")):
            if key in mapping:
                peers = mapping[key]
                if not isinstance(peers, list) or len(peers) != 1 or not isinstance(peers[0], str):
                    raise ValueError("exactly one trusted numeric peer IP is required")
                values[field] = peers[0]
        fixtures = mapping.get("fixture_targets", [])
        if not isinstance(fixtures, list) or any(not isinstance(item, (list, tuple)) or len(item) != 2 for item in fixtures):
            raise ValueError("fixture_targets must be exact [IP, port] pairs")
        return cls(audit_path=audit_path, test_mode=os.environ.get("CDM_DEGRADED_TEST_MODE") == "1",
                   fixture_targets=tuple(tuple(item) for item in fixtures), **values)


class _Audit:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.failed = False

    def write(self, **record):
        with self.lock:
            if self.failed:
                raise OSError("audit storage failure is latched")
            record["created_at"] = datetime.now(timezone.utc).isoformat()
            try:
                with self.path.open("a", encoding="ascii") as handle:
                    handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError:
                self.failed = True
                raise


def _respond(connection, status):
    reasons = {400: "Bad Request", 403: "Forbidden", 502: "Bad Gateway", 503: "Service Unavailable"}
    connection.sendall(f"HTTP/1.1 {status} {reasons[status]}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("ascii"))


def _header(connection, timeout):
    content = bytearray()
    deadline = time.monotonic() + timeout
    while not content.endswith(b"\r\n\r\n"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("header-deadline-exceeded")
        connection.settimeout(remaining)
        piece = connection.recv(1)
        if not piece:
            raise ValueError("incomplete-header")
        content.extend(piece)
        if len(content) > _MAX_HEADER:
            raise ValueError("oversized-header")
    return bytes(content)


def _target(frame, fixture_targets=()):
    lines = frame[:-4].decode("ascii").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or parts[2] != "HTTP/1.1":
        raise ValueError("invalid-connect")
    host, separator, port = parts[1].rpartition(":")
    if not separator or not port.isdecimal() or not host:
        raise ValueError("invalid-authority")
    address = ipaddress.ip_address(host.strip("[]"))
    port = int(port)
    authority = f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"
    fixture = (str(address), port) in fixture_targets
    incoming_authorities = {authority}
    if address.version == 6:
        # mitmproxy 12.2.3 emits bare canonical IPv6 in upstream CONNECT.
        # Canonicalize it before forwarding; never accept a hostname or zone.
        incoming_authorities.add(f"{address}:{port}")
    if parts[1] not in incoming_authorities or (port not in (80, 443) and not fixture):
        raise ValueError("invalid-authority")
    if not fixture and (not address.is_global or address.is_multicast or address.is_loopback
            or address.is_link_local or address.is_reserved or address.is_unspecified
            or getattr(address, "ipv4_mapped", None) or "%" in str(address)):
        raise ValueError("non-public-destination")
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if not separator or name.lower() in headers or name.lower() not in {"host", "user-agent", "connection", "proxy-connection"}:
            raise ValueError("invalid-header")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("invalid-header")
        headers[name.lower()] = value.strip()
        if name.lower() in {"connection", "proxy-connection"} and value.strip().lower() not in {"close", "keep-alive"}:
            raise ValueError("invalid-connection-header")
    if headers.get("host") != parts[1]:
        raise ValueError("invalid-host")
    return str(address), port, authority


def _check_parent_response(frame):
    lines = frame[:-4].decode("ascii").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or parts[0] not in ("HTTP/1.0", "HTTP/1.1") or parts[1] != "200":
        raise OSError("parent-rejected-connect")
    seen = set()
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if not separator or not name or name.lower() in seen or any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise OSError("invalid-parent-header")
        seen.add(name.lower())
        if name.lower() in {"transfer-encoding", "upgrade"} or (name.lower() == "content-length" and value.strip() != "0"):
            raise OSError("framed-parent-response")


def _relay(client, parent, config, audit):
    client.setblocking(False)
    parent.setblocking(False)
    other = {client: parent, parent: client}
    buffers = {client: bytearray(), parent: bytearray()}
    ended = set()
    closed_writes = set()
    started = last_activity = time.monotonic()
    while True:
        if audit.failed:
            return "audit-unavailable"
        for source in ended:
            destination = other[source]
            if not buffers[destination] and destination not in closed_writes:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                closed_writes.add(destination)
        if len(ended) == 2 and not any(buffers.values()):
            return "eof"
        now = time.monotonic()
        remaining = config.idle_timeout - (now - last_activity)
        if config.session_timeout is not None:
            remaining = min(remaining, config.session_timeout - (now - started))
        if remaining <= 0:
            return "timeout"
        readers = [source for source in other if source not in ended and len(buffers[other[source]]) < _MAX_BUFFER]
        writers = [destination for destination in other if buffers[destination]]
        ready_read, ready_write, _ = select.select(readers, writers, [], min(remaining, 0.1))
        for destination in ready_write:
            try:
                sent = destination.send(buffers[destination])
            except BlockingIOError:
                continue
            if not sent:
                return "closed"
            del buffers[destination][:sent]
            last_activity = time.monotonic()
        for source in ready_read:
            try:
                piece = source.recv(_MAX_BUFFER - len(buffers[other[source]]))
            except BlockingIOError:
                continue
            if not piece:
                ended.add(source)
            else:
                buffers[other[source]].extend(piece)
                last_activity = time.monotonic()


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            self._handle()
        except OSError:
            # Client disconnects and resets must never escape as worker errors.
            pass

    def _handle(self) -> None:
        config = self.server.config
        source = self.client_address[0]
        self.request.settimeout(config.header_timeout)
        trusted = source in (config.gateway_source, config.dns_source)
        target = None
        status = 403
        reason = "untrusted-source"
        if trusted:
            if not config.upstream_host:
                status, reason = 503, "parent-unconfigured"
            else:
                try:
                    host, port, target = _target(_header(self.request, config.header_timeout), config.fixture_targets)
                    if source == config.dns_source and (host, port) != ("1.1.1.1", 443):
                        raise ValueError("dns-destination-forbidden")
                except (UnicodeError, ValueError, OSError) as exc:
                    status, reason = 403, str(exc)
                else:
                    status, reason = 200, "destination-approved"
        try:
            self.server.audit.write(source=source, target=target,
                                    result="allow" if status == 200 else "reject", reason=reason)
        except OSError:
            _respond(self.request, 503)
            return
        if status != 200:
            _respond(self.request, status)
            return
        established = False
        try:
            parent_address = ipaddress.ip_address(config.upstream_host)
            family = socket.AF_INET6 if parent_address.version == 6 else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as parent:
                parent.settimeout(config.header_timeout)
                parent.connect((str(parent_address), config.upstream_port))
                parent.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode("ascii"))
                response = _header(parent, config.header_timeout)
                _check_parent_response(response)
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                established = True
                reason = _relay(self.request, parent, config, self.server.audit)
        except (OSError, ValueError) as exc:
            reason = str(exc)
            if not established:
                _respond(self.request, 502)
        if established:
            try:
                self.request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        try:
            self.server.audit.write(source=source, target=target,
                                    result="closed" if established else "parent-failure", reason=reason)
        except OSError:
            pass


class RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, config: RelayConfig, address):
        self.config = config
        self.audit = _Audit(config.audit_path)
        self._slots = threading.BoundedSemaphore(config.max_sessions)
        super().__init__(address, _Handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.settimeout(self.config.header_timeout)
                try:
                    self.audit.write(source=client_address[0], target=None,
                                     result="reject", reason="session-limit")
                except OSError:
                    pass
                _respond(request, 503)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def serve(config: RelayConfig, address=("0.0.0.0", 8080)) -> RelayServer:
    """Bind a relay; the caller owns serve_forever, shutdown and server_close."""
    return RelayServer(config, address)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--audit", type=Path, default=Path(os.environ.get("CDM_RELAY_AUDIT", "/audit/egress.jsonl")))
    args = parser.parse_args(argv)
    try:
        listener = ipaddress.ip_address(args.listen)
        if listener.version != 4 or not 1 <= args.port <= 65535:
            raise ValueError("listen must be an IPv4 literal with a valid port")
        if args.config:
            mapping = json.loads(args.config.read_text())
        else:
            port = os.environ.get("CDM_RELAY_UPSTREAM_PORT")
            mapping = {"parent_host": os.environ.get("CDM_RELAY_UPSTREAM_HOST") or None,
                       "parent_port": int(port) if port else None,
                       "trusted_dns_ips": [os.environ.get("CDM_RELAY_DNS_SOURCE", "172.31.1.2")],
                       "trusted_gateway_ips": [os.environ.get("CDM_RELAY_GATEWAY_SOURCE", "172.31.1.3")]}
        config = RelayConfig.from_mapping(mapping, audit_path=args.audit)
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    os.umask(0o077)
    with serve(config, (str(listener), args.port)) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
