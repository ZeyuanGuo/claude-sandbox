"""An exact-destination Unix broker and OpenSSH ProxyCommand client."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import sys
import threading

from controlled_dev_machine.proxy_bridge import relay_sockets

_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in
                          ("10.0.0.0/8", "100.64.0.0/10", "192.168.71.0/24"))
_MAX_HEADER = 1024


def destination(host: str, port: int) -> tuple[str, int]:
    """Reject public, ambiguous or hostname targets before any connection."""
    if not isinstance(host, str) or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid SSH destination")
    address = ipaddress.ip_address(host)
    if (not isinstance(address, ipaddress.IPv4Address) or str(address) != host
            or not any(address in network for network in _PRIVATE_NETWORKS)):
        raise ValueError("SSH destination must be a canonical internal IPv4")
    return str(address), port


def load_targets(path: Path) -> frozenset[tuple[str, int]]:
    data = json.loads(path.read_text())
    if set(data) != {"schema_version", "targets"} or data["schema_version"] != 1:
        raise ValueError("invalid SSH allowlist schema")
    targets = frozenset(destination(item["host"], item["port"]) for item in data["targets"])
    if not targets:
        raise ValueError("SSH allowlist is empty")
    return targets


def read_header(connection: socket.socket) -> dict:
    raw = bytearray()
    while len(raw) < _MAX_HEADER:
        piece = connection.recv(1)
        if not piece:
            raise ValueError("incomplete SSH broker header")
        raw.extend(piece)
        if piece == b"\n":
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("SSH broker header must be an object")
            return value
    raise ValueError("oversized SSH broker header")


class Audit:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.failed = False

    def write(self, host: str | None, port: int | None, result: str) -> None:
        with self.lock:
            if self.failed:
                raise OSError("SSH audit unavailable")
            record = {"time": datetime.now(timezone.utc).isoformat(),
                      "host": host, "port": port, "result": result}
            try:
                with self.path.open("a", encoding="ascii") as handle:
                    handle.write(json.dumps(record, sort_keys=True) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError:
                self.failed = True
                raise


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        connection = self.request
        connection.settimeout(5)
        host = port = None
        try:
            request = read_header(connection)
            if set(request) != {"host", "port"}:
                raise ValueError("invalid SSH broker fields")
            host, port = destination(request["host"], request["port"])
            if (host, port) not in self.server.targets:
                raise ValueError("SSH destination is not allowed")
            self.server.audit.write(host, port, "approved")
            # Address validation and audit happen before creating an IP socket.
            peer = socket.create_connection((host, port), timeout=8)
        except (ValueError, OSError, KeyError, TypeError):
            try:
                self.server.audit.write(host, port, "rejected-or-unreachable")
                connection.sendall(b'{"ok":false}\n')
            except OSError:
                pass
            return
        try:
            connection.sendall(b'{"ok":true}\n')
            reason = relay_sockets(connection, peer)
        except OSError:
            peer.close()
            reason = "connection-error"
        try:
            self.server.audit.write(host, port, reason)
        except OSError:
            pass


class Broker(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path: Path, targets: frozenset[tuple[str, int]], audit: Path):
        self.targets = targets
        self.audit = Audit(audit)
        self.slots = threading.BoundedSemaphore(32)
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError("refusing to replace non-owned SSH socket")
            probe = socket.socket(socket.AF_UNIX)
            try:
                probe.connect(str(path))
            except ConnectionRefusedError:
                path.unlink()
            else:
                raise ValueError("SSH broker already running")
            finally:
                probe.close()
        super().__init__(str(path), Handler)
        os.chmod(path, 0o600)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def client(path: Path, host: str, port: int, raw: bool = False,
           expected_host: str | None = None, expected_port: int | None = None) -> int:
    host, port = destination(host, port)
    if expected_host is not None and (host, port) != destination(expected_host, expected_port or 0):
        raise ValueError("SSH destination does not match fixed socket endpoint")
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(15)
        connection.connect(str(path))
        if not raw:
            connection.sendall(json.dumps({"host": host, "port": port}).encode() + b"\n")
            if read_header(connection) != {"ok": True}:
                raise ValueError("SSH destination rejected or unreachable")
        connection.settimeout(None)

        def send_stdin():
            try:
                while True:
                    data = os.read(sys.stdin.fileno(), 65536)
                    if not data:
                        connection.shutdown(socket.SHUT_WR)
                        return
                    connection.sendall(data)
            except OSError:
                pass

        threading.Thread(target=send_stdin, daemon=True).start()
        while True:
            data = connection.recv(65536)
            if not data:
                return 0
            view = memoryview(data)
            while view:
                view = view[os.write(sys.stdout.fileno(), view):]


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest="mode", required=True)
    serve = modes.add_parser("serve")
    serve.add_argument("--socket", type=Path, required=True)
    serve.add_argument("--targets", type=Path, required=True)
    serve.add_argument("--audit", type=Path, required=True)
    connect = modes.add_parser("client")
    connect.add_argument("--socket", type=Path, required=True)
    connect.add_argument("--raw", action="store_true",
                         help="connect to a dedicated fixed-destination reverse socket")
    connect.add_argument("--expected-host")
    connect.add_argument("--expected-port", type=int)
    connect.add_argument("host")
    connect.add_argument("port", type=int)
    args = parser.parse_args()
    try:
        if args.mode == "client":
            return client(args.socket, args.host, args.port, args.raw,
                          args.expected_host, args.expected_port)
        args.socket.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        args.audit.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        with Broker(args.socket, load_targets(args.targets), args.audit) as server:
            server.serve_forever()
    except (OSError, ValueError) as exc:
        print(f"SSH bridge failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
