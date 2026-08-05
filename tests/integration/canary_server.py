from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_TEST_ID = re.compile(r"^[a-zA-Z0-9._-]{1,96}$")


class CanaryHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send(b"ok\n", "text/plain")
            return
        if self.path.startswith("/__cdm_upgrade_response/"):
            self._record_and_upgrade()
            return
        self._record_and_echo(b"")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        self._record_and_echo(self.rfile.read(length))

    def log_message(self, format: str, *args: object) -> None:
        return

    def _record_and_echo(self, body: bytes) -> None:
        test_id = self.headers.get("x-cdm-test-id", "")
        if not _TEST_ID.fullmatch(test_id):
            self._send(b"invalid test id\n", "text/plain", status=400)
            return
        digest = hashlib.sha256(body).hexdigest()
        record = {
            "test_id": test_id,
            "scheme": "https" if isinstance(self.connection, ssl.SSLSocket) else "http",
            "method": self.command,
            "path": self.path,
            "body_size": len(body),
            "body_sha256": digest,
        }
        root = Path(self.server.record_root)  # type: ignore[attr-defined]
        body_dir = root / "bodies"
        body_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        (body_dir / f"{test_id}.bin").write_bytes(body)
        with (root / "received.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        response = json.dumps(record, sort_keys=True).encode() + b"\n"
        self._send(response, "application/json")

    def _record_and_upgrade(self) -> None:
        test_id = self.headers.get("x-cdm-test-id", "")
        if not _TEST_ID.fullmatch(test_id):
            self._send(b"invalid test id\n", "text/plain", status=400)
            return
        record = {
            "test_id": test_id,
            "scheme": "https" if isinstance(self.connection, ssl.SSLSocket) else "http",
            "method": self.command,
            "path": self.path,
            "body_size": 0,
            "body_sha256": hashlib.sha256(b"").hexdigest(),
            "response_status": 101,
        }
        root = Path(self.server.record_root)  # type: ignore[attr-defined]
        with (root / "received.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        self.send_response(101)
        self.send_header("connection", "upgrade")
        self.send_header("upgrade", "cdm-fixture")
        self.end_headers()

    def _send(self, body: bytes, content_type: str, *, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(port: int, record_root: Path, cert: Path | None, key: Path | None) -> None:
    server = ThreadingHTTPServer(("0.0.0.0", port), CanaryHandler)
    server.record_root = str(record_root)  # type: ignore[attr-defined]
    if cert is not None and key is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record-root", type=Path, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    args = parser.parse_args()
    args.record_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    https = threading.Thread(
        target=_serve,
        args=(443, args.record_root, args.cert, args.key),
        daemon=True,
    )
    https.start()
    _serve(80, args.record_root, None, None)


if __name__ == "__main__":
    main()
