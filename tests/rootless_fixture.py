"""Offline parent/DoH/origin fixture. Never creates an external connection."""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import select
import socket
import socketserver
import ssl
import threading

from controlled_dev_machine.dns_gateway import _static_response


def event(kind: str, **values) -> None:
    with Path("/fixture/events.jsonl").open("a") as handle:
        handle.write(json.dumps({"kind": kind, **values}) + "\n")


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        event("origin", host=self.headers.get("Host"), path=self.path)
        body = b"rootless-canary-ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class Doh(BaseHTTPRequestHandler):
    def do_POST(self):
        query = self.rfile.read(int(self.headers["Content-Length"]))
        event("doh", host=self.headers.get("Host"), path=self.path)
        response = _static_response(query, "9.9.9.9")
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args):
        pass


class Parent(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        header = b""
        while not header.endswith(b"\r\n\r\n") and len(header) < 16384:
            chunk = self.request.recv(1)
            if not chunk:
                return
            header += chunk
        authority = header.split(b" ")[1].decode("ascii")
        destinations = {"1.1.1.1:443": 18443, "9.9.9.9:443": 18444, "9.9.9.9:80": 18080}
        event("connect", target=authority)
        if authority not in destinations:
            self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        with socket.create_connection(("127.0.0.1", destinations[authority]), 5) as upstream:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            while True:
                ready, _, _ = select.select([self.request, upstream], [], [], 20)
                if not ready:
                    return
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is self.request else self.request).sendall(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert-root", type=Path, default=Path("/fixture"))
    args = parser.parse_args()
    servers = []
    for port, handler, name in ((18443, Doh, "doh"), (18444, Origin, "origin"), (18080, Origin, "")):
        server = ThreadingHTTPServer(("127.0.0.1", port), handler)
        if name:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(args.cert_root / (name + ".pem"), args.cert_root / (name + ".key"))
            server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    with socketserver.ThreadingTCPServer(("0.0.0.0", 18081), Parent) as parent:
        parent.serve_forever()


if __name__ == "__main__":
    main()
