"""Rootless byte bridges for the strict local-egress topology."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import selectors
import socket
import threading


def _relay(left: socket.socket, right: socket.socket) -> None:
    left.setblocking(False)
    right.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(left, selectors.EVENT_READ, right)
    selector.register(right, selectors.EVENT_READ, left)
    try:
        while True:
            events = selector.select(300)
            if not events:
                return
            for key, _ in events:
                try:
                    data = key.fileobj.recv(131072)
                except OSError:
                    return
                if not data:
                    return
                try:
                    key.data.sendall(data)
                except OSError:
                    return
    finally:
        selector.close()
        for sock in (left, right):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()


def _session(client: socket.socket, connector) -> None:
    try:
        peer = connector()
        _relay(client, peer)
    except OSError:
        client.close()


def _serve(listener: socket.socket, connector) -> None:
    while True:
        client, _ = listener.accept()
        threading.Thread(target=_session, args=(client, connector), daemon=True).start()


def _unix_connect(path: Path) -> socket.socket:
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    peer.connect(str(path))
    return peer


def _tcp_connect(host: str, port: int) -> socket.socket:
    peer = socket.create_connection((host, port), timeout=10)
    peer.settimeout(None)
    return peer


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    tcp = sub.add_parser("tcp-listen")
    tcp.add_argument("--listen", required=True)
    tcp.add_argument("--socket", type=Path, required=True)
    unix = sub.add_parser("unix-listen")
    unix.add_argument("--socket", type=Path, required=True)
    unix.add_argument("--host", required=True)
    unix.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    if args.mode == "tcp-listen":
        host, raw_port = args.listen.rsplit(":", 1)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, int(raw_port)))
        listener.listen(128)
        _serve(listener, lambda: _unix_connect(args.socket))
    else:
        args.socket.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            args.socket.unlink()
        except FileNotFoundError:
            pass
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(args.socket))
        os.chmod(args.socket, 0o660)
        listener.listen(128)
        _serve(listener, lambda: _tcp_connect(args.host, args.port))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
