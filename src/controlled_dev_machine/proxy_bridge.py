"""Rootless byte bridges for the strict local-egress topology."""
from __future__ import annotations

import argparse
import errno
import math
import os
import select
import socket
import stat
import threading
import time
from contextlib import suppress
from pathlib import Path

_MAX_BUFFER = 65536
_IDLE_TIMEOUT = 1800.0
_MAX_SESSIONS = 64


def _positive_timeout(value: float) -> float:
    if (isinstance(value, bool) or not isinstance(value, int | float)
            or not math.isfinite(value) or value <= 0):
        raise ValueError("timeout must be a finite positive number")
    return value


def relay_sockets(left: socket.socket, right: socket.socket, *,
                  idle_timeout: float = _IDLE_TIMEOUT,
                  max_buffer: int = _MAX_BUFFER) -> str:
    """Relay bytes with bounded buffers and half-close support; own both sockets."""
    _positive_timeout(idle_timeout)
    if type(max_buffer) is not int or not 1 <= max_buffer <= 1048576:
        raise ValueError("max_buffer must be between 1 and 1048576")
    other = {left: right, right: left}
    buffers = {left: bytearray(), right: bytearray()}
    ended = set()
    closed_writes = set()
    last_activity = time.monotonic()
    try:
        left.setblocking(False)
        right.setblocking(False)
        while True:
            # An EOF ends only that direction, after its buffered bytes drain.
            for source in ended:
                destination = other[source]
                if not buffers[destination] and destination not in closed_writes:
                    with suppress(OSError):
                        destination.shutdown(socket.SHUT_WR)
                    closed_writes.add(destination)
            if len(ended) == 2 and not any(buffers.values()):
                return "eof"
            remaining = idle_timeout - (time.monotonic() - last_activity)
            if remaining <= 0:
                return "timeout"
            readers = [source for source in other if source not in ended
                       and len(buffers[other[source]]) < max_buffer]
            writers = [destination for destination in other if buffers[destination]]
            ready_read, ready_write, _ = select.select(readers, writers, [], remaining)
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
                    piece = source.recv(max_buffer - len(buffers[other[source]]))
                except BlockingIOError:
                    continue
                if not piece:
                    ended.add(source)
                else:
                    buffers[other[source]].extend(piece)
                    last_activity = time.monotonic()
    except OSError:
        return "closed"
    finally:
        for sock in (left, right):
            with suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()


def _relay(left: socket.socket, right: socket.socket, *,
           idle_timeout: float = _IDLE_TIMEOUT) -> str:
    return relay_sockets(left, right, idle_timeout=idle_timeout)


def _session(client: socket.socket, connector, *,
             idle_timeout: float = _IDLE_TIMEOUT, slots=None) -> None:
    peer = None
    try:
        peer = connector()
        _relay(client, peer, idle_timeout=idle_timeout)
    except OSError:
        # Only the configured connector is attempted; never fall back to direct TCP.
        pass
    finally:
        client.close()
        if peer is not None:
            peer.close()
        if slots is not None:
            slots.release()


def _serve(listener: socket.socket, connector, *, max_sessions: int = _MAX_SESSIONS,
           idle_timeout: float = _IDLE_TIMEOUT, stop_event=None) -> None:
    if type(max_sessions) is not int or not 1 <= max_sessions <= 256:
        raise ValueError("max_sessions must be between 1 and 256")
    _positive_timeout(idle_timeout)
    slots = threading.BoundedSemaphore(max_sessions)
    listener.settimeout(0.2)
    while stop_event is None or not stop_event.is_set():
        try:
            client, _ = listener.accept()
        except TimeoutError:
            continue
        except OSError:
            if stop_event is not None and stop_event.is_set():
                return
            raise
        if not slots.acquire(blocking=False):
            client.close()
            continue
        try:
            threading.Thread(target=_session, args=(client, connector),
                             kwargs={"idle_timeout": idle_timeout, "slots": slots},
                             daemon=True).start()
        except Exception:
            client.close()
            slots.release()
            raise


def _unix_connect(path: Path, timeout: float = 10.0) -> socket.socket:
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        peer.settimeout(_positive_timeout(timeout))
        peer.connect(str(path))
        peer.settimeout(None)
    except Exception:
        peer.close()
        raise
    return peer


def _tcp_connect(host: str, port: int, timeout: float = 10.0) -> socket.socket:
    peer = socket.create_connection((host, port), timeout=_positive_timeout(timeout))
    peer.settimeout(None)
    return peer


def _remove_stale_socket(path: Path) -> None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.geteuid():
        raise ValueError("refusing to replace a non-socket or foreign Unix socket")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.2)
        probe.connect(str(path))
    except OSError as exc:
        if exc.errno not in (errno.ECONNREFUSED, errno.ENOENT):
            raise
    else:
        raise OSError(errno.EADDRINUSE, "Unix socket already has a listener", str(path))
    finally:
        probe.close()
    try:
        after = path.lstat()
    except FileNotFoundError:
        return
    if (before.st_dev, before.st_ino, before.st_uid, before.st_mode) != (
            after.st_dev, after.st_ino, after.st_uid, after.st_mode):
        raise ValueError("Unix socket changed while checking its listener")
    path.unlink()


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
    for mode in (tcp, unix):
        mode.add_argument("--max-sessions", type=int, default=_MAX_SESSIONS)
        mode.add_argument("--idle-timeout", type=float, default=_IDLE_TIMEOUT)
        mode.add_argument("--connect-timeout", type=float, default=10.0)
    args = parser.parse_args()
    _positive_timeout(args.connect_timeout)
    _positive_timeout(args.idle_timeout)
    if not 1 <= args.max_sessions <= 256:
        parser.error("--max-sessions must be between 1 and 256")
    if args.mode == "tcp-listen":
        host, raw_port = args.listen.rsplit(":", 1)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, int(raw_port)))
        listener.listen(128)
        def connector():
            return _unix_connect(args.socket, timeout=args.connect_timeout)
    else:
        args.socket.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _remove_stale_socket(args.socket)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(args.socket))
        os.chmod(args.socket, 0o660)
        listener.listen(128)
        def connector():
            return _tcp_connect(args.host, args.port, timeout=args.connect_timeout)
    try:
        _serve(listener, connector, max_sessions=args.max_sessions,
               idle_timeout=args.idle_timeout)
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
