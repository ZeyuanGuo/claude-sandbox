"""Fixed Unix-socket SSH shadow for a mapped, non-root target identity."""
from __future__ import annotations

import argparse
import json
import math
import os
import select
import signal
import socket
import stat
import threading
import time
from contextlib import suppress
from pathlib import Path

from controlled_dev_machine.proxy_bridge import relay_sockets

_FILES = ("ssh_config", "known_hosts", "id_ed25519_fleet")


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _directory(path: Path, owner: int) -> os.stat_result:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("SSH bridge paths must be absolute without traversal")
    for component in (path, *path.parents):
        if stat.S_ISLNK(component.lstat().st_mode):
            raise ValueError("SSH bridge paths must not contain symbolic links")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
        raise ValueError("SSH bridge root must be a private owned directory")
    return info


class SSHShadow:
    """Freeze endpoints at prepare; later accepts only those original paths.

    Call prepare(), supervise serve(stop_event), then close(). The helper must
    have namespace CHOWN/DAC permissions; the target gets no extra capability.
    An existing shadow may be adopted only when empty, private and helper-owned.
    """

    def __init__(self, source: Path, shadow: Path, *, uid: int, gid: int,
                 max_sessions: int = 64, idle_timeout: float = 1800.0,
                 connect_timeout: float = 5.0):
        if any(type(value) is not int or value < 0 for value in (uid, gid)):
            raise ValueError("uid and gid must be nonnegative integers")
        if type(max_sessions) is not int or not 1 <= max_sessions <= 256:
            raise ValueError("max_sessions must be between 1 and 256")
        for timeout in (idle_timeout, connect_timeout):
            if isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
                raise ValueError("timeouts must be finite and positive")
        self.source, self.shadow = Path(source), Path(shadow)
        self.uid, self.gid = uid, gid
        self.idle_timeout, self.connect_timeout = idle_timeout, connect_timeout
        self.owner = os.geteuid()
        self.source_fd = self.shadow_fd = None
        self.source_identity = None
        self.listeners: dict[socket.socket, str] = {}
        self.created: dict[str, tuple[int, int]] = {}
        self.created_directory = False
        self.slots = threading.BoundedSemaphore(max_sessions)
        self.sessions: set[socket.socket] = set()
        self.threads: set[threading.Thread] = set()
        self.lock = threading.Lock()
        self.closed = threading.Event()
        self.prepared = False

    @property
    def active_sessions(self) -> int:
        with self.lock:
            return len(self.threads)

    def _source_stat(self, name: str) -> os.stat_result:
        current = _directory(self.source, self.owner)
        if _identity(current) != self.source_identity:
            raise ValueError("SSH source directory was replaced")
        info = os.stat(name, dir_fd=self.source_fd, follow_symlinks=False)
        if info.st_uid != self.owner or info.st_mode & 0o022:
            raise ValueError("SSH source endpoint must be owned and non-writable by others")
        return info

    def _record_created(self, name: str) -> None:
        self.created[name] = _identity(os.stat(name, dir_fd=self.shadow_fd,
                                               follow_symlinks=False))

    def _copy(self, name: str) -> dict:
        before = self._source_stat(name)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("SSH configuration inputs must be regular files")
        source_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=self.source_fd)
        try:
            if _identity(os.fstat(source_fd)) != _identity(before):
                raise ValueError("SSH configuration changed during opening")
            destination_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                                     dir_fd=self.shadow_fd)
            self._record_created(name)
            try:
                while data := os.read(source_fd, 65536):
                    remaining = memoryview(data)
                    while remaining:
                        remaining = remaining[os.write(destination_fd, remaining):]
                os.fchown(destination_fd, self.uid, self.gid)
                os.fchmod(destination_fd, stat.S_IMODE(before.st_mode))
                os.fsync(destination_fd)
                after = os.fstat(source_fd)
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError("SSH configuration changed during copying")
                info = os.fstat(destination_fd)
                return {"uid": info.st_uid, "gid": info.st_gid,
                        "mode": stat.S_IMODE(info.st_mode), "size": info.st_size}
            finally:
                os.close(destination_fd)
        finally:
            os.close(source_fd)

    def prepare(self) -> dict:
        if self.prepared or self.closed.is_set():
            raise ValueError("SSH shadow cannot be prepared twice")
        try:
            original = _directory(self.source, self.owner)
            self.source_identity = _identity(original)
            self.source_fd = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY
                                     | os.O_NOFOLLOW | os.O_CLOEXEC)
            if _identity(os.fstat(self.source_fd)) != self.source_identity:
                raise ValueError("SSH source changed during opening")
            names = []
            for name in sorted(os.listdir(self.source_fd)):
                if name.endswith(".sock"):
                    if not stat.S_ISSOCK(self._source_stat(name).st_mode):
                        raise ValueError("SSH .sock endpoint must be a Unix socket")
                    names.append(name)
            if not names:
                raise ValueError("SSH source contains no fixed Unix endpoints")
            if not self.shadow.is_absolute() or ".." in self.shadow.parts:
                raise ValueError("SSH shadow path must be absolute without traversal")
            _directory(self.shadow.parent, self.owner)
            if self.shadow.exists() or self.shadow.is_symlink():
                _directory(self.shadow, self.owner)
                if any(self.shadow.iterdir()):
                    raise ValueError("SSH shadow must be empty")
            else:
                self.shadow.mkdir(mode=0o700)
                self.created_directory = True
            self.shadow_fd = os.open(self.shadow, os.O_RDONLY | os.O_DIRECTORY
                                     | os.O_NOFOLLOW | os.O_CLOEXEC)
            files = {name: self._copy(name) for name in _FILES}
            endpoints = {}
            for name in names:
                source_info = self._source_stat(name)
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    listener.bind(f"/proc/self/fd/{self.shadow_fd}/{name}")
                    self._record_created(name)
                    os.chown(name, self.uid, self.gid, dir_fd=self.shadow_fd,
                             follow_symlinks=False)
                    os.chmod(name, stat.S_IMODE(source_info.st_mode), dir_fd=self.shadow_fd)
                    listener.listen(64)
                    listener.setblocking(False)
                    self.listeners[listener] = name
                    endpoints[name] = {"uid": self.uid, "gid": self.gid,
                                       "mode": stat.S_IMODE(source_info.st_mode)}
                except BaseException:
                    listener.close()
                    raise
            os.fchown(self.shadow_fd, self.uid, self.gid)
            os.fchmod(self.shadow_fd, 0o700)
            proof = {"schema_version": 1, "shadow_root": str(self.shadow),
                     "uid": self.uid, "gid": self.gid, "mode": 0o700,
                     "socket_names": names, "files": files, "sockets": endpoints}
            ready_name = ".ready-in-progress"
            ready = os.open(ready_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                            | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.shadow_fd)
            self._record_created(ready_name)
            try:
                payload = memoryview((json.dumps(proof, sort_keys=True) + "\n").encode())
                while payload:
                    payload = payload[os.write(ready, payload):]
                os.fchown(ready, self.uid, self.gid)
                os.fsync(ready)
            finally:
                os.close(ready)
            os.link(ready_name, "ready.json", src_dir_fd=self.shadow_fd,
                    dst_dir_fd=self.shadow_fd, follow_symlinks=False)
            self._record_created("ready.json")
            os.unlink(ready_name, dir_fd=self.shadow_fd)
            self.created.pop(ready_name)
            os.fsync(self.shadow_fd)
            self.prepared = True
            return proof
        except BaseException:
            self.close()
            raise

    def _connect(self, name: str) -> socket.socket:
        before = self._source_stat(name)
        if not stat.S_ISSOCK(before.st_mode):
            raise ValueError("SSH source socket was replaced with another type")
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            peer.settimeout(self.connect_timeout)
            peer.connect(f"/proc/self/fd/{self.source_fd}/{name}")
            after = self._source_stat(name)
            if _identity(before) != _identity(after) or not stat.S_ISSOCK(after.st_mode):
                raise ValueError("SSH source endpoint changed while connecting")
            peer.settimeout(None)
            return peer
        except BaseException:
            peer.close()
            raise

    def _session(self, client: socket.socket, name: str) -> None:
        peer = None
        try:
            peer = self._connect(name)
            with self.lock:
                self.sessions.add(peer)
            if not self.closed.is_set():
                relay_sockets(client, peer, idle_timeout=self.idle_timeout)
        except (OSError, ValueError):
            pass
        finally:
            client.close()
            if peer is not None:
                peer.close()
            with self.lock:
                self.sessions.discard(client)
                self.sessions.discard(peer)
                self.threads.discard(threading.current_thread())
            self.slots.release()

    def serve(self, stop_event: threading.Event) -> None:
        if not self.prepared:
            raise ValueError("SSH shadow must be prepared before serving")
        try:
            while not stop_event.is_set() and not self.closed.is_set():
                readable, _, _ = select.select(list(self.listeners), [], [], 0.2)
                for listener in readable:
                    try:
                        client, _ = listener.accept()
                    except BlockingIOError:
                        continue
                    if not self.slots.acquire(blocking=False):
                        client.close()
                        continue
                    worker = threading.Thread(target=self._session,
                                              args=(client, self.listeners[listener]), daemon=True)
                    with self.lock:
                        self.sessions.add(client)
                        self.threads.add(worker)
                    try:
                        worker.start()
                    except BaseException:
                        with self.lock:
                            self.sessions.discard(client)
                            self.threads.discard(worker)
                        client.close()
                        self.slots.release()
                        raise
        finally:
            self.close()

    def close(self) -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        for listener in self.listeners:
            listener.close()
        with self.lock:
            sessions = list(self.sessions)
            workers = list(self.threads)
        for connection in sessions:
            with suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
        deadline = time.monotonic() + self.connect_timeout + 0.5
        for worker in workers:
            if worker is not threading.current_thread():
                worker.join(timeout=max(0, deadline - time.monotonic()))
        if self.shadow_fd is not None:
            for name, identity in self.created.items():
                with suppress(OSError):
                    if _identity(os.stat(name, dir_fd=self.shadow_fd,
                                         follow_symlinks=False)) == identity:
                        os.unlink(name, dir_fd=self.shadow_fd)
            os.close(self.shadow_fd)
            self.shadow_fd = None
            if self.created_directory:
                with suppress(OSError):
                    self.shadow.rmdir()
        if self.source_fd is not None:
            os.close(self.source_fd)
            self.source_fd = None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--shadow", type=Path, required=True)
    parser.add_argument("--uid", type=int, default=1010)
    parser.add_argument("--gid", type=int, default=1010)
    parser.add_argument("--max-sessions", type=int, default=64)
    parser.add_argument("--idle-timeout", type=float, default=1800.0)
    parser.add_argument("--connect-timeout", type=float, default=5.0)
    args = parser.parse_args()
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    bridge = SSHShadow(args.source, args.shadow, uid=args.uid, gid=args.gid,
                       max_sessions=args.max_sessions, idle_timeout=args.idle_timeout,
                       connect_timeout=args.connect_timeout)
    try:
        proof = bridge.prepare()
        print(json.dumps(proof, sort_keys=True), flush=True)
        bridge.serve(stop)
    except (ValueError, OSError) as error:
        parser.exit(1, f"SSH shadow refused: {type(error).__name__}\n")
    finally:
        bridge.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
