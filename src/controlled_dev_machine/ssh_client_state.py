"""Refresh a same-host SSH client directory without remounting a container.

Only regular files are copied. Host control sockets are never exposed. The target mounts this directory read-only and uses the audited bridge.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import stat
import uuid

from .ssh_alias_bridge import target_config


def atomic_file(path: Path, data: bytes, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("SSH client destination must not be a symlink")
    if path.exists() and path.read_bytes() == data:
        path.chmod(mode)
        return
    temporary = path.with_name('.cdm-new-' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class SSHClientState:
    def __init__(self, source: Path, destination: Path, target_home: Path):
        self.source, self.destination, self.target_home = source, destination, target_home
        self.previous = None

    def refresh(self):
        if self.source.is_symlink() or self.destination.is_symlink():
            raise ValueError("SSH directory roots must not be symlinks")
        self.destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.destination.chmod(0o700)
        with (self.destination / '.cdm-sync.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            files, signature = {}, []
            for directory, dirs, names in os.walk(self.source, followlinks=False):
                dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
                for name in sorted(names):
                    path = Path(directory) / name
                    try:
                        info = path.stat()
                    except FileNotFoundError:
                        continue
                    if not stat.S_ISREG(info.st_mode):
                        continue
                    relative = str(path.relative_to(self.source))
                    if relative.startswith('.cdm-'):
                        continue
                    files[relative] = path
                    signature.append((relative, info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
            signature.sort()
            if signature == self.previous:
                return False
            # Render before touching the last usable snapshot. Invalid source
            # configuration leaves existing connections/configuration intact.
            rendered = target_config(self.source / 'config', '/run/cdm-ssh/alias.sock',
                                     '/run/cdm-ssh/campus-agent.sock', target_home=self.target_home)
            manifest = self.destination / '.cdm-managed.json'
            previous = json.loads(manifest.read_text()) if manifest.exists() else []
            current = sorted(set(files) | {'config'})
            for name, source in files.items():
                if name != 'config':
                    atomic_file(self.destination / name, source.read_bytes())
            atomic_file(self.destination / 'config', rendered.encode())
            for name in set(previous) - set(current):
                path = Path(name)
                if path.is_absolute() or '..' in path.parts:
                    raise ValueError('invalid SSH client manifest')
                (self.destination / path).unlink(missing_ok=True)
            atomic_file(manifest, (json.dumps(current) + '\n').encode())
            self.previous = signature
            return True
