"""Private recovery checkpoints for application files; no automatic cleanup policy."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import tarfile
import uuid


def checkpoint(apps: Path, archive_root: Path, *, label="manual", quiesced=False) -> dict:
    if apps.is_symlink() or archive_root.is_symlink() or not apps.is_dir():
        raise ValueError("checkpoint roots must be real directories")
    if archive_root.resolve().is_relative_to(apps.resolve()):
        raise ValueError("archive directory must be outside application state")
    archive_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    archive_root.chmod(0o700)
    name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    temporary = archive_root / (name + ".partial")
    destination = archive_root / name
    temporary.mkdir(mode=0o700)
    files, skipped, changed = [], [], []
    with tarfile.open(temporary / "apps.tar.gz", "w:gz") as archive:
        for directory, dirs, names in os.walk(apps, followlinks=False):
            archive.add(directory, arcname=str(Path(directory).relative_to(apps)), recursive=False)
            for leaf in list(dirs):
                path = Path(directory) / leaf
                if path.is_symlink():
                    archive.add(path, arcname=str(path.relative_to(apps)), recursive=False)
                    dirs.remove(leaf)
            for leaf in names:
                path = Path(directory) / leaf
                before = path.lstat()
                relative = str(path.relative_to(apps))
                if stat.S_ISLNK(before.st_mode):
                    archive.add(path, arcname=relative, recursive=False)
                elif stat.S_ISREG(before.st_mode):
                    digest = hashlib.sha256()
                    with path.open("rb") as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(block)
                    archive.add(path, arcname=relative, recursive=False)
                    after = path.stat()
                    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                        changed.append(relative)
                    files.append({"path": relative, "size": before.st_size, "sha256": digest.hexdigest()})
                else:
                    skipped.append(relative)
    result = {"schema_version": 1, "label": label, "source": str(apps), "path": str(destination),
              "files": files, "skipped_runtime_objects": skipped, "changed_during_checkpoint": changed,
              "consistent": quiesced and not changed, "application_quiesced": quiesced, "private_contains_account_state": True}
    (temporary / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
    for path in temporary.iterdir():
        path.chmod(0o600)
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
    os.replace(temporary, destination)
    return result
