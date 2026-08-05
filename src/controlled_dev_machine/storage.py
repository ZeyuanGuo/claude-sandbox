from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from controlled_dev_machine.config import HostConfig, StorageThreshold


@dataclass(frozen=True)
class FilesystemReport:
    configured_path: str
    probed_path: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    required_free_bytes: int
    sufficient: bool


@dataclass(frozen=True)
class RegisteredPathReport:
    path: str
    exists: bool
    size_bytes: int | None
    error: str | None


@dataclass(frozen=True)
class StorageReport:
    root: FilesystemReport
    audit: FilesystemReport
    registered_paths: tuple[RegisteredPathReport, ...]
    docker_socket: str
    docker_inspection_available: bool
    docker_report: str | None
    cleanup_candidates: tuple[str, ...]

    def as_json(self) -> dict[str, object]:
        return asdict(self)


def build_storage_report(config: HostConfig) -> StorageReport:
    paths = (config.paths.persistent_home, config.paths.state, config.paths.audit)
    registered = tuple(_registered_path(path) for path in paths)
    socket_access = os.access(config.docker.socket, os.R_OK | os.W_OK)
    docker_report = _docker_report(config) if socket_access else None
    return StorageReport(
        root=_filesystem_report(Path("/"), config.storage.root),
        audit=_filesystem_report(config.paths.audit, config.storage.audit),
        registered_paths=registered,
        docker_socket=str(config.docker.socket),
        docker_inspection_available=socket_access,
        docker_report=docker_report,
        cleanup_candidates=(),
    )


def _filesystem_report(path: Path, threshold: StorageThreshold) -> FilesystemReport:
    probe = _existing_ancestor(path)
    usage = shutil.disk_usage(probe)
    required = threshold.required_free_bytes(usage.total)
    return FilesystemReport(
        configured_path=str(path),
        probed_path=str(probe),
        total_bytes=usage.total,
        used_bytes=usage.used,
        free_bytes=usage.free,
        required_free_bytes=required,
        sufficient=usage.free >= required,
    )


def _registered_path(path: Path) -> RegisteredPathReport:
    if not path.exists():
        return RegisteredPathReport(str(path), False, 0, None)
    result = subprocess.run(
        ["du", "-sx", "--bytes", "--", str(path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or f"du exited {result.returncode}"
        return RegisteredPathReport(str(path), True, None, message)
    size_text = result.stdout.split(maxsplit=1)[0]
    try:
        size = int(size_text)
    except ValueError:
        return RegisteredPathReport(str(path), True, None, "du output is not numeric")
    return RegisteredPathReport(str(path), True, size, None)


def _docker_report(config: HostConfig) -> str:
    result = subprocess.run(
        ["docker", "system", "df", "-v"],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "DOCKER_HOST": f"unix://{config.docker.socket}"},
    )
    return result.stdout if result.returncode == 0 else result.stderr


def _existing_ancestor(path: Path) -> Path:
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return probe

