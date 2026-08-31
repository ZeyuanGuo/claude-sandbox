from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from os import geteuid as _geteuid
from pathlib import Path

from controlled_dev_machine.config import HostConfig, StorageThreshold
from controlled_dev_machine.errors import DeploymentError
from controlled_dev_machine.runtime import _lifecycle_lock


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


@dataclass(frozen=True)
class RotationResult:
    active_run_id: str | None
    deleted: tuple[dict[str, object], ...]
    skipped: tuple[dict[str, object], ...]
    bytes_freed: int

    def as_json(self) -> dict[str, object]:
        return asdict(self)


_RUN_ID_RE = re.compile(r"^(\d{8}T\d{6}\.\d{6}Z)-[0-9a-f]{8}$")
_ARCHIVE_NAME_RE = re.compile(r"^(\d{8}T\d{6}\.\d{6}Z)-[0-9a-f]{16}\.mitm$")


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


def rotate_audit(config: HostConfig, *, now: datetime | None = None) -> RotationResult:
    """Delete only closed, expired audit artifacts owned by this instance."""
    if _geteuid() != 0:
        raise DeploymentError("审计轮转需要宿主提权")
    audit = config.paths.audit
    pcap_root = audit / "pcap"
    structured_root = audit / "structured"
    plaintext_archive = audit / "plaintext" / "archive"
    for root in (audit, pcap_root, structured_root, plaintext_archive):
        if root.is_symlink() or (root.exists() and not root.is_dir()):
            raise DeploymentError(f"审计目录类型异常，拒绝清理: {root}")

    active_run_id = _active_run_id(config)
    with _lifecycle_lock(config):
        current = now or datetime.now(UTC)
        deleted: list[dict[str, object]] = []
        skipped: list[dict[str, object]] = []
        bytes_freed = 0
        for root, retention, kind in (
            (
                pcap_root,
                timedelta(hours=config.storage.pcap_retention_hours),
                "pcap",
            ),
            (
                structured_root,
                timedelta(days=config.storage.structured_retention_days),
                "structured",
            ),
        ):
            freed, removed, ignored = _rotate_run_directories(
                root,
                current - retention,
                active_run_id,
                kind,
            )
            bytes_freed += freed
            deleted.extend(removed)
            skipped.extend(ignored)
        freed, removed, ignored = _rotate_plaintext_archive(
            plaintext_archive,
            current - timedelta(hours=config.storage.plaintext_retention_hours),
        )
        bytes_freed += freed
        deleted.extend(removed)
        skipped.extend(ignored)
        return RotationResult(active_run_id, tuple(deleted), tuple(skipped), bytes_freed)


def _active_run_id(config: HostConfig) -> str | None:
    path = config.paths.state / "audit-active.json"
    if not path.exists():
        if _project_running(config):
            raise DeploymentError("环境正在运行但缺少审计运行清单，拒绝自动清理")
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise DeploymentError(f"审计运行清单损坏，拒绝自动清理: {path}") from exc
    run_id = raw.get("run_id") if isinstance(raw, dict) else None
    if not isinstance(run_id, str) or _RUN_ID_RE.fullmatch(run_id) is None:
        raise DeploymentError(f"审计运行清单缺少有效 run_id，拒绝自动清理: {path}")
    return run_id


def _project_running(config: HostConfig) -> bool:
    result = subprocess.run(
        [
            "docker",
            "--host",
            f"unix://{config.docker.socket}",
            "ps",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={config.resource_prefix}",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise DeploymentError(f"无法确认环境是否运行，拒绝自动清理: {result.stderr.strip()}")
    return bool(result.stdout.strip())


def _rotate_run_directories(
    root: Path,
    cutoff: datetime,
    active_run_id: str | None,
    kind: str,
) -> tuple[int, list[dict[str, object]], list[dict[str, object]]]:
    if not root.exists():
        return 0, [], []
    removed: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    bytes_freed = 0
    for path in sorted(root.iterdir()):
        if path.is_symlink() or not path.is_dir():
            skipped.append({"path": str(path), "reason": "不是普通运行目录"})
            continue
        run_id = path.name
        timestamp = _run_id_timestamp(run_id)
        if timestamp is None:
            skipped.append({"path": str(path), "reason": "运行编号格式无法确认"})
            continue
        if run_id == active_run_id:
            skipped.append({"path": str(path), "reason": "当前运行"})
            continue
        if timestamp >= cutoff:
            skipped.append({"path": str(path), "reason": "仍在保留期内"})
            continue
        size = _tree_size(path)
        shutil.rmtree(path)
        removed.append({"path": str(path), "kind": kind, "bytes": size})
        bytes_freed += size
    return bytes_freed, removed, skipped


def _rotate_plaintext_archive(
    root: Path, cutoff: datetime
) -> tuple[int, list[dict[str, object]], list[dict[str, object]]]:
    if not root.exists():
        return 0, [], []
    removed: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    bytes_freed = 0
    for path in sorted(root.iterdir()):
        if path.is_symlink() or not path.is_file():
            skipped.append({"path": str(path), "reason": "不是普通明文归档文件"})
            continue
        match = _ARCHIVE_NAME_RE.fullmatch(path.name)
        if match is None:
            skipped.append({"path": str(path), "reason": "归档文件名无法确认"})
            continue
        timestamp = _parse_timestamp(match.group(1))
        if timestamp >= cutoff:
            skipped.append({"path": str(path), "reason": "仍在保留期内"})
            continue
        size = path.stat().st_size
        path.unlink()
        removed.append({"path": str(path), "kind": "plaintext", "bytes": size})
        bytes_freed += size
    return bytes_freed, removed, skipped


def _run_id_timestamp(run_id: str) -> datetime | None:
    match = _RUN_ID_RE.fullmatch(run_id)
    return _parse_timestamp(match.group(1)) if match else None


def _parse_timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y%m%dT%H%M%S.%fZ").replace(tzinfo=UTC)


def _tree_size(root: Path) -> int:
    total = 0
    for directory, dir_names, file_names in os.walk(root, followlinks=False):
        for name in (*dir_names, *file_names):
            path = Path(directory) / name
            try:
                if path.is_symlink():
                    raise DeploymentError(f"审计目录包含符号链接，拒绝清理: {path}")
                total += path.stat().st_size
            except OSError as exc:
                raise DeploymentError(f"无法读取审计对象大小，拒绝清理: {path}") from exc
    return total
