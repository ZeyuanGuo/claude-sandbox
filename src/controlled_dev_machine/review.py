from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from controlled_dev_machine.errors import ReviewError
from controlled_dev_machine.policy import PolicyError, canonical_domain

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")


@dataclass(frozen=True)
class ReviewRecord:
    request_id: str
    state: str
    created_at: str
    updated_at: str
    review_expires_at: str
    decision_expires_at: str | None
    policy_digest: str
    request_sha256: str
    body_sha256: str
    body_size: int
    scheme: str
    host: str
    port: int
    method: str
    path: str
    header_names: tuple[str, ...]
    content_type: str | None
    reason: str | None


class RequestStore:
    def __init__(self, root: Path):
        self.root = root
        self.requests_dir = root / "requests"
        self.lock_path = root / ".lock"

    def initialize(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.requests_dir.mkdir(mode=0o700, exist_ok=True)
        _inherit_owner(self.requests_dir, self.root)
        os.chmod(self.requests_dir, 0o700)

    def probe_writable(self) -> None:
        """Verify that the request directory accepts a complete durable write."""
        self.initialize()
        path = self.requests_dir / f".health-{uuid.uuid4().hex}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            if os.write(descriptor, b"controlled-review-health\n") != 25:
                raise ReviewError("审核目录健康写入不完整")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
            path.unlink(missing_ok=True)

    def enqueue(
        self,
        *,
        policy_digest: str,
        scheme: str,
        host: str,
        port: int,
        method: str,
        path: str,
        headers: Mapping[str, str] | Sequence[tuple[str, str]],
        body: bytes,
        review_ttl_seconds: int = 300,
        now: datetime | None = None,
    ) -> ReviewRecord:
        if review_ttl_seconds < 1 or review_ttl_seconds > 3600:
            raise ReviewError("请求审核期限必须在 1 到 3600 秒之间")
        self.initialize()
        header_items = _normalize_headers(headers)
        normalized = _request_fields(
            policy_digest=policy_digest,
            scheme=scheme,
            host=host,
            port=port,
            method=method,
            path=path,
            headers=header_items,
            body=body,
        )
        current = _utc(now)
        request_id = uuid.uuid4().hex
        request_dir = self.requests_dir / request_id
        request_dir.mkdir(mode=0o700)
        _inherit_owner(request_dir, self.requests_dir)
        body_sha256 = hashlib.sha256(body).hexdigest()
        fingerprint_payload = {
            "policy_digest": normalized["policy_digest"],
            "scheme": normalized["scheme"],
            "host": normalized["host"],
            "port": normalized["port"],
            "method": normalized["method"],
            "path": normalized["path"],
            "headers": sorted((key.lower(), value) for key, value in header_items),
            "body_sha256": body_sha256,
        }
        request_sha256 = hashlib.sha256(
            json.dumps(
                fingerprint_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
        ).hexdigest()
        content_type = next(
            (value for key, value in header_items if key.lower() == "content-type"), None
        )
        timestamp = current.isoformat().replace("+00:00", "Z")
        record = ReviewRecord(
            request_id=request_id,
            state="pending",
            created_at=timestamp,
            updated_at=timestamp,
            review_expires_at=_format_time(
                current + timedelta(seconds=review_ttl_seconds)
            ),
            decision_expires_at=None,
            policy_digest=normalized["policy_digest"],
            request_sha256=request_sha256,
            body_sha256=body_sha256,
            body_size=len(body),
            scheme=normalized["scheme"],
            host=normalized["host"],
            port=normalized["port"],
            method=normalized["method"],
            path=normalized["path"],
            header_names=tuple(sorted({key.lower() for key, _ in header_items})),
            content_type=content_type,
            reason=None,
        )
        try:
            _write_bytes(request_dir / "body.bin", body)
            _write_json(request_dir / "headers.json", header_items)
            _write_json(request_dir / "record.json", asdict(record))
        except Exception:
            for child in ("record.json", "headers.json", "body.bin"):
                (request_dir / child).unlink(missing_ok=True)
            request_dir.rmdir()
            raise
        return record

    def list_records(self) -> tuple[ReviewRecord, ...]:
        self.initialize()
        records: list[ReviewRecord] = []
        with self._locked():
            for item in sorted(self.requests_dir.iterdir()):
                if item.is_dir() and _REQUEST_ID_RE.fullmatch(item.name):
                    records.append(self._read(item.name))
        return tuple(records)

    def get(self, request_id: str) -> ReviewRecord:
        _validate_request_id(request_id)
        with self._locked():
            return self._read(request_id)

    def raw(self, request_id: str) -> tuple[tuple[tuple[str, str], ...], bytes]:
        _validate_request_id(request_id)
        with self._locked():
            request_dir = self.requests_dir / request_id
            self._read(request_id)
            headers = json.loads((request_dir / "headers.json").read_text(encoding="utf-8"))
            if not isinstance(headers, list):
                raise ReviewError("原始请求头文件损坏")
            try:
                normalized_headers = tuple((str(item[0]), str(item[1])) for item in headers)
            except (IndexError, TypeError) as exc:
                raise ReviewError("原始请求头文件损坏") from exc
            return normalized_headers, (request_dir / "body.bin").read_bytes()

    def approve_once(
        self,
        request_id: str,
        *,
        ttl_seconds: int,
        reason: str,
        now: datetime | None = None,
    ) -> ReviewRecord:
        if ttl_seconds < 1 or ttl_seconds > 300:
            raise ReviewError("单次批准有效期必须在 1 到 300 秒之间")
        if not reason.strip():
            raise ReviewError("批准必须记录理由")
        current = _utc(now)
        with self._locked():
            record = self._read(request_id)
            self._require_pending(record, current)
            return self._replace(
                record,
                state="approved_once",
                updated_at=_format_time(current),
                decision_expires_at=_format_time(current + timedelta(seconds=ttl_seconds)),
                reason=reason.strip(),
            )

    def reject(
        self, request_id: str, *, reason: str, now: datetime | None = None
    ) -> ReviewRecord:
        if not reason.strip():
            raise ReviewError("拒绝必须记录理由")
        current = _utc(now)
        with self._locked():
            record = self._read(request_id)
            self._require_pending(record, current)
            return self._replace(
                record,
                state="blocked",
                updated_at=_format_time(current),
                decision_expires_at=None,
                reason=reason.strip(),
            )

    def fail_closed(
        self, request_id: str, *, reason: str, now: datetime | None = None
    ) -> ReviewRecord:
        if not reason.strip():
            raise ReviewError("失败关闭必须记录理由")
        current = _utc(now)
        with self._locked():
            record = self._read(request_id)
            if record.state not in {"pending", "approved_once"}:
                raise ReviewError(f"失败关闭状态不能从 {record.state} 产生")
            return self._replace(
                record,
                state="blocked",
                updated_at=_format_time(current),
                decision_expires_at=None,
                reason=reason.strip(),
            )

    def consume_approval(
        self,
        request_id: str,
        *,
        request_sha256: str,
        policy_digest: str,
        now: datetime | None = None,
    ) -> ReviewRecord:
        current = _utc(now)
        with self._locked():
            record = self._read(request_id)
            if record.state != "approved_once":
                raise ReviewError(f"请求状态不是 approved_once: {record.state}")
            if _parse_time(record.decision_expires_at) <= current:
                self._replace(
                    record,
                    state="expired",
                    updated_at=_format_time(current),
                    decision_expires_at=None,
                    reason="approval expired",
                )
                raise ReviewError("单次批准已经过期")
            if request_sha256 != record.request_sha256:
                raise ReviewError("请求正文或元数据已经变化，拒绝复用批准")
            if policy_digest != record.policy_digest:
                raise ReviewError("策略版本已经变化，拒绝复用批准")
            return self._replace(
                record,
                state="authorized",
                updated_at=_format_time(current),
                decision_expires_at=None,
                reason=record.reason,
            )

    def mark_completed(
        self, request_id: str, *, now: datetime | None = None
    ) -> ReviewRecord:
        return self._mark_outcome(request_id, "completed", "upstream response completed", now)

    def mark_upstream_error(
        self, request_id: str, *, reason: str, now: datetime | None = None
    ) -> ReviewRecord:
        return self._mark_outcome(request_id, "upstream_error", reason, now)

    def mark_dispatch_unknown(
        self, request_id: str, *, reason: str, now: datetime | None = None
    ) -> ReviewRecord:
        return self._mark_outcome(request_id, "dispatch_unknown", reason, now)

    def mark_client_disconnected(
        self, request_id: str, *, now: datetime | None = None
    ) -> ReviewRecord:
        current = _utc(now)
        with self._locked():
            record = self._read(request_id)
            if record.state not in {"pending", "approved_once"}:
                raise ReviewError(f"断连状态不能从 {record.state} 产生")
            return self._replace(
                record,
                state="client_disconnected",
                updated_at=_format_time(current),
                decision_expires_at=None,
                reason="client disconnected before authorization",
            )

    def expire_due(self, *, now: datetime | None = None) -> tuple[str, ...]:
        current = _utc(now)
        expired: list[str] = []
        with self._locked():
            for item in sorted(self.requests_dir.iterdir()):
                if not item.is_dir() or not _REQUEST_ID_RE.fullmatch(item.name):
                    continue
                record = self._read(item.name)
                deadline = (
                    _parse_time(record.decision_expires_at)
                    if record.decision_expires_at
                    else None
                )
                if record.state == "approved_once" and deadline is not None and deadline <= current:
                    self._replace(
                        record,
                        state="expired",
                        updated_at=_format_time(current),
                        decision_expires_at=None,
                        reason="approval expired",
                    )
                    expired.append(record.request_id)
                elif record.state == "pending" and _parse_time(record.review_expires_at) <= current:
                    self._replace(
                        record,
                        state="expired",
                        updated_at=_format_time(current),
                        decision_expires_at=None,
                        reason="review timed out",
                    )
                    expired.append(record.request_id)
        return tuple(expired)

    def _require_pending(self, record: ReviewRecord, now: datetime) -> None:
        if record.state != "pending":
            raise ReviewError(f"请求状态不是 pending: {record.state}")
        if _parse_time(record.review_expires_at) <= now:
            self._replace(
                record,
                state="expired",
                updated_at=_format_time(now),
                decision_expires_at=None,
                reason="review timed out",
            )
            raise ReviewError("请求审核已经超时")
        if _parse_time(record.created_at) > now + timedelta(seconds=5):
            raise ReviewError("请求时间在未来，拒绝处理")

    def _mark_outcome(
        self,
        request_id: str,
        state: str,
        reason: str,
        now: datetime | None,
    ) -> ReviewRecord:
        current = _utc(now)
        with self._locked():
            record = self._read(request_id)
            if record.state != "authorized":
                raise ReviewError(f"上游结果不能从 {record.state} 产生")
            return self._replace(
                record,
                state=state,
                updated_at=_format_time(current),
                decision_expires_at=None,
                reason=reason.strip() or state,
            )

    def _read(self, request_id: str) -> ReviewRecord:
        _validate_request_id(request_id)
        path = self.requests_dir / request_id / "record.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ReviewError(f"审核请求不存在: {request_id}") from exc
        except json.JSONDecodeError as exc:
            raise ReviewError(f"审核记录损坏: {request_id}") from exc
        try:
            raw["header_names"] = tuple(raw["header_names"])
            return ReviewRecord(**raw)
        except (KeyError, TypeError) as exc:
            raise ReviewError(f"审核记录字段损坏: {request_id}") from exc

    def _replace(self, record: ReviewRecord, **changes: Any) -> ReviewRecord:
        values = asdict(record)
        values.update(changes)
        values["header_names"] = tuple(values["header_names"])
        updated = ReviewRecord(**values)
        record_path = self.requests_dir / record.request_id / "record.json"
        _write_json(record_path, asdict(updated), replace=True)
        return updated

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.initialize()
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            _inherit_descriptor_owner(descriptor, self.root)
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def _request_fields(**values: Any) -> dict[str, Any]:
    policy_digest = values["policy_digest"]
    if not isinstance(policy_digest, str) or not _SHA256_RE.fullmatch(policy_digest):
        raise ReviewError("policy_digest 必须是 SHA-256")
    scheme = values["scheme"]
    if scheme not in {"http", "https"}:
        raise ReviewError("scheme 只允许 http/https")
    raw_host = values["host"]
    if not isinstance(raw_host, str) or not raw_host:
        raise ReviewError("host 必须是非空字符串")
    try:
        host = str(ipaddress.ip_address(raw_host))
    except ValueError:
        try:
            host = canonical_domain(raw_host)
        except PolicyError as exc:
            raise ReviewError(str(exc)) from exc
        is_ip = False
    else:
        is_ip = True
    port = values["port"]
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ReviewError("端口必须在 1 到 65535 之间")
    if not is_ip and port not in {80, 443}:
        raise ReviewError("域名审核队列当前只接受 80/443")
    method = values["method"]
    if not isinstance(method, str) or not re.fullmatch(r"[A-Z]+", method.upper()):
        raise ReviewError("HTTP 方法格式无效")
    path = values["path"]
    if not isinstance(path, str) or not path.startswith("/"):
        raise ReviewError("请求路径必须以 / 开头")
    headers = values["headers"]
    _normalize_headers(headers)
    body = values["body"]
    if not isinstance(body, bytes):
        raise ReviewError("请求正文必须是 bytes")
    return {
        "policy_digest": policy_digest,
        "scheme": scheme,
        "host": host,
        "port": port,
        "method": method.upper(),
        "path": path,
    }


def _normalize_headers(
    headers: Mapping[str, str] | Sequence[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    items = tuple(headers.items()) if isinstance(headers, Mapping) else tuple(headers)
    if not all(
        isinstance(item, tuple)
        and len(item) == 2
        and isinstance(item[0], str)
        and isinstance(item[1], str)
        and item[0]
        for item in items
    ):
        raise ReviewError("请求头必须是字符串键值对")
    return items


def _write_json(path: Path, value: Any, *, replace: bool = False) -> None:
    payload = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()
    _write_bytes(path, payload, replace=replace)


def _write_bytes(path: Path, payload: bytes, *, replace: bool = False) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _inherit_descriptor_owner(descriptor, path.parent)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if not replace and path.exists():
            raise ReviewError(f"拒绝覆盖已有文件: {path}")
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _inherit_owner(path: Path, parent: Path) -> None:
    owner = parent.stat()
    current = path.stat()
    if (current.st_uid, current.st_gid) != (owner.st_uid, owner.st_gid):
        os.chown(path, owner.st_uid, owner.st_gid)


def _inherit_descriptor_owner(descriptor: int, parent: Path) -> None:
    owner = parent.stat()
    current = os.fstat(descriptor)
    if (current.st_uid, current.st_gid) != (owner.st_uid, owner.st_gid):
        os.fchown(descriptor, owner.st_uid, owner.st_gid)


def _validate_request_id(request_id: str) -> None:
    if not _REQUEST_ID_RE.fullmatch(request_id):
        raise ReviewError("request_id 格式无效")


def _utc(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ReviewError("时间必须包含时区")
    return current.astimezone(UTC)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_time(value: str | None) -> datetime:
    if value is None:
        raise ReviewError("记录缺少过期时间")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReviewError("记录包含无效时间") from exc
    if parsed.tzinfo is None:
        raise ReviewError("记录时间缺少时区")
    return parsed.astimezone(UTC)
