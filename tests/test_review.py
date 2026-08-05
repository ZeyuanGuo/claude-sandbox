import errno
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from controlled_dev_machine.errors import ReviewError
from controlled_dev_machine.review import RequestStore

POLICY_DIGEST = "a" * 64


def _pending(store: RequestStore, now: datetime):
    return store.enqueue(
        policy_digest=POLICY_DIGEST,
        scheme="https",
        host="Example.COM.",
        port=443,
        method="post",
        path="/v1/messages?test=1",
        headers={"Content-Type": "application/json", "Authorization": "secret"},
        body=b'{"message":"hello"}',
        now=now,
    )


def test_approval_is_bound_to_exact_request_and_policy(tmp_path: Path) -> None:
    now = datetime(2026, 7, 28, tzinfo=UTC)
    store = RequestStore(tmp_path / "review")
    pending = _pending(store, now)
    approved = store.approve_once(
        pending.request_id, ttl_seconds=60, reason="controlled test", now=now
    )
    assert approved.state == "approved_once"

    with pytest.raises(ReviewError, match="正文或元数据已经变化"):
        store.consume_approval(
            pending.request_id,
            request_sha256="b" * 64,
            policy_digest=POLICY_DIGEST,
            now=now,
        )

    authorized = store.consume_approval(
        pending.request_id,
        request_sha256=pending.request_sha256,
        policy_digest=POLICY_DIGEST,
        now=now,
    )
    assert authorized.state == "authorized"
    completed = store.mark_completed(pending.request_id, now=now)
    assert completed.state == "completed"


def test_client_disconnect_ends_pending_review(tmp_path: Path) -> None:
    now = datetime(2026, 7, 28, tzinfo=UTC)
    store = RequestStore(tmp_path / "review")
    pending = _pending(store, now)
    disconnected = store.mark_client_disconnected(pending.request_id, now=now)
    assert disconnected.state == "client_disconnected"
    with pytest.raises(ReviewError, match="pending"):
        store.approve_once(
            pending.request_id, ttl_seconds=60, reason="too late", now=now
        )


def test_expired_approval_cannot_be_used(tmp_path: Path) -> None:
    now = datetime(2026, 7, 28, tzinfo=UTC)
    store = RequestStore(tmp_path / "review")
    pending = _pending(store, now)
    store.approve_once(pending.request_id, ttl_seconds=1, reason="test", now=now)
    with pytest.raises(ReviewError, match="已经过期"):
        store.consume_approval(
            pending.request_id,
            request_sha256=pending.request_sha256,
            policy_digest=POLICY_DIGEST,
            now=now + timedelta(seconds=2),
        )
    assert store.get(pending.request_id).state == "expired"


def test_fail_closed_revokes_an_unconsumed_approval(tmp_path: Path) -> None:
    now = datetime(2026, 7, 28, tzinfo=UTC)
    store = RequestStore(tmp_path / "review")
    pending = _pending(store, now)
    store.approve_once(pending.request_id, ttl_seconds=60, reason="test", now=now)
    blocked = store.fail_closed(
        pending.request_id,
        reason="policy unavailable before authorization",
        now=now,
    )
    assert blocked.state == "blocked"
    assert blocked.decision_expires_at is None


def test_authorized_request_keeps_uncertain_dispatch_as_a_distinct_outcome(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 7, 28, tzinfo=UTC)
    store = RequestStore(tmp_path / "review")
    pending = _pending(store, now)
    store.approve_once(pending.request_id, ttl_seconds=60, reason="test", now=now)
    store.consume_approval(
        pending.request_id,
        request_sha256=pending.request_sha256,
        policy_digest=POLICY_DIGEST,
        now=now,
    )

    with pytest.raises(ReviewError, match="authorized"):
        store.fail_closed(pending.request_id, reason="too late", now=now)
    uncertain = store.mark_dispatch_unknown(
        pending.request_id, reason="dispatch failed", now=now
    )
    assert uncertain.state == "dispatch_unknown"


def test_writable_probe_detects_disk_full_and_cleans_up(
    tmp_path: Path, monkeypatch
) -> None:
    store = RequestStore(tmp_path / "review")
    original_write = os.write

    def disk_full(descriptor: int, content: bytes) -> int:
        if content == b"controlled-review-health\n":
            raise OSError(errno.ENOSPC, "disk full")
        return original_write(descriptor, content)

    monkeypatch.setattr(os, "write", disk_full)
    with pytest.raises(OSError) as error:
        store.probe_writable()
    assert error.value.errno == errno.ENOSPC
    assert not list(store.requests_dir.glob(".health-*"))


def test_raw_secrets_are_not_copied_into_metadata(tmp_path: Path) -> None:
    now = datetime(2026, 7, 28, tzinfo=UTC)
    store = RequestStore(tmp_path / "review")
    pending = _pending(store, now)
    record_text = (
        tmp_path / "review" / "requests" / pending.request_id / "record.json"
    ).read_text(encoding="utf-8")
    assert "secret" not in record_text
    assert set(pending.header_names) == {"authorization", "content-type"}
    assert (tmp_path / "review").stat().st_mode & 0o777 == 0o700


def test_duplicate_headers_are_preserved_in_raw_order(tmp_path: Path) -> None:
    store = RequestStore(tmp_path / "review")
    pending = store.enqueue(
        policy_digest=POLICY_DIGEST,
        scheme="https",
        host="example.com",
        port=443,
        method="GET",
        path="/",
        headers=(("Cookie", "a=1"), ("Cookie", "b=2")),
        body=b"",
    )
    headers, _ = store.raw(pending.request_id)
    assert headers == (("Cookie", "a=1"), ("Cookie", "b=2"))


def test_pending_review_expires_without_operator_action(tmp_path: Path) -> None:
    now = datetime(2026, 7, 28, tzinfo=UTC)
    store = RequestStore(tmp_path / "review")
    pending = store.enqueue(
        policy_digest=POLICY_DIGEST,
        scheme="https",
        host="example.com",
        port=443,
        method="GET",
        path="/",
        headers={},
        body=b"",
        review_ttl_seconds=1,
        now=now,
    )
    assert store.expire_due(now=now + timedelta(seconds=2)) == (pending.request_id,)
    assert store.get(pending.request_id).state == "expired"


def test_ip_review_accepts_explicit_nonstandard_port(tmp_path: Path) -> None:
    store = RequestStore(tmp_path / "review")
    pending = store.enqueue(
        policy_digest=POLICY_DIGEST,
        scheme="http",
        host="192.0.2.10",
        port=18680,
        method="POST",
        path="/v1/messages",
        headers={"Content-Type": "application/json"},
        body=b"{}",
    )
    assert pending.host == "192.0.2.10"
    assert pending.port == 18680


def test_domain_review_rejects_nonstandard_port(tmp_path: Path) -> None:
    store = RequestStore(tmp_path / "review")
    with pytest.raises(ReviewError, match="80/443"):
        store.enqueue(
            policy_digest=POLICY_DIGEST,
            scheme="http",
            host="example.com",
            port=18680,
            method="GET",
            path="/",
            headers={},
            body=b"",
        )
