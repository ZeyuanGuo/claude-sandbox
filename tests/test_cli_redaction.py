from controlled_dev_machine.cli import _redacted_path, _safe_record
from controlled_dev_machine.review import ReviewRecord


def test_redacted_path_removes_all_query_values() -> None:
    secret = "query-secret-value"
    rendered = _redacted_path(f"/v1/messages?access_token={secret}&beta=true")

    assert rendered == "/v1/messages?<redacted:2>"
    assert secret not in rendered


def test_safe_record_removes_query_values_and_content_type_parameters() -> None:
    record = ReviewRecord(
        request_id="0" * 32,
        state="pending",
        created_at="2026-07-28T00:00:00Z",
        updated_at="2026-07-28T00:00:00Z",
        review_expires_at="2026-07-28T00:05:00Z",
        decision_expires_at=None,
        policy_digest="1" * 64,
        request_sha256="2" * 64,
        body_sha256="3" * 64,
        body_size=10,
        scheme="https",
        host="example.test",
        port=443,
        method="POST",
        path="/upload?token=private",
        header_names=("content-type",),
        content_type="multipart/form-data; boundary=private-boundary",
        reason=None,
    )

    rendered = _safe_record(record)

    assert rendered["path"] == "/upload?<redacted:1>"
    assert rendered["content_type"] == "multipart/form-data"
    assert "request_sha256" not in rendered
    assert "private" not in str(rendered)
