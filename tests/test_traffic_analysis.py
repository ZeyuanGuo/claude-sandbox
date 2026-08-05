import json

from controlled_dev_machine.traffic_analysis import analyze_review_payload


def test_analysis_reports_machine_indicators_without_raw_values() -> None:
    secret = "test-secret-value"
    body = json.dumps(
        {
            "model": "test-model",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "cwd=/home/alice/project TZ=UTC "
                        "host=devbox GPU=TEST_DEVICE\n"
                        "gitStatus:\nCurrent branch: main\nGit user: Alice\n"
                        "Recent commits:\nabc test commit"
                    ),
                }
            ],
            "metadata": {
                "user_id": json.dumps(
                    {
                        "device_id": "stable-client-id",
                        "account_uuid": "",
                        "session_id": "private-session-value",
                    }
                )
            },
        }
    ).encode()
    result = analyze_review_payload(
        {
            "X-Api-Key": secret,
            "Content-Type": "application/json",
            "X-Stainless-OS": "Linux",
            "X-Stainless-Arch": "x64",
            "X-Claude-Code-Session-Id": "private-session-value",
        },
        body,
        target_home="/home/alice",
        target_name="alice",
    )
    rendered = json.dumps(result, sort_keys=True)
    kinds = {item["kind"] for item in result["machine_indicators"]}

    assert result["headers"]["credential_header_names"] == ["x-api-key"]
    assert result["body"]["encoding"] == "json"
    assert {
        "timezone",
        "hostname",
        "gpu",
        "target_home",
        "client_identifier_field",
        "device_identifier_field",
        "account_identifier_field",
        "os_or_kernel",
        "os_header_field",
        "architecture_header_field",
        "session_identifier_header_field",
        "session_identifier_field",
        "project_git_snapshot",
        "project_git_branch",
        "project_git_identity",
        "project_git_history",
    } <= kinds
    assert next(
        field for field in result["headers"]["fields"] if field["name"] == "x-api-key"
    )["credential"] is True
    assert [
        field["key"] for field in result["body"]["embedded_client_metadata"]
    ] == ["account_uuid", "device_id", "session_id"]
    assert next(
        field
        for field in result["body"]["embedded_client_metadata"]
        if field["key"] == "device_id"
    )["length"] == len("stable-client-id")
    assert secret not in rendered
    assert "private-session-value" not in rendered
    assert "stable-client-id" not in rendered
    assert "TZ=UTC" not in rendered


def test_analysis_detects_machine_field_names_and_broader_values() -> None:
    body = json.dumps(
        {
            "timezone": "Europe/Berlin",
            "hostname": "cdm-target-a1b2",
            "platform": "Darwin",
            "arch": "aarch64",
            "ipv6": "2001:db8::1",
            "mac_address": "00:11:22:33:44:55",
            "cpu_model": "test processor",
            "note": "UTC+08:00",
        }
    ).encode()
    result = analyze_review_payload(
        {"Content-Type": "application/json", "Content-Encoding": "gzip"},
        body,
        target_home="/home/alice",
        target_name="alice",
    )
    kinds = {item["kind"] for item in result["machine_indicators"]}

    assert {
        "timezone_field",
        "hostname_field",
        "os_or_kernel_field",
        "architecture_field",
        "network_identifier_field",
        "cpu_field",
        "timezone",
        "os_or_kernel",
        "architecture",
        "ipv6",
        "mac_address",
    } <= kinds
    assert result["inspection_limitations"] == [
        "content_encoding_not_decoded",
        "machine_indicator_detection_is_heuristic",
    ]


def test_credential_header_has_no_value_hash() -> None:
    secret = "Bearer low-entropy"
    result = analyze_review_payload(
        {
            "Authorization": secret,
            "X-Auth-Token": secret,
            "X-AccessToken": secret,
            "X-AuthToken": secret,
            "X-CSRFToken": secret,
            "X-Goog-Api-Key": secret,
            "Api-Key": secret,
            "Content-Type": "application/json",
        },
        b"{}",
        target_home="/home/alice",
        target_name="alice",
    )
    credentials = [
        field for field in result["headers"]["fields"] if field["credential"] is True
    ]

    assert {field["name"] for field in credentials} == {
        "api-key",
        "authorization",
        "x-accesstoken",
        "x-auth-token",
        "x-authtoken",
        "x-csrftoken",
        "x-goog-api-key",
    }
    assert all(set(field) == {"name", "credential"} for field in credentials)
    assert secret not in json.dumps(result)


def test_analysis_does_not_confuse_tool_pair_or_clock_with_timezone_or_ipv6() -> None:
    result = analyze_review_payload(
        {"Content-Type": "application/json"},
        json.dumps({"text": "Use Read/Write at 12:34:56"}).encode(),
        target_home="/home/alice",
        target_name="alice",
    )
    kinds = {item["kind"] for item in result["machine_indicators"]}

    assert "timezone" not in kinds
    assert "ipv6" not in kinds


def test_analysis_preserves_duplicate_json_keys_for_detection() -> None:
    result = analyze_review_payload(
        {"Content-Type": "application/json"},
        b'{"timezone":"Europe/Berlin","timezone":"redacted"}',
        target_home="/home/alice",
        target_name="alice",
    )
    timezone_fields = [
        item for item in result["machine_indicators"] if item["kind"] == "timezone_field"
    ]

    assert len(timezone_fields) == 2
    assert any(item["kind"] == "timezone" for item in result["machine_indicators"])


def test_analysis_detects_common_machine_key_variants_in_body_and_headers() -> None:
    result = analyze_review_payload(
        {"Content-Type": "application/json", "X-Hostname": "cdm-a1b2"},
        b'{"host":"cdm-a1b2","osVersion":"6.8","localIp":"10.0.0.2"}',
        target_home="/home/alice",
        target_name="alice",
    )
    kinds_by_source = {
        (item["kind"], item["source"]) for item in result["machine_indicators"]
    }

    assert ("hostname_field", "raw_body") in kinds_by_source
    assert ("os_or_kernel_field", "raw_body") in kinds_by_source
    assert ("network_identifier_field", "raw_body") in kinds_by_source
    assert ("hostname_field", "request_header") in kinds_by_source


def test_metadata_description_is_not_mislabeled_as_client_identifier() -> None:
    result = analyze_review_payload(
        {"Content-Type": "application/json"},
        b'{"metadata":{"description":"ordinary text"}}',
        target_home="/home/alice",
        target_name="alice",
    )

    assert not [
        item
        for item in result["machine_indicators"]
        if item["kind"] == "client_identifier_field"
    ]
