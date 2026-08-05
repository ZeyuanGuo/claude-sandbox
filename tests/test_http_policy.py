from pathlib import Path

from controlled_dev_machine.http_policy import HttpRequestView, evaluate_http_request
from controlled_dev_machine.policy import load_policy


def test_unknown_request_requires_review() -> None:
    policy = load_policy(Path("policies/strict/0001-bootstrap.yaml"))
    decision = evaluate_http_request(
        policy,
        HttpRequestView("https", "example.com", 443, "POST", "/v1", "application/json", 12),
    )
    assert decision.action == "review"


def test_direct_ip_is_blocked_before_review() -> None:
    policy = load_policy(Path("policies/strict/0001-bootstrap.yaml"))
    decision = evaluate_http_request(
        policy,
        HttpRequestView("https", "1.1.1.1", 443, "GET", "/", None, 0),
    )
    assert decision.action == "block"


def test_nonstandard_connect_port_is_blocked() -> None:
    policy = load_policy(Path("policies/strict/0001-bootstrap.yaml"))
    decision = evaluate_http_request(
        policy,
        HttpRequestView("https", "example.com", 8443, "GET", "/", None, 0),
    )
    assert decision.action == "block"


def test_daily_policy_allows_public_web_without_review() -> None:
    policy = load_policy(Path("policies/daily/0001-public-web.yaml"))
    decision = evaluate_http_request(
        policy,
        HttpRequestView("https", "docs.python.org", 443, "GET", "/3/", None, 0),
    )
    assert decision.action == "allow"
    assert decision.rule_id is None


def test_daily_policy_allows_normal_public_login_headers() -> None:
    policy = load_policy(Path("policies/daily/0001-public-web.yaml"))
    decision = evaluate_http_request(
        policy,
        HttpRequestView(
            "https",
            "accounts.example.com",
            443,
            "GET",
            "/session",
            None,
            0,
            sensitive_headers=("authorization", "cookie"),
        ),
    )
    assert decision.action == "allow"
    assert decision.rule_id is None


def test_daily_policy_blocks_special_use_names_and_direct_ips() -> None:
    policy = load_policy(Path("policies/daily/0001-public-web.yaml"))
    requests = (
        HttpRequestView("https", "metadata.google.internal", 443, "GET", "/", None, 0),
        HttpRequestView("https", "home.arpa", 443, "GET", "/", None, 0),
        HttpRequestView("https", "localhost", 443, "GET", "/", None, 0),
        HttpRequestView("https", "service.localhost", 443, "GET", "/", None, 0),
        HttpRequestView("https", "0177.0.0.1", 443, "GET", "/", None, 0),
        HttpRequestView("https", "127.1", 443, "GET", "/", None, 0),
        HttpRequestView("http", "169.254.169.254", 80, "GET", "/", None, 0),
        HttpRequestView("http", "192.168.1.1", 80, "GET", "/", None, 0),
    )
    assert all(evaluate_http_request(policy, request).action == "block" for request in requests)


def test_daily_policy_blacklist_cannot_be_bypassed_by_method_or_body() -> None:
    policy = load_policy(Path("policies/daily/0001-public-web.yaml"))
    decision = evaluate_http_request(
        policy,
        HttpRequestView(
            "https",
            "dns.google",
            443,
            "CUSTOM",
            "/dns-query",
            "application/octet-stream",
            10_000_000,
        ),
    )
    assert decision.action == "block"
    assert decision.rule_id == "block-google-doh"


def test_daily_policy_keeps_closed_gate_canary_under_review() -> None:
    policy = load_policy(Path("policies/daily/0001-public-web.yaml"))
    decision = evaluate_http_request(
        policy,
        HttpRequestView("https", "canary.test", 443, "POST", "/gate", None, 12),
    )
    assert decision.action == "review"
    assert decision.rule_id == "closed-gate-canary-review"


def test_exact_ip_rule_is_reviewed_but_other_ip_stays_blocked(tmp_path: Path) -> None:
    path = tmp_path / "exact-ip-review.yaml"
    path.write_text(
        """
schema_version: 1
policy_id: exact-ip-review
revision: 1
mode: strict
created_at: "2026-08-05T00:00:00Z"
parent_digest:
web_default: review
rules:
  - id: api-fixture
    priority: 1
    action: review
    purpose: "测试精确 IP 规则"
    domain_kind: ip
    domain: 192.0.2.10
    schemes: [http]
    ports: [18680]
    methods: [POST]
    path_prefixes: [/v1/messages]
    content_types: [application/json]
    body_max_bytes: 1024
    tls_identity_required: false
    plaintext_required: true
    evidence: local-fixture
""".lstrip(),
        encoding="utf-8",
    )
    policy = load_policy(path)
    approved_target = evaluate_http_request(
        policy,
        HttpRequestView(
            "http", "192.0.2.10", 18680, "POST", "/v1/messages", "application/json", 12
        ),
    )
    other_target = evaluate_http_request(
        policy,
        HttpRequestView("http", "192.0.2.11", 18680, "POST", "/", "application/json", 12),
    )
    assert approved_target.action == "review"
    assert approved_target.rule_id == "api-fixture"
    assert other_target.action == "block"


def test_exact_path_does_not_allow_query_or_suffix(tmp_path: Path) -> None:
    policy_path = tmp_path / "exact-path.yaml"
    policy_path.write_text(
        """
schema_version: 1
policy_id: exact-path
revision: 1
mode: strict
created_at: "2026-07-28T00:00:00Z"
parent_digest:
web_default: review
rules:
  - id: hello
    priority: 1
    action: allow
    purpose: fixed startup request
    domain_kind: exact
    domain: api.anthropic.com
    schemes: [https]
    ports: [443]
    methods: [GET]
    path_prefixes: [/api/hello]
    path_match: exact
    content_types: []
    body_max_bytes: 0
    tls_identity_required: true
    plaintext_required: true
    evidence: test
""".lstrip(),
        encoding="utf-8",
    )
    policy = load_policy(policy_path)

    exact = evaluate_http_request(
        policy,
        HttpRequestView("https", "api.anthropic.com", 443, "GET", "/api/hello", None, 0),
    )
    with_query = evaluate_http_request(
        policy,
        HttpRequestView(
            "https", "api.anthropic.com", 443, "GET", "/api/hello?data=x", None, 0
        ),
    )
    with_suffix = evaluate_http_request(
        policy,
        HttpRequestView(
            "https", "api.anthropic.com", 443, "GET", "/api/hello-more", None, 0
        ),
    )
    with_sensitive_header = evaluate_http_request(
        policy,
        HttpRequestView(
            "https",
            "api.anthropic.com",
            443,
            "GET",
            "/api/hello",
            None,
            0,
            sensitive_headers=("authorization",),
        ),
    )

    assert exact.action == "allow"
    assert with_query.action == "review"
    assert with_suffix.action == "review"
    assert with_sensitive_header.action == "review"


def test_rule_can_explicitly_allow_sensitive_headers(tmp_path: Path) -> None:
    path = tmp_path / "sensitive-header-rule.yaml"
    path.write_text(
        """
schema_version: 1
policy_id: sensitive-header-rule
revision: 1
mode: strict
created_at: "2026-08-05T00:00:00Z"
parent_digest:
web_default: review
rules:
  - id: api-fixture
    priority: 1
    action: allow
    purpose: "测试认证头显式放行"
    domain_kind: ip
    domain: 192.0.2.10
    schemes: [http]
    ports: [18680]
    methods: [POST]
    path_prefixes: [/v1/messages]
    content_types: [application/json]
    body_max_bytes: 1024
    allow_sensitive_headers: true
    tls_identity_required: false
    plaintext_required: true
    evidence: local-fixture
""".lstrip(),
        encoding="utf-8",
    )
    policy = load_policy(path)
    decision = evaluate_http_request(
        policy,
        HttpRequestView(
            "http",
            "192.0.2.10",
            18680,
            "POST",
            "/v1/messages",
            "application/json",
            12,
            sensitive_headers=("x-api-key",),
        ),
    )
    assert decision.action == "allow"
    assert decision.rule_id == "api-fixture"
