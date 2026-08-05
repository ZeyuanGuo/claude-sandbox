from pathlib import Path

import pytest

from controlled_dev_machine.errors import PolicyError
from controlled_dev_machine.policy import canonical_domain, load_policy


def test_bootstrap_policy_is_strict_review() -> None:
    policy = load_policy(Path("policies/strict/0001-bootstrap.yaml"))
    assert policy.mode == "strict"
    assert policy.web_default == "review"
    assert len(policy.digest()) == 64


def test_policy_digests_stay_stable() -> None:
    expected = {
        "0001-bootstrap.yaml": "58e5267d92375bdbdffe4c8145dc70d3cd933ab3b684405d866d75380ad8750d",
        "0002-claude-account.yaml": (
            "ff93b68351ff32b42cf8472306af82cc88aaaf0ebf714f3130aa4fa96bd4cce9"
        ),
    }
    for name, digest in expected.items():
        assert load_policy(Path("policies/strict") / name).digest() == digest


def test_daily_policy_is_audited_public_web() -> None:
    policy = load_policy(Path("policies/daily/0001-public-web.yaml"))
    assert policy.mode == "daily"
    assert policy.web_default == "allow_audited_public"
    assert policy.digest() == (
        "55712df7f180adcc9b42f15c7513b091c40ee7740f55711912da95ff9bb902ee"
    )
    assert policy.parent_digest == (
        "ff93b68351ff32b42cf8472306af82cc88aaaf0ebf714f3130aa4fa96bd4cce9"
    )


def test_strict_policy_snapshots_form_one_digest_chain() -> None:
    previous_digest = None
    for path in sorted(Path("policies/strict").glob("*.yaml")):
        policy = load_policy(path)
        assert policy.parent_digest == previous_digest
        previous_digest = policy.digest()

    assert previous_digest == "ff93b68351ff32b42cf8472306af82cc88aaaf0ebf714f3130aa4fa96bd4cce9"


def test_account_login_policy_allows_only_observed_startup_requests() -> None:
    policy = load_policy(Path("policies/strict/0002-claude-account.yaml"))
    actions = {rule.rule_id: rule.action for rule in policy.rules}

    assert policy.policy_id == "strict-claude-account-login-transparent-verification"
    assert policy.web_default == "review"
    assert actions == {
        "block-claude-event-logging": "block",
        "allow-claude-api-startup-hello": "allow",
        "allow-claude-platform-startup-hello": "allow",
        "allow-claude-changelog": "allow",
        "allow-exit-identity-check": "allow",
        "review-claude-webfetch-domain-check": "review",
    }


def test_strict_policy_cannot_default_allow(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        """
schema_version: 1
policy_id: bad-policy
revision: 1
mode: strict
created_at: "2026-07-28T00:00:00Z"
parent_digest:
web_default: allow_audited_public
rules: []
""".lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="不能默认放行"):
        load_policy(path)


def test_allow_rule_requires_evidence_and_plaintext(tmp_path: Path) -> None:
    path = tmp_path / "bad-rule.yaml"
    path.write_text(
        """
schema_version: 1
policy_id: strict-one
revision: 1
mode: strict
created_at: "2026-07-28T00:00:00Z"
parent_digest:
web_default: review
rules:
  - id: api
    action: allow
    priority: 100
    purpose: test
    domain_kind: exact
    domain: example.com
    schemes: [https]
    ports: [443]
    methods: [POST]
    path_prefixes: [/v1]
    content_types: [application/json]
    body_max_bytes: 1024
    tls_identity_required: true
    plaintext_required: false
    evidence: unreviewed
""".lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="必须要求明文"):
        load_policy(path)


def test_direct_ip_is_not_a_domain(tmp_path: Path) -> None:
    path = tmp_path / "ip-rule.yaml"
    path.write_text(
        """
schema_version: 1
policy_id: strict-ip
revision: 1
mode: strict
created_at: "2026-07-28T00:00:00Z"
parent_digest:
web_default: review
rules:
  - id: ip
    priority: 1
    action: block
    purpose: direct IP
    domain_kind: exact
    domain: 127.0.0.1
    schemes: [https]
    ports: [443]
    methods: [GET]
    path_prefixes: [/]
    content_types: []
    body_max_bytes: 0
    tls_identity_required: true
    plaintext_required: true
    evidence: policy
""".lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="直接 IP"):
        load_policy(path)


@pytest.mark.parametrize(
    "value",
    ("2130706433", "0x7f000001", "0177.0.0.1", "127.1", "0x7f.1"),
)
def test_legacy_ipv4_forms_are_not_domains(value: str) -> None:
    with pytest.raises(PolicyError, match="IPv4|域名格式"):
        canonical_domain(value)


def test_numeric_label_in_a_real_domain_is_allowed() -> None:
    assert canonical_domain("123.example") == "123.example"


def test_exact_ip_rule_can_be_reviewed_on_a_nonstandard_port(tmp_path: Path) -> None:
    path = tmp_path / "ip-review.yaml"
    path.write_text(
        """
schema_version: 1
policy_id: strict-ip-review
revision: 1
mode: strict
created_at: "2026-07-28T00:00:00Z"
parent_digest:
web_default: review
rules:
  - id: api
    priority: 1
    action: review
    purpose: exact API test endpoint
    domain_kind: ip
    domain: 192.0.2.10
    schemes: [http]
    ports: [18680]
    methods: [POST]
    path_prefixes: [/]
    content_types: [application/json]
    body_max_bytes: 1024
    tls_identity_required: false
    plaintext_required: true
    evidence: test
""".lstrip(),
        encoding="utf-8",
    )
    policy = load_policy(path)
    assert policy.rules[0].domain == "192.0.2.10"
