from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from controlled_dev_machine.errors import PolicyError

_RULE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class HttpRule:
    rule_id: str
    priority: int
    action: str
    purpose: str
    domain_kind: str
    domain: str
    schemes: tuple[str, ...]
    ports: tuple[int, ...]
    methods: tuple[str, ...]
    path_prefixes: tuple[str, ...]
    path_match: str
    content_types: tuple[str, ...]
    body_max_bytes: int
    allow_sensitive_headers: bool
    tls_identity_required: bool
    plaintext_required: bool
    evidence: str


@dataclass(frozen=True)
class PolicySnapshot:
    schema_version: int
    policy_id: str
    revision: int
    mode: str
    created_at: str
    parent_digest: str | None
    deployment: str
    web_default: str
    rules: tuple[HttpRule, ...]

    def digest(self) -> str:
        normalized = asdict(self)
        if normalized["deployment"] == "active":
            del normalized["deployment"]
        for rule in normalized["rules"]:
            if rule["path_match"] == "prefix":
                del rule["path_match"]
            if not rule["allow_sensitive_headers"]:
                del rule["allow_sensitive_headers"]
        payload = json.dumps(
            normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        return hashlib.sha256(payload).hexdigest()


def load_policy(path: Path) -> PolicySnapshot:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"策略文件不存在: {path}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"策略不是有效 YAML: {exc}") from exc
    root = _mapping(raw, "策略根节点")

    schema_version = _integer(root.get("schema_version"), "schema_version")
    if schema_version != 1:
        raise PolicyError(f"不支持 schema_version={schema_version}，当前只支持 1")
    policy_id = _string(root.get("policy_id"), "policy_id")
    if not _RULE_ID_RE.fullmatch(policy_id):
        raise PolicyError("policy_id 格式无效")
    revision = _integer(root.get("revision"), "revision")
    if revision < 1:
        raise PolicyError("revision 必须大于 0")
    mode = _choice(root.get("mode"), "mode", {"strict", "daily", "maintenance", "observe"})
    created_at = _timestamp(root.get("created_at"), "created_at")

    parent_value = root.get("parent_digest")
    parent_digest = None if parent_value in (None, "") else _string(parent_value, "parent_digest")
    if parent_digest is not None and not _HEX_64_RE.fullmatch(parent_digest):
        raise PolicyError("parent_digest 必须是 SHA-256")

    deployment = _choice(
        root.get("deployment", "active"),
        "deployment",
        {"active", "test_only", "retired"},
    )

    web_default = _choice(
        root.get("web_default"),
        "web_default",
        {"block", "review", "allow_audited_public"},
    )
    if mode == "strict" and web_default == "allow_audited_public":
        raise PolicyError("strict 策略不能默认放行公网 Web")
    if mode == "daily" and web_default != "allow_audited_public":
        raise PolicyError("daily 策略必须明确使用 allow_audited_public")

    rules_raw = root.get("rules", [])
    if not isinstance(rules_raw, list):
        raise PolicyError("rules 必须是列表")
    rules = tuple(_rule(item, index) for index, item in enumerate(rules_raw))
    ids = [rule.rule_id for rule in rules]
    if len(ids) != len(set(ids)):
        raise PolicyError("规则 ID 不能重复")

    return PolicySnapshot(
        schema_version=schema_version,
        policy_id=policy_id,
        revision=revision,
        mode=mode,
        created_at=created_at,
        parent_digest=parent_digest,
        deployment=deployment,
        web_default=web_default,
        rules=rules,
    )


def canonical_domain(value: str) -> str:
    candidate = value.strip().rstrip(".").lower()
    if not candidate or candidate.startswith(".") or "*" in candidate:
        raise PolicyError("域名必须是明确名称，不能包含通配符")
    try:
        ipaddress.ip_address(candidate.strip("[]"))
    except ValueError:
        pass
    else:
        raise PolicyError("不能把直接 IP 当作域名")
    if _legacy_ipv4_address(candidate):
        raise PolicyError("不能把传统数字 IPv4 表示当作域名")
    try:
        ascii_name = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise PolicyError(f"域名无法进行 IDNA 规范化: {value}") from exc
    labels = ascii_name.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        raise PolicyError(f"域名格式无效: {value}")
    return ascii_name


def _legacy_ipv4_address(value: str) -> bool:
    """Recognize inet_aton-style IPv4 forms without resolving a hostname."""
    parts = value.split(".")
    if len(parts) > 4:
        return False
    numbers: list[int] = []
    for part in parts:
        if not part:
            return False
        try:
            if part.lower().startswith("0x"):
                number = int(part[2:], 16)
            elif len(part) > 1 and part.startswith("0"):
                number = int(part[1:] or "0", 8)
            else:
                number = int(part, 10)
        except ValueError:
            return False
        numbers.append(number)
    limits = {
        1: (0xFFFFFFFF,),
        2: (0xFF, 0xFFFFFF),
        3: (0xFF, 0xFF, 0xFFFF),
        4: (0xFF, 0xFF, 0xFF, 0xFF),
    }
    return all(
        0 <= number <= limit
        for number, limit in zip(numbers, limits[len(numbers)], strict=True)
    )


def _rule(value: Any, index: int) -> HttpRule:
    raw = _mapping(value, f"rules[{index}]")
    rule_id = _string(raw.get("id"), f"rules[{index}].id")
    if not _RULE_ID_RE.fullmatch(rule_id):
        raise PolicyError(f"rules[{index}].id 格式无效")
    priority = _integer(raw.get("priority"), f"rules[{index}].priority")
    if priority < 0 or priority > 1_000_000:
        raise PolicyError(f"rules[{index}].priority 必须在 0 到 1000000 之间")
    action = _choice(raw.get("action"), f"rules[{index}].action", {"allow", "block", "review"})
    purpose = _string(raw.get("purpose"), f"rules[{index}].purpose")
    domain_kind = _choice(
        raw.get("domain_kind", "exact"),
        f"rules[{index}].domain_kind",
        {"exact", "suffix", "ip"},
    )
    domain_value = _string(raw.get("domain"), f"rules[{index}].domain")
    if domain_kind == "ip":
        try:
            domain = str(ipaddress.ip_address(domain_value.strip("[]")))
        except ValueError as exc:
            raise PolicyError(f"rules[{index}].domain 必须是 IP 地址") from exc
    else:
        domain = canonical_domain(domain_value)
    schemes = _string_tuple(raw.get("schemes"), f"rules[{index}].schemes")
    if not schemes or not set(schemes) <= {"http", "https"}:
        raise PolicyError(f"rules[{index}].schemes 只允许 http/https")
    ports = _int_tuple(raw.get("ports"), f"rules[{index}].ports")
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise PolicyError(f"rules[{index}].ports 必须在 1 到 65535 之间")
    if domain_kind != "ip" and any(port not in {80, 443} for port in ports):
        raise PolicyError(f"rules[{index}].ports 对域名当前只允许 80/443")
    methods = tuple(
        item.upper()
        for item in _string_tuple(raw.get("methods"), f"rules[{index}].methods")
    )
    if not methods or any(
        method != "*" and not re.fullmatch(r"[A-Z]+", method) for method in methods
    ):
        raise PolicyError(f"rules[{index}].methods 格式无效")
    path_prefixes = _string_tuple(
        raw.get("path_prefixes"), f"rules[{index}].path_prefixes"
    )
    if not path_prefixes or any(not item.startswith("/") for item in path_prefixes):
        raise PolicyError(f"rules[{index}].path_prefixes 必须以 / 开头")
    path_match = _choice(
        raw.get("path_match", "prefix"),
        f"rules[{index}].path_match",
        {"exact", "prefix"},
    )
    content_types = _string_tuple(
        raw.get("content_types", []), f"rules[{index}].content_types"
    )
    body_max_bytes = _integer(raw.get("body_max_bytes"), f"rules[{index}].body_max_bytes")
    if body_max_bytes < 0:
        raise PolicyError(f"rules[{index}].body_max_bytes 不能为负数")
    allow_sensitive_headers = _boolean(
        raw.get("allow_sensitive_headers", False),
        f"rules[{index}].allow_sensitive_headers",
    )
    tls_required = _boolean(
        raw.get("tls_identity_required", True), f"rules[{index}].tls_identity_required"
    )
    plaintext_required = _boolean(
        raw.get("plaintext_required", True), f"rules[{index}].plaintext_required"
    )
    evidence = _string(raw.get("evidence", "unreviewed"), f"rules[{index}].evidence")
    if action == "allow" and (not plaintext_required or evidence == "unreviewed"):
        raise PolicyError(f"rules[{index}] 放行规则必须要求明文并提供审核依据")
    return HttpRule(
        rule_id=rule_id,
        priority=priority,
        action=action,
        purpose=purpose,
        domain_kind=domain_kind,
        domain=domain,
        schemes=tuple(sorted(set(schemes))),
        ports=tuple(sorted(set(ports))),
        methods=tuple(sorted(set(methods))),
        path_prefixes=tuple(sorted(set(path_prefixes))),
        path_match=path_match,
        content_types=tuple(sorted(set(content_types))),
        body_max_bytes=body_max_bytes,
        allow_sensitive_headers=allow_sensitive_headers,
        tls_identity_required=tls_required,
        plaintext_required=plaintext_required,
        evidence=evidence,
    )


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise PolicyError(f"{name} 必须是对象")
    return value


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{name} 必须是非空字符串")
    return value.strip()


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{name} 必须是整数")
    return value


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{name} 必须是布尔值")
    return value


def _choice(value: Any, name: str, choices: set[str]) -> str:
    parsed = _string(value, name)
    if parsed not in choices:
        raise PolicyError(f"{name} 只允许: {', '.join(sorted(choices))}")
    return parsed


def _string_tuple(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise PolicyError(f"{name} 必须是字符串列表")
    return tuple(value)


def _int_tuple(value: Any, name: str) -> tuple[int, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, int) and not isinstance(item, bool) for item in value
    ):
        raise PolicyError(f"{name} 必须是整数列表")
    return tuple(value)


def _timestamp(value: Any, name: str) -> str:
    parsed = _string(value, name)
    try:
        timestamp = datetime.fromisoformat(parsed.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyError(f"{name} 必须是 ISO 8601 时间") from exc
    if timestamp.tzinfo is None:
        raise PolicyError(f"{name} 必须包含时区")
    return parsed
