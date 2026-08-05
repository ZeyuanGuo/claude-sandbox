from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from controlled_dev_machine.policy import (
    HttpRule,
    PolicyError,
    PolicySnapshot,
    canonical_domain,
)

_SPECIAL_USE_DOMAIN_SUFFIXES = (
    ".docker.internal",
    ".home.arpa",
    ".internal",
    ".lan",
    ".local",
    ".localdomain",
    ".localhost",
    ".localnet",
)


@dataclass(frozen=True)
class HttpRequestView:
    scheme: str
    host: str
    port: int
    method: str
    path: str
    content_type: str | None
    body_size: int
    sensitive_headers: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyDecision:
    action: str
    reason: str
    rule_id: str | None


def evaluate_http_request(policy: PolicySnapshot, request: HttpRequestView) -> PolicyDecision:
    is_ip = False
    try:
        host = str(ipaddress.ip_address(request.host.strip("[]")))
    except ValueError:
        try:
            host = canonical_domain(request.host)
        except PolicyError as domain_error:
            return PolicyDecision("block", str(domain_error), None)
    else:
        is_ip = True
    if not is_ip and any(
        host == suffix.removeprefix(".") or host.endswith(suffix)
        for suffix in _SPECIAL_USE_DOMAIN_SUFFIXES
    ):
        return PolicyDecision("block", "特殊用途或内网主机名不能访问", None)
    if request.scheme not in {"http", "https"}:
        return PolicyDecision("block", "只允许可解析的 HTTP/HTTPS", None)
    if request.port < 1 or request.port > 65535:
        return PolicyDecision("block", "Web 请求端口无效", None)
    if request.body_size < 0:
        return PolicyDecision("block", "请求正文大小无效", None)

    for rule in sorted(policy.rules, key=lambda item: (item.priority, item.rule_id)):
        if _matches(rule, request, host, is_ip):
            return PolicyDecision(rule.action, f"matched rule {rule.rule_id}", rule.rule_id)

    if is_ip or request.port != (443 if request.scheme == "https" else 80):
        return PolicyDecision("block", "Web 请求使用了策略外地址或端口", None)

    defaults = {
        "block": PolicyDecision("block", "strict default block", None),
        "review": PolicyDecision("review", "request requires operator review", None),
        "allow_audited_public": PolicyDecision(
            "allow", "daily audited public web default", None
        ),
    }
    return defaults[policy.web_default]


def _matches(rule: HttpRule, request: HttpRequestView, host: str, is_ip: bool) -> bool:
    if rule.domain_kind == "ip":
        domain_matches = is_ip and host == rule.domain
    elif is_ip:
        domain_matches = False
    elif rule.domain_kind == "exact":
        domain_matches = host == rule.domain
    else:
        domain_matches = host == rule.domain or host.endswith(f".{rule.domain}")
    if not domain_matches:
        return False
    if request.scheme not in rule.schemes or request.port not in rule.ports:
        return False
    if "*" not in rule.methods and request.method.upper() not in rule.methods:
        return False
    if rule.path_match == "exact":
        path_matches = request.path in rule.path_prefixes
    else:
        path_matches = any(request.path.startswith(prefix) for prefix in rule.path_prefixes)
    if not path_matches:
        return False
    if rule.action == "block":
        return True
    if request.sensitive_headers and not rule.allow_sensitive_headers:
        return False
    if request.body_size > rule.body_max_bytes:
        return False
    if rule.content_types:
        actual_type = (request.content_type or "").split(";", 1)[0].strip().lower()
        if actual_type not in {item.lower() for item in rule.content_types}:
            return False
    return True
