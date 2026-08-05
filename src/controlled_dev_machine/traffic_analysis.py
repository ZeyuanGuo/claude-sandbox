from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

_CREDENTIAL_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
}

_CREDENTIAL_HEADER_PARTS = {
    "auth",
    "authorization",
    "cookie",
    "credential",
    "key",
    "password",
    "secret",
    "signature",
    "token",
}

_MACHINE_HEADER_KINDS = {
    "user-agent": "user_agent_header_field",
    "x-app": "client_app_header_field",
    "x-claude-code-session-id": "session_identifier_header_field",
    "x-stainless-arch": "architecture_header_field",
    "x-stainless-lang": "language_header_field",
    "x-stainless-os": "os_header_field",
    "x-stainless-package-version": "package_version_header_field",
    "x-stainless-runtime": "runtime_header_field",
    "x-stainless-runtime-version": "runtime_version_header_field",
}

_PROTOCOL_HEADERS = {
    "accept",
    "accept-encoding",
    "anthropic-beta",
    "anthropic-dangerous-direct-browser-access",
    "anthropic-version",
    "connection",
    "content-length",
    "content-type",
    "host",
    "proxy-connection",
    "x-stainless-retry-count",
    "x-stainless-timeout",
}

_SAFE_JSON_KEYS = {
    "account_uuid",
    "cache_control",
    "content",
    "context_management",
    "display",
    "device_id",
    "edits",
    "effort",
    "input",
    "keep",
    "max_tokens",
    "messages",
    "metadata",
    "model",
    "name",
    "output_config",
    "properties",
    "role",
    "stream",
    "system",
    "text",
    "thinking",
    "tools",
    "ttl",
    "type",
    "user_id",
    "session_id",
    "parent_session_id",
}

_KEY_INDICATORS = (
    ("timezone_field", re.compile(r"^(?:tz|time_zone|timezone)$")),
    ("locale_field", re.compile(r"^(?:lang|language|locale|lc_all|lc_ctype)$")),
    (
        "hostname_field",
        re.compile(r"^(?:computer_name|host|host_name|hostname|node_name)$"),
    ),
    (
        "os_or_kernel_field",
        re.compile(r"^(?:kernel|kernel_version|operating_system|os|os_version|platform|uname)$"),
    ),
    ("architecture_field", re.compile(r"^(?:arch|architecture|machine)$")),
    (
        "container_field",
        re.compile(r"^(?:cgroup|container|container_id|docker|pod_name)$"),
    ),
    ("gpu_field", re.compile(r"^(?:cuda|gpu|gpu_id|gpu_model|nvidia)$")),
    ("cpu_field", re.compile(r"^(?:cpu|cpu_model|processor)$")),
    ("memory_field", re.compile(r"^(?:memory|memory_bytes|ram|ram_bytes)$")),
    (
        "proxy_or_ca_field",
        re.compile(
            r"^(?:ca_bundle|certificate|http_proxy|https_proxy|no_proxy|proxy|ssl_cert_file)$"
        ),
    ),
    (
        "network_identifier_field",
        re.compile(
            r"^(?:client_ip|ip|ip_address|ipv4|ipv6|local_ip|mac|mac_address|"
            r"public_ip|source_ip)$"
        ),
    ),
    (
        "local_identity_field",
        re.compile(r"^(?:gid|home|home_directory|uid|user_name|username)$"),
    ),
    (
        "device_identifier_field",
        re.compile(r"^(?:device_id|hardware_id|machine_id)$"),
    ),
    ("session_identifier_field", re.compile(r"^(?:parent_session_id|session_id)$")),
    ("account_identifier_field", re.compile(r"^(?:account_id|account_uuid)$")),
)

_STATIC_INDICATORS = (
    (
        "timezone",
        re.compile(
            r"\b(?:Africa|America|Antarctica|Arctic|Asia|Atlantic|Australia|Europe|"
            r"Indian|Pacific|Etc)/[A-Za-z_+-]+\b"
        ),
    ),
    (
        "timezone",
        re.compile(
            r"\b(?:(?:UTC|GMT)[+-]\d{1,2}(?::\d{2})?|"
            r"time\s*zone|timezone|TZ=)",
            re.I,
        ),
    ),
    (
        "locale",
        re.compile(
            r"\b[a-z]{2}_[A-Z]{2}(?:\.(?:UTF-?8|[A-Z0-9-]+))?|"
            r"\bLC_(?:ALL|CTYPE)=|\bLANG=|\blocale\b",
            re.I,
        ),
    ),
    ("hostname", re.compile(r"\bdevbox\b|\bhostname\b", re.I)),
    (
        "os_or_kernel",
        re.compile(
            r"\b(?:Alpine|Android|CentOS|Darwin|Debian|Fedora|FreeBSD|Linux|macOS|"
            r"Red Hat|RHEL|Ubuntu|Windows|kernel|uname)\b",
            re.I,
        ),
    ),
    ("architecture", re.compile(r"\b(?:aarch64|arm64|armv\d+|i[3-6]86|x64|x86_64)\b", re.I)),
    ("container", re.compile(r"\bDocker\b|\bcontainer\b|\bcgroup\b|\boverlayfs\b", re.I)),
    ("gpu", re.compile(r"\bNVIDIA\b|\bGPU\b|\bRTX\b|\bCUDA\b|\b5090\b", re.I)),
    (
        "proxy_or_ca_env",
        re.compile(
            r"\b(?:HTTP_PROXY|HTTPS_PROXY|NO_PROXY|NODE_EXTRA_CA_CERTS|"
            r"CLAUDE_CONFIG_DIR|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE)\b"
        ),
    ),
    ("ipv4", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")),
    ("mac_address", re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")),
    ("calendar_date", re.compile(r"\b20\d{2}-\d{2}-\d{2}\b")),
    ("clock_time", re.compile(r"\b\d{2}:\d{2}:\d{2}\b")),
    ("project_git_snapshot", re.compile(r"\bgitStatus:")),
    ("project_git_branch", re.compile(r"\bCurrent branch:")),
    ("project_git_identity", re.compile(r"\bGit user:")),
    ("project_git_history", re.compile(r"\bRecent commits:")),
)


class _JsonObject(list[tuple[str, object]]):
    pass


def analyze_review_payload(
    headers: Mapping[str, str] | Sequence[tuple[str, str]],
    body: bytes,
    *,
    target_home: str,
    target_name: str,
) -> dict[str, Any]:
    header_items = tuple(headers.items()) if isinstance(headers, Mapping) else tuple(headers)
    header_names = sorted({name.lower() for name, _ in header_items})
    credential_headers = sorted(name for name in header_names if _is_credential_header(name))
    header_fields: list[dict[str, object]] = []

    indicators: list[dict[str, object]] = []
    leaf_types: Counter[str] = Counter()
    string_fields: list[dict[str, object]] = []
    embedded_client_metadata: list[dict[str, object]] = []
    inspection_limitations = ["machine_indicator_detection_is_heuristic"]
    truncated_string_fields = 0
    dynamic_indicators = (
        ("target_home", re.compile(re.escape(target_home))),
        ("target_user", re.compile(rf"(?<![\w-]){re.escape(target_name)}(?![\w-])")),
    )

    def inspect_string(path: str, value: str, *, record_body_field: bool = True) -> None:
        nonlocal truncated_string_fields
        encoded = value.encode("utf-8", errors="replace")
        if record_body_field and len(string_fields) < 256:
            string_fields.append(
                {
                    "path": path,
                    "length": len(value),
                    "sha256": hashlib.sha256(encoded).hexdigest(),
                }
            )
        elif record_body_field:
            truncated_string_fields += 1
        for label, pattern in (*_STATIC_INDICATORS, *dynamic_indicators):
            count = len(pattern.findall(value))
            if count:
                indicators.append(
                    {
                        "kind": label,
                        "path": path,
                        "source": _indicator_source(path),
                        "count": count,
                    }
                )
        ipv6_count = _count_ipv6(value)
        if ipv6_count:
            indicators.append(
                {
                    "kind": "ipv6",
                    "path": path,
                    "source": _indicator_source(path),
                    "count": ipv6_count,
                }
            )
        if path.endswith(".user_id"):
            indicators.append(
                {
                    "kind": "client_identifier_field",
                    "path": path,
                    "source": _indicator_source(path),
                    "count": 1,
                }
            )
        if path == "$.metadata.user_id":
            try:
                metadata = json.loads(value)
            except json.JSONDecodeError:
                metadata = None
            if isinstance(metadata, dict):
                for key, item in sorted(metadata.items()):
                    metadata_path = f"{path}.{_safe_key(str(key))}"
                    for kind in _key_indicator_kinds(str(key)):
                        indicators.append(
                            {
                                "kind": kind,
                                "path": metadata_path,
                                "source": "client_metadata",
                                "count": 1,
                            }
                        )
                    encoded_item = str(item).encode("utf-8", errors="replace")
                    embedded_client_metadata.append(
                        {
                            "key": _safe_key(str(key)),
                            "type": type(item).__name__,
                            "length": len(str(item)),
                            "empty": item == "",
                            "sha256": hashlib.sha256(encoded_item).hexdigest(),
                        }
                    )

    for name, value in header_items:
        normalized_name = name.lower()
        encoded = value.encode("utf-8", errors="replace")
        credential = _is_credential_header(normalized_name)
        header_field: dict[str, object] = {
            "name": normalized_name,
            "credential": credential,
        }
        if not credential:
            header_field["length"] = len(value)
            header_field["sha256"] = hashlib.sha256(encoded).hexdigest()
        header_fields.append(header_field)
        if credential:
            continue
        path = f"$headers.{normalized_name}"
        if normalized_name not in _PROTOCOL_HEADERS:
            inspect_string(path, value, record_body_field=False)
        kind = _MACHINE_HEADER_KINDS.get(normalized_name)
        if kind is not None:
            indicators.append(
                {
                    "kind": kind,
                    "path": path,
                    "source": "request_header",
                    "count": 1,
                }
            )
        header_key = normalized_name.removeprefix("x-")
        for header_kind in _key_indicator_kinds(header_key):
            indicators.append(
                {
                    "kind": header_kind,
                    "path": path,
                    "source": "request_header",
                    "count": 1,
                }
            )

    def walk(value: object, path: str) -> None:
        stack: list[tuple[object, str]] = [(value, path)]
        while stack:
            item, item_path = stack.pop()
            if isinstance(item, _JsonObject):
                leaf_types["object"] += 1
                for key, child in reversed(item):
                    child_path = f"{item_path}.{_safe_key(key)}"
                    for kind in _key_indicator_kinds(key):
                        indicators.append(
                            {
                                "kind": kind,
                                "path": child_path,
                                "source": _indicator_source(child_path),
                                "count": 1,
                            }
                        )
                    stack.append((child, child_path))
                continue
            if isinstance(item, dict):
                leaf_types["object"] += 1
                for key, child in reversed(tuple(item.items())):
                    key_text = str(key)
                    child_path = f"{item_path}.{_safe_key(key_text)}"
                    for kind in _key_indicator_kinds(key_text):
                        indicators.append(
                            {
                                "kind": kind,
                                "path": child_path,
                                "source": _indicator_source(child_path),
                                "count": 1,
                            }
                        )
                    stack.append((child, child_path))
                continue
            if isinstance(item, list):
                leaf_types["array"] += 1
                for index in range(len(item) - 1, -1, -1):
                    stack.append((item[index], f"{item_path}[{index}]"))
                continue
            if isinstance(item, str):
                leaf_types["string"] += 1
                inspect_string(item_path, item)
                continue
            if item is None:
                leaf_types["null"] += 1
            elif isinstance(item, bool):
                leaf_types["boolean"] += 1
            elif isinstance(item, int | float):
                leaf_types["number"] += 1
            else:
                leaf_types[type(item).__name__] += 1

    encoding = "binary"
    top_level_keys: list[str] = []
    try:
        decoded = body.decode("utf-8")
    except UnicodeDecodeError:
        decoded = None
        inspection_limitations.append("body_not_utf8")
    if decoded is not None:
        encoding = "utf-8"
        try:
            parsed = json.loads(decoded, object_pairs_hook=_JsonObject)
        except json.JSONDecodeError:
            inspection_limitations.append("body_not_json")
            inspect_string("$raw", decoded)
        else:
            encoding = "json"
            if isinstance(parsed, _JsonObject):
                top_level_keys = sorted(_safe_key(key) for key, _ in parsed)
            elif isinstance(parsed, dict):
                top_level_keys = sorted(_safe_key(str(key)) for key in parsed)
            walk(parsed, "$")
    content_encoding = next(
        (value for name, value in header_items if name.lower() == "content-encoding"), None
    )
    if content_encoding and content_encoding.lower() not in {"", "identity"}:
        inspection_limitations.append("content_encoding_not_decoded")
    if truncated_string_fields:
        inspection_limitations.append("string_field_inventory_truncated")

    return {
        "headers": {
            "names": header_names,
            "credential_header_names": credential_headers,
            "fields": sorted(header_fields, key=lambda item: str(item["name"])),
        },
        "body": {
            "size": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "encoding": encoding,
            "top_level_keys": top_level_keys,
            "leaf_types": dict(sorted(leaf_types.items())),
            "string_fields": string_fields,
            "truncated_string_fields": truncated_string_fields,
            "embedded_client_metadata": embedded_client_metadata,
        },
        "machine_indicators": indicators,
        "inspection_limitations": sorted(set(inspection_limitations)),
    }


def _safe_key(value: str) -> str:
    if value in _SAFE_JSON_KEYS:
        return value
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"<key:{digest}>"


def _is_credential_header(value: str) -> bool:
    normalized = value.lower().replace("_", "-")
    if normalized in _CREDENTIAL_HEADERS:
        return True
    parts = {part for part in normalized.split("-") if part}
    collapsed = re.sub(r"[^a-z0-9]", "", normalized)
    sensitive_fragments = (
        "apikey",
        "auth",
        "cookie",
        "credential",
        "password",
        "secret",
        "signature",
        "token",
    )
    return bool(parts & _CREDENTIAL_HEADER_PARTS) or any(
        fragment in collapsed for fragment in sensitive_fragments
    )


def _normalized_key(value: str) -> str:
    with_word_boundaries = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", with_word_boundaries.lower()).strip("_")


def _key_indicator_kinds(value: str) -> tuple[str, ...]:
    normalized = _normalized_key(value)
    return tuple(kind for kind, pattern in _KEY_INDICATORS if pattern.fullmatch(normalized))


def _indicator_source(path: str) -> str:
    if path.startswith("$headers"):
        return "request_header"
    if path.startswith("$.system"):
        return "client_system_context"
    if path.startswith("$.metadata"):
        return "client_metadata"
    if path.startswith("$.tools"):
        return "tool_schema"
    if path.startswith("$.messages"):
        return "conversation_or_tool_data"
    return "raw_body"


def _count_ipv6(value: str) -> int:
    count = 0
    for candidate in re.findall(r"(?<![0-9A-Za-z])\[?([0-9A-Fa-f:]{2,})\]?", value):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if isinstance(address, ipaddress.IPv6Address):
            count += 1
    return count
