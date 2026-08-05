#!/usr/bin/env python3
"""Small stdio MCP server used to verify Claude Code extension traffic."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SERVER_NAME = "sandbox-fixture"
DOCS_URL = "https://docs.python.org/3/"
METADATA_URL = "http://metadata.google.internal/"


def _log(method: str, *, request_id: object = None) -> None:
    path = Path(os.environ.get("CDM_MCP_LOG", ".claude/mcp-events.jsonl"))
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "time": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "method": method,
        "has_id": request_id is not None,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def _result(request_id: object, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _text_result(request_id: object, text: str) -> dict[str, Any]:
    return _result(
        request_id,
        {"content": [{"type": "text", "text": text}], "isError": False},
    )


def _fetch(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "cdm-mcp-fixture/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read(4096).decode("utf-8", errors="replace")
            return f"status={response.status} url={response.url} body_prefix={body[:160]!r}"
    except urllib.error.HTTPError as exc:
        reason = exc.headers.get("x-cdm-block-reason", "")
        return f"blocked_http_status={exc.code} block_reason={reason or 'not-provided'}"
    except Exception as exc:
        return f"request_failed={type(exc).__name__}: {exc}"


def _handle(message: dict[str, Any]) -> dict[str, Any] | None:
    method = str(message.get("method", ""))
    request_id = message.get("id")
    _log(method, request_id=request_id)

    if request_id is None:
        return None
    if method == "initialize":
        requested = message.get("params", {}).get("protocolVersion", "2024-11-05")
        return _result(
            request_id,
            {
                "protocolVersion": requested,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"subscribe": False, "listChanged": False},
                    "prompts": {"listChanged": False},
                },
                "serverInfo": {"name": SERVER_NAME, "version": "1.0.0"},
            },
        )
    if method == "ping":
        return _result(request_id, {})
    if method == "tools/list":
        return _result(
            request_id,
            {
                "tools": [
                    {
                        "name": "echo_canary",
                        "description": "Return a caller-provided audit canary.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"text": {"type": "string"}},
                            "required": ["text"],
                            "additionalProperties": False,
                        },
                    },
                    {
                        "name": "fetch_python_docs",
                        "description": (
                            "Fetch the Python documentation through the sandbox network."
                        ),
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                    {
                        "name": "probe_blocked_metadata",
                        "description": "Verify that a metadata hostname is blocked by policy.",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                ]
            },
        )
    if method == "tools/call":
        params = message.get("params", {})
        name = params.get("name")
        arguments = params.get("arguments", {})
        if name == "echo_canary":
            return _text_result(request_id, f"MCP_CANARY:{arguments.get('text', '')}")
        if name == "fetch_python_docs":
            return _text_result(request_id, _fetch(DOCS_URL))
        if name == "probe_blocked_metadata":
            return _text_result(request_id, _fetch(METADATA_URL))
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32602, "message": f"unknown tool: {name}"},
        }
    if method == "resources/list":
        return _result(
            request_id,
            {
                "resources": [
                    {
                        "uri": "fixture://controlled/canary",
                        "name": "Controlled audit canary",
                        "description": "Static content used to trace MCP resource handling.",
                        "mimeType": "text/plain",
                    }
                ]
            },
        )
    if method == "resources/read":
        uri = message.get("params", {}).get("uri")
        if uri != "fixture://controlled/canary":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32002, "message": "resource not found"},
            }
        return _result(
            request_id,
            {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": "MCP_RESOURCE_CANARY:controlled-development-machine",
                    }
                ]
            },
        )
    if method == "resources/templates/list":
        return _result(request_id, {"resourceTemplates": []})
    if method == "prompts/list":
        return _result(
            request_id,
            {
                "prompts": [
                    {
                        "name": "review-sandbox-change",
                        "description": "Review a file without changing it.",
                        "arguments": [
                            {
                                "name": "path",
                                "description": "Project-relative file path",
                                "required": True,
                            }
                        ],
                    }
                ]
            },
        )
    if method == "prompts/get":
        path = message.get("params", {}).get("arguments", {}).get("path", "")
        return _result(
            request_id,
            {
                "description": "Read-only fixture review",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": f"Review {path} without modifying files.",
                        },
                    }
                ],
            },
        )
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


def main() -> int:
    for raw_line in sys.stdin:
        try:
            message = json.loads(raw_line)
            response = _handle(message)
            if response is not None:
                sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            error = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": f"fixture failure: {exc}"},
            }
            sys.stdout.write(json.dumps(error, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
