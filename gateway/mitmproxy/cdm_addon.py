"""mitmproxy adapter for request-level fail-closed review.

This file is loaded by mitmdump. The policy evaluator and review store live in the
controller package so their security invariants can be tested without mitmproxy.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import time
from pathlib import Path

from mitmproxy import ctx, http, tcp

from controlled_dev_machine.gateway_bindings import (
    ConnectionBindingRegistry,
    DestinationBinding,
)
from controlled_dev_machine.gateway_health import HEALTH_HOST, HEALTH_PATH, HEALTH_REASON
from controlled_dev_machine.http_policy import HttpRequestView, evaluate_http_request
from controlled_dev_machine.policy import PolicyError, canonical_domain, load_policy
from controlled_dev_machine.review import RequestStore


class LeaseServiceUnavailable(RuntimeError):
    pass


class ControlledReviewAddon:
    def __init__(self) -> None:
        self.policy_path = Path(os.environ["CDM_POLICY_PATH"])
        self.expected_policy_digest = os.environ["CDM_EXPECTED_POLICY_DIGEST"]
        self.review_store = RequestStore(Path(os.environ["CDM_REVIEW_DIR"]))
        self.review_ttl = int(os.environ.get("CDM_REVIEW_TTL_SECONDS", "300"))
        self.poll_interval = float(os.environ.get("CDM_REVIEW_POLL_SECONDS", "0.25"))
        self.audit_fault: str | None = None
        self.audit_storage_fault: str | None = None
        self.canary_address = ipaddress.ip_address(os.environ["CDM_CANARY_ADDRESS"])
        self.dns_lease_socket = os.environ["CDM_DNS_LEASE_SOCKET"]
        self.connection_bindings = ConnectionBindingRegistry()
        self.pending_lease_lookups: dict[
            tuple[int, str, str], asyncio.Task[str | None]
        ] = {}
        upstream_host = os.environ.get("CDM_UPSTREAM_HOST")
        upstream_port = os.environ.get("CDM_UPSTREAM_PORT")
        self.upstream = (
            (upstream_host, int(upstream_port))
            if upstream_host and upstream_port
            else None
        )

    def running(self) -> None:
        if ctx.options.connection_strategy != "lazy":
            raise RuntimeError("connection_strategy must be lazy")
        if ctx.options.rawtcp:
            raise RuntimeError("rawtcp must be disabled")
        if ctx.options.mode != ["transparent"]:
            raise RuntimeError("gateway must expose only transparent mode")
        self.review_store.initialize()
        self._load_verified_policy()

    def _load_verified_policy(self):
        policy = load_policy(self.policy_path)
        actual = policy.digest()
        if actual != self.expected_policy_digest:
            raise RuntimeError(
                "policy digest mismatch: "
                f"expected {self.expected_policy_digest}, loaded {actual}"
            )
        return policy

    def _verified_policy_or_block(self, flow: http.HTTPFlow):
        try:
            return self._load_verified_policy()
        except Exception as exc:
            ctx.log.error(f"policy verification failed: {exc}")
            flow.response = _blocked(
                "policy-unavailable", "policy could not be loaded with the expected digest"
            )
            return None

    def _latch_audit_fault(self, reason: str) -> None:
        if self.audit_fault is None:
            self.audit_fault = reason
        ctx.log.error(f"AUDIT-CRITICAL: {reason}; blocking all later requests")

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """Validate CONNECT before mitmproxy starts a TLS handshake."""
        if self._verified_policy_or_block(flow) is None:
            return
        try:
            canonical_domain(flow.request.host)
        except PolicyError:
            valid_host = False
        else:
            valid_host = True
        if flow.request.port != 443 or not valid_host:
            flow.response = _blocked("invalid-connect", "CONNECT requires a hostname on port 443")

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        """A TCPFlow means HTTP/TLS classification failed; never tunnel it."""
        ctx.log.error("blocked unexpected raw TCP flow")
        flow.kill()

    async def request(self, flow: http.HTTPFlow) -> None:
        try:
            await self._request_checked(flow)
        except Exception as exc:
            self._latch_audit_fault(f"gateway request hook failed: {exc}")
            flow.response = _blocked("gateway-error", "gateway request hook failed closed")
            if flow.intercepted:
                flow.resume()
            ctx.log.error(f"gateway request hook failed closed: {exc}")

    async def _request_checked(self, flow: http.HTTPFlow) -> None:
        policy = self._verified_policy_or_block(flow)
        if policy is None:
            return
        request = flow.request
        if _requests_protocol_upgrade(request):
            flow.response = _blocked(
                "unsupported-upgrade",
                "protocol upgrades require a separately verified plaintext path",
            )
            return
        logical_host = request.pretty_host.lower().rstrip(".")
        if _is_health_probe(flow, request):
            try:
                self.review_store.probe_writable()
            except Exception as exc:
                ctx.log.error(f"review store health failed: {exc}")
                self.audit_storage_fault = str(exc)
                flow.response = _blocked(
                    "review-unavailable", "review store is not durably writable"
                )
            else:
                self.audit_storage_fault = None
                if self.audit_fault is not None:
                    flow.response = _blocked(
                        "audit-state-fault", "gateway requires operator recovery"
                    )
                else:
                    flow.response = _blocked(HEALTH_REASON, "gateway addon is ready")
            return
        if self.audit_fault is not None:
            flow.response = _blocked(
                "audit-state-fault", "gateway requires operator recovery"
            )
            return
        if self.audit_storage_fault is not None:
            flow.response = _blocked(
                "review-unavailable", "gateway health check detected an audit storage fault"
            )
            return
        header_items = tuple(request.headers.items(multi=True))
        duplicate_names = _ambiguous_duplicate_headers(header_items)
        if duplicate_names:
            flow.response = _blocked(
                "ambiguous-headers", f"duplicate security-sensitive headers: {duplicate_names}"
            )
            return
        try:
            destination_error = await self._verify_original_destination(
                flow, logical_host
            )
        except LeaseServiceUnavailable as exc:
            ctx.log.error(f"DNS lease service unavailable: {exc}")
            flow.response = _blocked(
                "lease-service-unavailable",
                "DNS lease service did not answer a valid local lookup",
            )
            return
        if destination_error is not None:
            flow.response = _blocked("invalid-destination", destination_error)
            return
        view = HttpRequestView(
            scheme=request.scheme,
            host=logical_host,
            port=request.port,
            method=request.method,
            path=request.path,
            content_type=request.headers.get("content-type"),
            body_size=len(request.raw_content or b""),
            sensitive_headers=_sensitive_headers(header_items),
        )
        if self.upstream and logical_host != "canary.test":
            flow.server_conn.via = ("http", self.upstream)
        flow.metadata["cdm_logical_host"] = logical_host
        decision = evaluate_http_request(policy, view)
        flow.metadata["cdm_policy_digest"] = policy.digest()
        flow.metadata["cdm_policy_action"] = decision.action
        flow.metadata["cdm_policy_rule"] = decision.rule_id
        if decision.action == "allow":
            return
        if decision.action == "block":
            flow.response = _blocked("policy-block", decision.reason)
            return

        try:
            record = self.review_store.enqueue(
                policy_digest=policy.digest(),
                scheme=request.scheme,
                host=logical_host,
                port=request.port,
                method=request.method,
                path=request.path,
                headers=header_items,
                body=request.raw_content or b"",
                review_ttl_seconds=self.review_ttl,
            )
        except Exception as exc:
            ctx.log.error(f"review enqueue failed: {exc}")
            flow.response = _blocked(
                "review-unavailable", "request could not be durably queued for review"
            )
            return
        flow.metadata["cdm_review_request_id"] = record.request_id
        flow.intercept()
        deadline = asyncio.get_running_loop().time() + self.review_ttl
        try:
            while asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(self.poll_interval)
                current = self.review_store.get(record.request_id)
                if not flow.client_conn.connected:
                    if current.state in {"pending", "approved_once"}:
                        self.review_store.mark_client_disconnected(record.request_id)
                    if flow.intercepted:
                        flow.resume()
                    return
                if current.state == "approved_once":
                    current_policy = self._verified_policy_or_block(flow)
                    if current_policy is None:
                        try:
                            self.review_store.fail_closed(
                                record.request_id,
                                reason="policy unavailable before authorization",
                            )
                        except Exception as exc:
                            ctx.log.error(f"failed to close review record: {exc}")
                        flow.resume()
                        return
                    self.review_store.consume_approval(
                        record.request_id,
                        request_sha256=record.request_sha256,
                        policy_digest=current_policy.digest(),
                    )
                    flow.resume()
                    return
                if current.state in {"blocked", "expired"}:
                    flow.response = _blocked("review-rejected", current.reason or current.state)
                    flow.resume()
                    return
            current = self.review_store.get(record.request_id)
            if current.state == "pending":
                self.review_store.reject(record.request_id, reason="review timed out")
            flow.response = _blocked("review-timeout", "operator review timed out")
            flow.resume()
        except Exception as exc:
            try:
                current = self.review_store.get(record.request_id)
                if current.state in {"pending", "approved_once"}:
                    self.review_store.fail_closed(
                        record.request_id,
                        reason="review subsystem failed before upstream dispatch",
                    )
                elif current.state == "authorized":
                    self.review_store.mark_dispatch_unknown(
                        record.request_id,
                        reason="gateway failed while upstream dispatch status was uncertain",
                    )
            except Exception as close_exc:
                self._latch_audit_fault(f"review outcome could not be recorded: {close_exc}")
                ctx.log.error(f"failed to close review record: {close_exc}")
            flow.response = _blocked("review-error", "review subsystem failed closed")
            if flow.intercepted:
                flow.resume()
            ctx.log.error(f"review subsystem failed closed: {exc}")

    async def _verify_original_destination(
        self, flow: http.HTTPFlow, logical_host: str
    ) -> str | None:
        address = flow.server_conn.address
        if not address or len(address) != 2:
            return "transparent flow has no original destination"
        raw_host, raw_port = address
        try:
            destination = ipaddress.ip_address(raw_host)
        except ValueError:
            return "transparent destination is not a pinned IP address"
        if raw_port != flow.request.port:
            return "transparent destination port does not match the request"
        connection_target = self.connection_bindings.target(flow.client_conn)
        destination_key = (str(destination), raw_port)
        if connection_target is not None and connection_target != destination_key:
            return "transparent destination changed on an existing client connection"
        sni_domain = ""
        if flow.request.scheme == "https":
            try:
                request_domain = canonical_domain(logical_host)
                sni_domain = canonical_domain(flow.client_conn.sni or "")
            except PolicyError:
                return "HTTPS requires a canonical client SNI hostname"
            if request_domain != sni_domain:
                return "HTTPS request hostname does not match client SNI"

        lease_required = False
        if logical_host == "canary.test":
            if destination != self.canary_address:
                return "canary hostname does not map to the controlled canary"
        elif not _is_public_address(destination):
            return "transparent destination is not a public address"
        else:
            try:
                logical_address = ipaddress.ip_address(logical_host.strip("[]"))
            except ValueError:
                lease_required = True
            else:
                if logical_address != destination:
                    return "direct IP request does not match its destination"
        binding = self.connection_bindings.find(
            flow.client_conn,
            logical_host,
            str(destination),
            raw_port,
            flow.request.scheme,
            sni_domain,
        )
        if binding is None:
            lease_id = None
            if lease_required:
                lease_id = await self._shared_dns_lease(
                    flow.client_conn, logical_host, str(destination)
                )
                connection_target = self.connection_bindings.target(flow.client_conn)
                if connection_target is not None and connection_target != destination_key:
                    return "transparent destination changed on an existing client connection"
                binding = self.connection_bindings.find(
                    flow.client_conn,
                    logical_host,
                    str(destination),
                    raw_port,
                    flow.request.scheme,
                    sni_domain,
                )
                if binding is None and lease_id is None:
                    return "transparent destination has no matching DNS lease"
            if binding is None:
                binding = DestinationBinding(
                    logical_host,
                    str(destination),
                    raw_port,
                    flow.request.scheme,
                    sni_domain,
                    lease_id,
                )
                self.connection_bindings.remember(flow.client_conn, binding)
        if binding is None:
            return "transparent destination has no matching DNS lease"
        if binding.lease_id is not None:
            flow.metadata["cdm_dns_lease_id"] = binding.lease_id
        flow.metadata["cdm_original_destination"] = f"{destination}:{raw_port}"
        return None

    async def _shared_dns_lease(
        self, connection: object, hostname: str, address: str
    ) -> str | None:
        key = (id(connection), hostname, address)
        task = self.pending_lease_lookups.get(key)
        if task is None:
            task = asyncio.create_task(asyncio.to_thread(self._dns_lease, hostname, address))
            self.pending_lease_lookups[key] = task
            task.add_done_callback(
                lambda completed, lookup_key=key: self._forget_lease_lookup(
                    lookup_key, completed
                )
            )
        return await asyncio.shield(task)

    def _forget_lease_lookup(
        self, key: tuple[int, str, str], task: asyncio.Task[str | None]
    ) -> None:
        if self.pending_lease_lookups.get(key) is task:
            self.pending_lease_lookups.pop(key, None)

    def _dns_lease(self, hostname: str, address: str) -> str | None:
        request = json.dumps(
            {"hostname": hostname, "address": address}, separators=(",", ":")
        ).encode("ascii") + b"\n"
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(1)
                    connection.connect(self.dns_lease_socket)
                    connection.sendall(request)
                    response = b""
                    while b"\n" not in response and len(response) <= 4096:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                parsed = json.loads(response)
                if not isinstance(parsed, dict):
                    raise ValueError("DNS lease response root is not an object")
                lease_id = parsed.get("lease_id")
                if parsed.get("allowed") is False and lease_id is None:
                    return None
                if parsed.get("allowed") is not True or not isinstance(lease_id, str):
                    raise ValueError("DNS lease response has an invalid decision")
                if len(lease_id) != 32 or any(
                    character not in "0123456789abcdef" for character in lease_id
                ):
                    raise ValueError("DNS lease response has an invalid identifier")
                return lease_id
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt < 2:
                    time.sleep(0.01 * (attempt + 1))
        raise LeaseServiceUnavailable(str(last_error)) from last_error

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        if flow.response.status_code != 101:
            flow.response.stream = True
            return
        request_id = flow.metadata.get("cdm_review_request_id")
        if request_id:
            try:
                current = self.review_store.get(request_id)
                if current.state == "authorized":
                    self.review_store.mark_upstream_error(
                        request_id,
                        reason="upstream attempted an unsupported protocol upgrade",
                    )
            except Exception as exc:
                self._latch_audit_fault(
                    f"upgrade outcome for {request_id} could not be recorded: {exc}"
                )
        flow.response = _blocked_without_body(
            "unsupported-upgrade",
        )

    def response(self, flow: http.HTTPFlow) -> None:
        request_id = flow.metadata.get("cdm_review_request_id")
        if not request_id:
            return
        try:
            current = self.review_store.get(request_id)
            if current.state == "authorized":
                self.review_store.mark_completed(request_id)
        except Exception as exc:
            self._latch_audit_fault(
                f"upstream response outcome for {request_id} could not be recorded: {exc}"
            )

    def error(self, flow: http.HTTPFlow) -> None:
        request_id = flow.metadata.get("cdm_review_request_id")
        if not request_id:
            return
        try:
            current = self.review_store.get(request_id)
            if current.state == "authorized":
                reason = str(flow.error) if flow.error else "unknown upstream error"
                self.review_store.mark_upstream_error(request_id, reason=reason)
        except Exception as exc:
            self._latch_audit_fault(
                f"upstream error outcome for {request_id} could not be recorded: {exc}"
            )


def _blocked(code: str, message: str) -> http.Response:
    return http.Response.make(
        403,
        f"controlled gateway blocked request: {code}: {message}\n",
        {"content-type": "text/plain; charset=utf-8", "x-cdm-block-reason": code},
    )


def _blocked_without_body(code: str) -> http.Response:
    return http.Response.make(
        403,
        b"",
        {
            "content-length": "0",
            "x-cdm-block-reason": code,
        },
    )


def _requests_protocol_upgrade(request: http.Request) -> bool:
    if request.method.upper() == "CONNECT":
        return True
    connection = {
        token.strip().lower()
        for token in request.headers.get("connection", "").split(",")
        if token.strip()
    }
    return "upgrade" in request.headers or "upgrade" in connection


def _ambiguous_duplicate_headers(headers: tuple[tuple[str, str], ...]) -> str:
    sensitive = {"host", "content-length", "transfer-encoding", "content-type"}
    counts: dict[str, int] = {}
    for name, _ in headers:
        normalized = name.lower()
        if normalized in sensitive:
            counts[normalized] = counts.get(normalized, 0) + 1
    return ",".join(sorted(name for name, count in counts.items() if count > 1))


def _sensitive_headers(headers: tuple[tuple[str, str], ...]) -> tuple[str, ...]:
    sensitive = {
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-api-key",
    }
    return tuple(sorted({name.lower() for name, _ in headers} & sensitive))


def _is_health_probe(flow: http.HTTPFlow, request: http.Request) -> bool:
    peer = flow.client_conn.peername
    try:
        loopback = bool(peer) and ipaddress.ip_address(peer[0]).is_loopback
    except (ValueError, TypeError):
        loopback = False
    return (
        loopback
        and request.scheme == "http"
        and request.headers.get("host", "").lower() == HEALTH_HOST
        and request.method == "GET"
        and request.path == HEALTH_PATH
        and not request.raw_content
    )


def _is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_global
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_private
        and not address.is_reserved
        and not address.is_unspecified
    )


addons = [ControlledReviewAddon()]
