from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import signal
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from controlled_dev_machine.config import HostConfig
from controlled_dev_machine.errors import DeploymentError
from controlled_dev_machine.policy import load_policy
from controlled_dev_machine.review import RequestStore, ReviewRecord
from controlled_dev_machine.runtime import (
    _atomic_text,
    _docker,
    _host_parent_table,
    audit_status,
    compose_exec_async,
    load_runtime,
    service_is_healthy,
)


@dataclass(frozen=True)
class _GatewayCapture:
    process: subprocess.Popen[bytes]
    pcap_path: Path
    log_path: Path
    metadata_path: Path
    started_at: str
    ready_at: str | None
    capture_filter: str


def run_closed_gate(config: HostConfig, *, timeout_seconds: float = 15.0) -> dict[str, Any]:
    """Run the local, no-public-upstream checks for the strict environment."""
    if timeout_seconds < 5 or timeout_seconds > 120:
        raise DeploymentError("封闭门禁超时时间必须在 5 到 120 秒之间")
    manifest = load_runtime(config)
    audit = audit_status(config)
    _require_live_audit(audit)
    policy = load_policy(Path(manifest.policy_snapshot_path))

    checks: list[dict[str, Any]] = []
    checks.append(_run_environment_neutral(config))
    if policy.web_default == "review":
        checks.append(_run_public_dns_via_proxy(config, audit))
    checks.append(_run_dns_via_gateway(config, policy.web_default))
    _expect_command_failure(
        config,
        [
            "curl",
            "--connect-timeout",
            "2",
            "--max-time",
            "4",
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--output",
            "/dev/null",
            "http://169.254.169.254/latest/meta-data/",
        ],
        timeout=6,
        name="metadata-destination-blocked",
    )
    checks.append({"name": "metadata-destination-blocked", "ok": True})
    _expect_command_success(
        config,
        [
            "python3",
            "-c",
            (
                "import socket\n"
                "try:\n"
                "    socket.create_connection(('1.1.1.1', 22), 2)\n"
                "except OSError:\n"
                "    pass\n"
                "else:\n"
                "    raise SystemExit('direct TCP unexpectedly succeeded')\n"
            ),
        ],
        timeout=5,
        name="direct-non-web-tcp-blocked",
    )
    checks.append({"name": "direct-non-web-tcp-blocked", "ok": True})
    _expect_command_failure(
        config,
        ["dig", "+time=1", "+tries=1", "@1.1.1.1", "example.com"],
        timeout=4,
        name="external-dns-blocked",
    )
    checks.append({"name": "external-dns-blocked", "ok": True})
    checks.append(_run_non_web_udp_blocked(config, audit))
    checks.append(_run_dns_lease_binding_blocked(config))
    checks.append(_run_raw_tcp_connect_blocked(config, audit, manifest))
    checks.append(_run_protocol_upgrade_blocked(config))
    checks.append(_run_application_connect_blocked(config))

    store = RequestStore(config.paths.review)
    if policy.web_default == "review":
        checks.append(
            _run_public_review_before_upstream(
                config,
                store,
                timeout_seconds,
                audit,
            )
        )
    checks.append(_run_policy_digest_fault(config, store, timeout_seconds, audit))
    checks.append(_run_public_web_via_parent(config, audit))
    checks.append(_run_review_store_fault(config, store, timeout_seconds))
    for scheme in ("http", "https"):
        checks.append(_run_approved_request(config, store, scheme, timeout_seconds))
    checks.append(_run_unexpected_upgrade_response(config, store, timeout_seconds))
    checks.append(_run_rejected_request(config, store, timeout_seconds))
    checks.append(_run_disconnected_request(config, store, timeout_seconds))
    if policy.web_default == "review":
        checks.append(_run_disallowed_dns_type_before_upstream(config, audit))
    # This probe opens a bare parent-proxy TCP connection. Run it after every
    # zero-upstream-packet capture so a delayed FIN/ACK cannot pollute them.
    checks.append(_run_upstream_isolation(config, manifest))

    flow_path = config.paths.audit / "plaintext" / "flows.mitm"
    if not flow_path.is_file() or flow_path.stat().st_size == 0:
        raise DeploymentError("封闭门禁未发现明文流量文件")
    checks.append({"name": "plaintext-flow-present", "ok": True, "bytes": flow_path.stat().st_size})
    audit = audit_status(config)
    _require_live_audit(audit)
    run_id = audit.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise DeploymentError("审计运行编号缺失")
    evidence_path = config.paths.audit / "structured" / run_id / "verify-closed.json"
    result = {
        "ok": True,
        "resource_prefix": config.resource_prefix,
        "run_id": run_id,
        "target_cgroup_id": audit.get("target_cgroup_id"),
        "checks": checks,
        "canary_received": _received_records(config),
        "manifest": manifest.compose_path,
        "evidence_path": str(evidence_path),
    }
    _atomic_text(
        evidence_path,
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        mode=0o600,
    )
    return result


def _run_environment_neutral(config: HostConfig) -> dict[str, Any]:
    _expect_command_success(
        config,
        [
            "python3",
            "-c",
            (
                "import os\n"
                "for name in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY',"
                "'http_proxy','https_proxy','all_proxy','no_proxy','CURL_CA_BUNDLE',"
                "'GIT_SSL_CAINFO','NODE_EXTRA_CA_CERTS','REQUESTS_CA_BUNDLE',"
                "'SSL_CERT_FILE'):\n"
                "    if os.environ.get(name): raise SystemExit(f'{name} is set')\n"
                "if os.environ.get('NODE_USE_SYSTEM_CA') != '1':\n"
                "    raise SystemExit('Node system CA mode is not enabled')\n"
            ),
        ],
        timeout=5,
        name="native-network-environment",
    )
    return {"name": "native-network-environment", "ok": True}


def _run_upstream_isolation(config: HostConfig, manifest: Any) -> dict[str, Any]:
    network_name = f"{manifest.resource_prefix}_upstream_net"
    result = _docker(config, "network", "inspect", network_name, capture=True)
    try:
        network = json.loads(result.stdout)[0]
        network_id = str(network["Id"])
        options = network.get("Options") or {}
        bridge = options.get("com.docker.network.bridge.name") or f"br-{network_id[:12]}"
        ipam = network["IPAM"]["Config"]
        containers = network["Containers"]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise DeploymentError("无法读取上游 Docker 网络状态") from exc
    if network.get("Internal") is not True:
        raise DeploymentError("上游 Docker 网络仍有普通公网路由")
    if ipam != [
        {
            "Subnet": manifest.upstream_subnet,
            "Gateway": manifest.upstream_gateway_address,
        }
    ]:
        raise DeploymentError("上游 Docker 网络地址与运行清单不一致")
    observed_addresses = {
        str(item.get("Name")): str(item.get("IPv4Address", "")).split("/", 1)[0]
        for item in containers.values()
        if isinstance(item, dict)
    }
    expected_addresses = {
        f"{manifest.resource_prefix}-gateway-1": manifest.gateway_upstream_address,
        f"{manifest.resource_prefix}-dns-1": manifest.dns_upstream_address,
    }
    if observed_addresses != expected_addresses:
        raise DeploymentError("上游 Docker 网络只应包含固定地址的 DNS 和网关")

    table = _host_parent_table(manifest)
    nft = subprocess.run(
        ["nft", "list", "table", "inet", table],
        text=True,
        capture_output=True,
        check=False,
    )
    if nft.returncode != 0:
        raise DeploymentError("宿主父代理门禁不存在")
    required_rules = (
        f'iifname "{bridge}" ip saddr {{ '
        f"{manifest.gateway_upstream_address}, {manifest.dns_upstream_address} }} "
        f"tcp dport {config.upstream.port} accept",
        f'iifname "{bridge}" drop',
        f"tcp dport {config.upstream.port} drop",
    )
    if any(rule not in nft.stdout for rule in required_rules):
        raise DeploymentError("宿主父代理门禁规则与运行清单不一致")

    probe = (
        "import socket,sys\n"
        "proxy_host=sys.argv[1];proxy_port=int(sys.argv[2])\n"
        "for host,port,should_connect in ((proxy_host,proxy_port,True),"
        "('1.1.1.1',443,False)):\n"
        " s=socket.socket();s.settimeout(2)\n"
        " try:s.connect((host,port));connected=True\n"
        " except OSError:connected=False\n"
        " finally:s.close()\n"
        " if connected != should_connect:\n"
        "  raise SystemExit(f'unexpected {host}:{port}={connected}')\n"
    )
    for service, interpreter in (("dns", "python3"), ("gateway", "python")):
        process = compose_exec_async(
            config,
            service,
            [interpreter, "-c", probe, "upstream.cdm.test", str(config.upstream.port)],
        )
        stdout, stderr = _communicate(process, 7)
        if process.returncode != 0:
            raise DeploymentError(
                f"{service} 上游隔离检查失败: {stderr.strip() or stdout.strip()}"
            )

    unrelated_probe = (
        "import socket,sys\n"
        "s=socket.socket();s.settimeout(2)\n"
        "try:s.connect(('upstream.cdm.test',int(sys.argv[1])))\n"
        "except OSError:raise SystemExit(0)\n"
        "raise SystemExit('unrelated container reached parent proxy')\n"
    )
    unrelated = _docker(
        config,
        "run",
        "--rm",
        "--network",
        "bridge",
        "--add-host",
        "upstream.cdm.test:host-gateway",
        manifest.target_image,
        "python3",
        "-c",
        unrelated_probe,
        str(config.upstream.port),
        capture=True,
        check=False,
    )
    if unrelated.returncode != 0:
        detail = (unrelated.stderr or unrelated.stdout).strip()
        raise DeploymentError(f"无关容器父代理隔离失败: {detail[-500:]}")
    return {
        "name": "internal-upstream-and-host-parent-guard",
        "ok": True,
        "bridge": bridge,
        "allowed_sources": sorted(expected_addresses.values()),
    }


def _run_dns_via_gateway(config: HostConfig, web_default: str) -> dict[str, Any]:
    names = (
        ("api.anthropic.com", "platform.claude.com")
        if web_default == "review"
        else ("api.anthropic.com", "example.com")
    )
    process = compose_exec_async(
        config,
        "target",
        [
            "python3",
            "-c",
            (
                "import ipaddress,json,socket\n"
                "result={}\n"
                f"for name in {names!r}:\n"
                "    items=socket.getaddrinfo(name,443,type=socket.SOCK_STREAM)\n"
                "    addresses=sorted({item[4][0] for item in items})\n"
                "    if not addresses or not all(\n"
                "        ipaddress.ip_address(v).is_global for v in addresses\n"
                "    ):\n"
                "        raise SystemExit(f'invalid DNS result for {name}: {addresses}')\n"
                "    result[name]=addresses\n"
                "print(json.dumps(result,sort_keys=True))\n"
            ),
        ],
    )
    stdout, stderr = _communicate(process, 8)
    if process.returncode != 0:
        raise DeploymentError(f"受控 DNS 解析失败: {stderr.strip() or stdout.strip()}")
    return {
        "name": "dns-via-parent-proxy",
        "ok": True,
        "addresses": json.loads(stdout),
    }


def _run_public_dns_via_proxy(
    config: HostConfig,
    audit: dict[str, Any],
) -> dict[str, Any]:
    if config.upstream.kind != "http" or config.upstream.port is None:
        raise DeploymentError("严格 DNS 验收要求 HTTP 父代理")
    hostname = "example.com"
    test_id = f"public-dns-{uuid.uuid4().hex[:12]}"
    capture = _start_gateway_capture(
        config,
        audit,
        test_id,
        capture_filter=f"dst port {config.upstream.port}",
        artifact_kind="dns-upstream",
        namespace="dns",
        direction="out",
    )
    try:
        _expect_command_success(
            config,
            [
                "python3",
                "-c",
                (
                    "import socket,sys\n"
                    "socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM)\n"
                ),
                hostname,
            ],
            timeout=4,
            name="public-dns-resolves",
        )
    except Exception:
        _discard_gateway_capture(capture)
        raise
    evidence = _finish_gateway_capture(
        capture,
        packet_error="公网 DNS 查询没有经父代理发出",
        packet_expectation="nonzero",
    )
    matching = [record for record in _dns_records(config) if record.get("name") == hostname]
    if not matching or any(record.get("action") != "allow" for record in matching):
        raise DeploymentError("公网 DNS 查询缺少放行审计记录")
    return {
        "name": "public-dns-via-proxy",
        "ok": True,
        "hostname": hostname,
        "dns_actions": [record["action"] for record in matching],
        "upstream_nonzero_packet_capture": evidence,
    }


def _run_disallowed_dns_type_before_upstream(
    config: HostConfig,
    audit: dict[str, Any],
) -> dict[str, Any]:
    if config.upstream.kind != "http" or config.upstream.port is None:
        raise DeploymentError("严格 DNS 查询类型验收要求 HTTP 父代理")
    baseline = len(_dns_records(config))
    test_id = f"closed-gate-dns-qtype-{uuid.uuid4().hex[:12]}"
    capture = _start_gateway_capture(
        config,
        audit,
        test_id,
        capture_filter=f"dst port {config.upstream.port}",
        artifact_kind="dns-qtype-upstream",
        namespace="dns",
        direction="out",
    )
    try:
        _expect_command_success(
            config,
            [
                "python3",
                "-c",
                (
                    "import re,socket,struct\n"
                    "text=open('/etc/resolv.conf',encoding='ascii').read()\n"
                    "match=re.search(r'^nameserver\\s+(\\S+)',text,re.M)\n"
                    "if not match: raise SystemExit('missing nameserver')\n"
                    "name='raw.githubusercontent.com'\n"
                    "question=b''.join(bytes([len(v)])+v.encode('ascii') "
                    "for v in name.split('.'))+b'\\0'+struct.pack('!HH',16,1)\n"
                    "query=struct.pack('!HHHHHH',0xC0DE,0x0100,1,0,0,0)+question\n"
                    "family=socket.AF_INET6 if ':' in match.group(1) else socket.AF_INET\n"
                    "s=socket.socket(family,socket.SOCK_DGRAM);s.settimeout(3)\n"
                    "try:\n"
                    " s.sendto(query,(match.group(1),53))\n"
                    " response,_=s.recvfrom(4096)\n"
                    "finally:s.close()\n"
                    "if len(response)<12 or response[:2]!=query[:2]: "
                    "raise SystemExit('invalid DNS response')\n"
                    "if struct.unpack('!H',response[2:4])[0]&15 != 2: "
                    "raise SystemExit('TXT query was not SERVFAIL')\n"
                ),
            ],
            timeout=5,
            name="strict-disallowed-dns-type-blocked",
        )
    except Exception:
        _discard_gateway_capture(capture)
        raise
    evidence = _finish_gateway_capture(
        capture,
        packet_error="严格模式不允许的 DNS 查询类型触及了父代理",
    )
    matching = [
        record
        for record in _dns_records(config)[baseline:]
        if record.get("action") == "servfail"
        and "查询类型不允许" in str(record.get("reason", ""))
    ]
    if not matching:
        raise DeploymentError("严格模式不允许的 DNS 查询类型缺少本地 SERVFAIL 审计记录")
    return {
        "name": "strict-disallowed-dns-type-blocked-before-upstream",
        "ok": True,
        "qtype": 16,
        "dns_actions": [record["action"] for record in matching],
        "upstream_zero_packet_capture": evidence,
    }


def _run_non_web_udp_blocked(
    config: HostConfig,
    audit: dict[str, Any],
) -> dict[str, Any]:
    run_id = audit.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise DeploymentError("无法定位普通 UDP 验收的审计运行")
    connect_path = config.paths.audit / "structured" / run_id / "connect.log"
    start_offset = connect_path.stat().st_size
    test_id = f"closed-gate-udp-{uuid.uuid4().hex[:12]}"
    capture = _start_gateway_capture(
        config,
        audit,
        test_id,
        capture_filter="udp and dst host 1.1.1.1 and dst port 443",
        artifact_kind="udp",
        direction="out",
    )
    try:
        _expect_command_success(
            config,
            [
                "python3",
                "-c",
                (
                    "import socket\n"
                    "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
                    "try:\n"
                    "    s.sendto(b'cdm-udp-probe',('1.1.1.1',443))\n"
                    "except OSError:\n"
                    "    pass\n"
                    "finally:\n"
                    "    s.close()\n"
                ),
            ],
            timeout=5,
            name="direct-non-web-udp-blocked",
        )
        deadline = time.monotonic() + 3
        observed = False
        while time.monotonic() < deadline:
            with connect_path.open("rb") as stream:
                stream.seek(start_offset)
                observed = b"CDM_SENDTO_BEGIN" in stream.read()
            if observed:
                break
            time.sleep(0.05)
        if not observed:
            raise DeploymentError("普通 UDP 尝试没有进入目标 cgroup 的 eBPF 审计")
    except Exception:
        _discard_gateway_capture(capture)
        raise
    evidence = _finish_gateway_capture(
        capture,
        packet_error="普通 UDP/443 尝试从透明网关出包",
    )
    return {
        "name": "direct-non-web-udp-blocked",
        "ok": True,
        "ebpf_attempt_observed": True,
        "gateway_zero_packet_capture": evidence,
    }


def _run_dns_lease_binding_blocked(config: HostConfig) -> dict[str, Any]:
    process = compose_exec_async(
        config,
        "target",
        [
            "curl",
            "--silent",
            "--show-error",
            "--include",
            "--connect-timeout",
            "3",
            "--max-time",
            "6",
            "--connect-to",
            "api.anthropic.com:443:1.1.1.1:443",
            "https://api.anthropic.com/api/hello",
        ],
    )
    stdout, stderr = _communicate(process, 8)
    response = stdout.lower()
    if process.returncode != 0 or not response.startswith(("http/1.1 403", "http/2 403")):
        raise DeploymentError(
            "伪造 DNS 目的地址没有被透明网关明确阻断: "
            f"{stderr.strip() or stdout[-500:]}"
        )
    if "x-cdm-block-reason: invalid-destination" not in response:
        raise DeploymentError("伪造 DNS 目的地址缺少 invalid-destination 证据")
    return {"name": "dns-lease-destination-binding", "ok": True}


def _run_raw_tcp_connect_blocked(
    config: HostConfig,
    audit: dict[str, Any],
    manifest: Any,
) -> dict[str, Any]:
    test_id = f"closed-gate-raw-tcp-{uuid.uuid4().hex[:12]}"
    capture = _start_gateway_capture(
        config,
        audit,
        test_id,
        capture_filter=f"dst host {manifest.canary_address} and dst port 443",
        artifact_kind="canary",
    )
    try:
        _expect_command_success(
            config,
            [
                "python3",
                "-c",
                (
                    "import socket,sys\n"
                    "marker=f'SSH-2.0-CDM-{sys.argv[1]}\\r\\n'.encode()\n"
                    "s=socket.create_connection(('canary.test',443),2)\n"
                    "s.sendall(marker)\n"
                    "s.shutdown(socket.SHUT_WR)\n"
                    "s.settimeout(3)\n"
                    "try:\n"
                    "    reply=s.recv(4096)\n"
                    "except socket.timeout:\n"
                    "    raise SystemExit('raw TCP connection remained open')\n"
                    "finally:\n"
                    "    s.close()\n"
                    "if marker in reply:\n"
                    "    raise SystemExit('raw TCP marker was echoed')\n"
                ),
                test_id,
            ],
            timeout=6,
            name="transparent-raw-tcp-blocked",
        )
        evidence = _finish_gateway_capture(
            capture,
            packet_error="raw TCP attempt reached the canary network",
        )
    except Exception:
        _discard_gateway_capture(capture)
        raise
    return {
        "name": "transparent-raw-tcp-blocked",
        "ok": True,
        "pcap_path": evidence["pcap_path"],
        "pcap_sha256": evidence["pcap_sha256"],
    }


def _run_protocol_upgrade_blocked(config: HostConfig) -> dict[str, Any]:
    test_id = f"closed-gate-upgrade-{uuid.uuid4().hex[:12]}"
    _expect_command_success(
        config,
        [
            "python3",
            "-c",
            (
                "import socket,sys\n"
                "test_id=sys.argv[1]\n"
                "s=socket.create_connection(('canary.test',80),2)\n"
                "request=(f'GET /{test_id} HTTP/1.1\\r\\n'"
                "+f'Host: canary.test\\r\\nX-CDM-Test-ID: {test_id}\\r\\n'"
                "+'Connection: Upgrade\\r\\nUpgrade: cdm-fixture\\r\\n\\r\\n').encode()\n"
                "s.sendall(request)\n"
                "data=s.recv(4096).lower()\n"
                "s.close()\n"
                "if not data.startswith(b'http/1.1 403'):\n"
                "    raise SystemExit(f'unexpected upgrade status: {data!r}')\n"
                "if b'x-cdm-block-reason: unsupported-upgrade' not in data:\n"
                "    raise SystemExit(f'missing upgrade block reason: {data!r}')\n"
            ),
            test_id,
        ],
        timeout=5,
        name="http-protocol-upgrade-blocked",
    )
    if any(item.get("test_id") == test_id for item in _received_records(config)):
        raise DeploymentError("协议升级请求到达了 canary")
    return {"name": "http-protocol-upgrade-blocked", "ok": True}


def _run_application_connect_blocked(config: HostConfig) -> dict[str, Any]:
    test_id = f"closed-gate-inner-connect-{uuid.uuid4().hex[:12]}"
    _expect_command_success(
        config,
        [
            "python3",
            "-c",
            (
                "import socket,ssl,sys\n"
                "test_id=sys.argv[1]\n"
                "s=socket.create_connection(('canary.test',443),2)\n"
                "context=ssl.create_default_context()\n"
                "tls=context.wrap_socket(s,server_hostname='canary.test')\n"
                "request=(f'CONNECT /{test_id} HTTP/1.1\\r\\n'"
                "+f'Host: canary.test\\r\\nX-CDM-Test-ID: {test_id}\\r\\n\\r\\n').encode()\n"
                "tls.sendall(request)\n"
                "reply=tls.recv(4096).lower()\n"
                "tls.close()\n"
                "local_400=reply.startswith(b'http/1.1 400')\n"
                "policy_403=reply.startswith(b'http/1.1 403')\n"
                "if not (local_400 or policy_403):\n"
                "    raise SystemExit(f'inner CONNECT was not blocked: {reply!r}')\n"
                "if policy_403 and b'x-cdm-block-reason: invalid-connect' not in reply "
                "and b'x-cdm-block-reason: unsupported-upgrade' not in reply:\n"
                "    raise SystemExit(f'missing inner CONNECT block reason: {reply!r}')\n"
            ),
            test_id,
        ],
        timeout=8,
        name="http-application-connect-blocked",
    )
    if any(item.get("test_id") == test_id for item in _received_records(config)):
        raise DeploymentError("应用层 CONNECT 请求到达了 canary")
    return {"name": "http-application-connect-blocked", "ok": True}


def _require_live_audit(audit: dict[str, Any]) -> None:
    processes = audit.get("processes")
    required = {
        "target-pcap",
        "gateway-pcap",
        "dns-pcap",
        "target-connect-ebpf",
        "network-watchdog",
    }
    if (
        not audit.get("active")
        or not isinstance(processes, list)
        or {item.get("kind") for item in processes if isinstance(item, dict)} != required
        or not all(item.get("alive") for item in processes if isinstance(item, dict))
    ):
        raise DeploymentError("透明网络门禁要求全部抓包、eBPF 和监督进程均在运行")


def _run_approved_request(
    config: HostConfig,
    store: RequestStore,
    scheme: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    test_id = f"closed-gate-{scheme}-{uuid.uuid4().hex[:12]}"
    path = f"/__cdm_closed_gate/{test_id}"
    body = f"controlled-dev-machine {scheme} gate\n".encode()
    process = compose_exec_async(
        config,
        "target",
        _curl_args(scheme, test_id, path, body, max_time=10),
    )
    record = _wait_pending(store, path, timeout_seconds)
    if process.poll() is not None:
        stdout, stderr = process.communicate()
        raise DeploymentError(
            f"{scheme} 请求在批准前结束: rc={process.returncode}; "
            f"{stderr.strip() or stdout.strip()}"
        )
    _, raw_body = store.raw(record.request_id)
    if raw_body != body:
        raise DeploymentError(f"{scheme} 审核记录正文与请求不一致")
    store.approve_once(
        record.request_id,
        ttl_seconds=30,
        reason=f"封闭门禁本地 {scheme} canary 回归",
    )
    stdout, stderr = _communicate(process, 12)
    if process.returncode != 0:
        raise DeploymentError(f"{scheme} 批准后请求失败: {stderr.strip() or stdout.strip()}")
    final = store.get(record.request_id)
    if final.state != "completed":
        raise DeploymentError(f"{scheme} 批准后状态异常: {final.state}")
    response = _json_response(stdout, scheme)
    expected_digest = hashlib.sha256(body).hexdigest()
    if response.get("body_sha256") != expected_digest or response.get("body_size") != len(body):
        raise DeploymentError(f"{scheme} canary 返回正文校验失败")
    received = [item for item in _received_records(config) if item.get("test_id") == test_id]
    if len(received) != 1 or received[0].get("body_sha256") != expected_digest:
        raise DeploymentError(f"{scheme} canary 未收到且仅收到一次正确正文")
    return {
        "name": f"{scheme}-review-approve",
        "ok": True,
        "request_id": record.request_id,
        "state": final.state,
        "body_sha256": expected_digest,
    }


def _run_unexpected_upgrade_response(
    config: HostConfig,
    store: RequestStore,
    timeout_seconds: float,
) -> dict[str, Any]:
    test_id = f"closed-gate-upstream-101-{uuid.uuid4().hex[:12]}"
    path = f"/__cdm_upgrade_response/{test_id}"
    process = compose_exec_async(
        config,
        "target",
        [
            "curl",
            "--silent",
            "--show-error",
            "--include",
            "--connect-timeout",
            "3",
            "--max-time",
            "10",
            "-H",
            f"x-cdm-test-id: {test_id}",
            f"http://canary.test{path}",
        ],
    )
    record = _wait_pending(store, path, timeout_seconds)
    store.approve_once(
        record.request_id,
        ttl_seconds=30,
        reason="封闭门禁上游 101 回归",
    )
    stdout, stderr = _communicate(process, timeout_seconds)
    if process.returncode != 0:
        raise DeploymentError(f"101 阻断请求失败: {stderr.strip() or stdout.strip()}")
    response = stdout.lower()
    if not response.startswith("http/1.1 403") or (
        "x-cdm-block-reason: unsupported-upgrade" not in response
    ):
        raise DeploymentError(f"上游 101 没有被改写为明确的本地 403: {stdout[-500:]}")
    final = store.get(record.request_id)
    if final.state != "upstream_error":
        raise DeploymentError(f"上游 101 审核状态错误: {final.state}")
    received = next(
        (item for item in _received_records(config) if item.get("test_id") == test_id),
        None,
    )
    if received is None or received.get("response_status") != 101:
        raise DeploymentError("canary 没有记录预期的上游 101 响应")
    return {
        "name": "http-upstream-101-blocked",
        "ok": True,
        "request_id": record.request_id,
        "state": final.state,
    }


def _run_policy_digest_fault(
    config: HostConfig,
    store: RequestStore,
    timeout_seconds: float,
    audit: dict[str, Any],
) -> dict[str, Any]:
    manifest = load_runtime(config)
    policy_path = Path(manifest.policy_path)
    original = policy_path.read_bytes()
    revision = re.search(br"(?m)^revision: ([0-9]+)[ \t]*$", original)
    if revision is None:
        raise DeploymentError("策略故障注入找不到预期 revision 字段，拒绝修改")
    current_revision = int(revision.group(1))
    replacement = f"revision: {current_revision + 1000}".encode("ascii")
    faulted = original[: revision.start()] + replacement + original[revision.end() :]
    test_id = f"closed-gate-policy-fault-{uuid.uuid4().hex[:12]}"
    path = f"/__cdm_closed_gate/{test_id}"
    process: subprocess.Popen[str] | None = None
    capture = _start_upstream_capture(config, audit, test_id)
    if not service_is_healthy(config, "gateway"):
        _discard_gateway_capture(capture)
        raise DeploymentError("策略故障注入前网关已经不健康")
    try:
        _write_in_place(policy_path, faulted)
        process = compose_exec_async(
            config,
            "target",
            [
                "curl",
                "--silent",
                "--show-error",
                "--include",
                "--connect-timeout",
                "3",
                "--max-time",
                "6",
                "-H",
                f"x-cdm-test-id: {test_id}",
                "--data-binary",
                "policy digest fault",
                f"http://canary.test{path}",
            ],
        )
        stdout, stderr = _communicate(process, 8)
        response = stdout.lower()
        if process.returncode != 0:
            raise DeploymentError(
                f"策略故障请求没有返回本地阻断响应: {stderr.strip() or stdout.strip()}"
            )
        if not response.startswith("http/1.1 403") or (
            "x-cdm-block-reason: policy-unavailable" not in response
        ):
            raise DeploymentError(f"策略故障没有返回明确的 policy-unavailable 403: {stdout[-500:]}")
        _wait_gateway_health(config, expected=False, timeout_seconds=timeout_seconds)
        if any(record.path == path for record in store.list_records()):
            raise DeploymentError("策略摘要不一致的请求错误进入了审核队列")
        upstream_evidence = _finish_upstream_capture(config, capture)
        capture = None
    finally:
        if capture is not None:
            _discard_gateway_capture(capture)
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        _write_in_place(policy_path, original)
    _wait_gateway_health(config, expected=True, timeout_seconds=timeout_seconds)
    return {
        "name": "policy-digest-fault-blocked",
        "ok": True,
        "expected_policy_digest": manifest.policy_digest,
        "upstream_zero_packet_capture": upstream_evidence,
    }


def _run_public_review_before_upstream(
    config: HostConfig,
    store: RequestStore,
    timeout_seconds: float,
    audit: dict[str, Any],
) -> dict[str, Any]:
    test_id = f"closed-gate-public-review-{uuid.uuid4().hex[:12]}"
    path = f"/__cdm_public_review/{test_id}"
    capture = _start_upstream_capture(config, audit, test_id)
    process: subprocess.Popen[str] | None = None
    record: ReviewRecord | None = None
    try:
        process = compose_exec_async(
            config,
            "target",
            [
                "curl",
                "--silent",
                "--show-error",
                "--include",
                "--connect-timeout",
                "3",
                "--max-time",
                "10",
                "-H",
                f"x-cdm-test-id: {test_id}",
                "-H",
                "content-type: text/plain",
                "--data-binary",
                "strict public review",
                f"https://api.anthropic.com{path}",
            ],
        )
        record = _wait_pending(store, path, timeout_seconds)
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise DeploymentError(
                "策略外公网请求在审核前结束: "
                f"rc={process.returncode}; {stderr.strip() or stdout.strip()}"
            )
        upstream_evidence = _finish_gateway_capture(
            capture,
            packet_error="策略外公网请求在审核决定前连接了父代理",
        )
        capture = None
        store.reject(record.request_id, reason="封闭门禁策略外公网请求")
        _communicate(process, 8)
        final = store.get(record.request_id)
        if final.state != "blocked":
            raise DeploymentError(f"策略外公网请求拒绝状态异常: {final.state}")
    finally:
        if capture is not None:
            _discard_gateway_capture(capture)
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        if record is not None:
            current = store.get(record.request_id)
            if current.state == "pending":
                store.reject(record.request_id, reason="封闭门禁清理未完成请求")
    return {
        "name": "strict-public-review-before-upstream",
        "ok": True,
        "request_id": record.request_id,
        "state": final.state,
        "upstream_zero_packet_capture": upstream_evidence,
    }


def _run_public_web_via_parent(
    config: HostConfig,
    audit: dict[str, Any],
) -> dict[str, Any]:
    if config.upstream.kind != "http" or config.upstream.port is None:
        raise DeploymentError("透明 Web 出口验收要求 HTTP 父代理")
    observed_upstream_ip = audit.get("observed_upstream_ip")
    if not isinstance(observed_upstream_ip, str):
        raise DeploymentError("父代理出口记录缺失")
    if config.upstream.expected_exit_cidr is None:
        raise DeploymentError("HTTP 父代理没有声明 expected_exit_cidr")
    expected = ipaddress.ip_network(config.upstream.expected_exit_cidr)
    if ipaddress.ip_address(observed_upstream_ip) not in expected:
        raise DeploymentError(f"父代理出口不在验收要求的范围 {expected}")
    test_id = f"closed-gate-public-parent-{uuid.uuid4().hex[:12]}"
    capture = _start_gateway_capture(
        config,
        audit,
        test_id,
        capture_filter=f"dst port {config.upstream.port}",
        artifact_kind="public-parent",
        direction="out",
    )
    try:
        process = compose_exec_async(
            config,
            "target",
            [
                "curl",
                "--silent",
                "--show-error",
                "--fail-with-body",
                "--connect-timeout",
                "4",
                "--max-time",
                "12",
                "https://api.ipify.org/",
            ],
        )
        stdout, stderr = _communicate(process, 14)
        if process.returncode != 0:
            raise DeploymentError(
                f"目标容器透明 Web 出口查询失败: {stderr.strip() or stdout.strip()}"
            )
        returned_ip = stdout.strip()
        if returned_ip != observed_upstream_ip:
            raise DeploymentError(
                f"目标容器出口 {returned_ip!r} 与宿主父代理出口 {observed_upstream_ip!r} 不一致"
            )
    except Exception:
        _discard_gateway_capture(capture)
        raise
    evidence = _finish_gateway_capture(
        capture,
        packet_error="目标容器透明 Web 请求没有产生父代理数据包",
        packet_expectation="nonzero",
    )
    return {
        "name": "target-public-web-via-parent",
        "ok": True,
        "returned_ip": returned_ip,
        "observed_upstream_ip": observed_upstream_ip,
        "parent_packet_capture": evidence,
    }


def _run_review_store_fault(
    config: HostConfig,
    store: RequestStore,
    timeout_seconds: float,
) -> dict[str, Any]:
    review_root = config.paths.review
    root_stat = review_root.lstat()
    if not stat.S_ISDIR(root_stat.st_mode) or review_root.is_symlink():
        raise DeploymentError(f"审核目录不是实例专用普通目录: {review_root}")
    test_id = f"closed-gate-review-fault-{uuid.uuid4().hex[:12]}"
    path = f"/__cdm_closed_gate/{test_id}"
    process: subprocess.Popen[str] | None = None
    if not service_is_healthy(config, "gateway"):
        raise DeploymentError("审核存储故障注入前网关已经不健康")
    try:
        os.chown(review_root, 0, 0)
        os.chmod(review_root, 0o500)
        _wait_gateway_health(config, expected=False, timeout_seconds=timeout_seconds)
        process = compose_exec_async(
            config,
            "target",
            [
                "curl",
                "--silent",
                "--show-error",
                "--include",
                "--connect-timeout",
                "3",
                "--max-time",
                "6",
                "-H",
                f"x-cdm-test-id: {test_id}",
                "--data-binary",
                "review store fault",
                f"http://canary.test{path}",
            ],
        )
        stdout, stderr = _communicate(process, 8)
        response = stdout.lower()
        if process.returncode != 0:
            raise DeploymentError(
                f"审核存储故障请求没有返回本地阻断响应: {stderr.strip() or stdout.strip()}"
            )
        if not response.startswith("http/1.1 403") or (
            "x-cdm-block-reason: review-unavailable" not in response
        ):
            raise DeploymentError(
                f"健康检查发现审核存储故障后没有返回明确的 review-unavailable 403: {stdout[-500:]}"
            )
        if any(item.get("test_id") == test_id for item in _received_records(config)):
            raise DeploymentError("审核存储不可写时请求到达了 canary")
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        os.chown(review_root, root_stat.st_uid, root_stat.st_gid)
        os.chmod(review_root, stat.S_IMODE(root_stat.st_mode))
    _wait_gateway_health(config, expected=True, timeout_seconds=timeout_seconds)
    if any(record.path == path for record in store.list_records()):
        raise DeploymentError("审核存储不可写的请求错误进入了审核队列")
    return {
        "name": "review-store-fault-blocked",
        "ok": True,
        "request_record_absent": True,
    }


def _run_rejected_request(
    config: HostConfig, store: RequestStore, timeout_seconds: float
) -> dict[str, Any]:
    test_id = f"closed-gate-reject-{uuid.uuid4().hex[:12]}"
    path = f"/__cdm_closed_gate/{test_id}"
    body = b"must be rejected\n"
    process = compose_exec_async(
        config,
        "target",
        _curl_args("http", test_id, path, body, max_time=10),
    )
    record = _wait_pending(store, path, timeout_seconds)
    store.reject(record.request_id, reason="封闭门禁拒绝路径")
    _communicate(process, 8)
    final = store.get(record.request_id)
    if final.state != "blocked":
        raise DeploymentError(f"拒绝路径状态异常: {final.state}")
    if any(item.get("test_id") == test_id for item in _received_records(config)):
        raise DeploymentError("拒绝的请求到达了 canary")
    return {"name": "http-review-reject", "ok": True, "request_id": record.request_id}


def _run_disconnected_request(
    config: HostConfig, store: RequestStore, timeout_seconds: float
) -> dict[str, Any]:
    test_id = f"closed-gate-disconnect-{uuid.uuid4().hex[:12]}"
    path = f"/__cdm_closed_gate/{test_id}"
    process = compose_exec_async(
        config,
        "target",
        _curl_args("http", test_id, path, b"client disconnect\n", max_time=1),
    )
    record = _wait_record(store, path, timeout_seconds)
    _communicate(process, 5)
    deadline = time.monotonic() + timeout_seconds
    final = store.get(record.request_id)
    while final.state == "pending" and time.monotonic() < deadline:
        time.sleep(0.1)
        final = store.get(record.request_id)
    if final.state != "client_disconnected":
        raise DeploymentError(f"客户端断开路径未闭锁: {final.state}")
    if any(item.get("test_id") == test_id for item in _received_records(config)):
        raise DeploymentError("客户端断开的请求到达了 canary")
    return {"name": "http-client-disconnect", "ok": True, "request_id": record.request_id}


def _curl_args(scheme: str, test_id: str, path: str, body: bytes, *, max_time: int) -> list[str]:
    port = 443 if scheme == "https" else 80
    return [
        "curl",
        "--silent",
        "--show-error",
        "--fail-with-body",
        "--connect-timeout",
        "3",
        "--max-time",
        str(max_time),
        "-H",
        f"x-cdm-test-id: {test_id}",
        "-H",
        "content-type: text/plain",
        "--data-binary",
        body.decode("utf-8"),
        f"{scheme}://canary.test:{port}{path}",
    ]


def _wait_pending(store: RequestStore, path: str, timeout_seconds: float) -> ReviewRecord:
    record = _wait_record(store, path, timeout_seconds)
    if record.state != "pending":
        raise DeploymentError(f"请求未停在 pending: {path} -> {record.state}")
    return record


def _wait_record(store: RequestStore, path: str, timeout_seconds: float) -> ReviewRecord:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for record in store.list_records():
            if record.path == path:
                return record
        time.sleep(0.1)
    raise DeploymentError(f"未在期限内看到审核请求: {path}")


def _expect_command_failure(
    config: HostConfig,
    args: list[str],
    *,
    timeout: float,
    name: str,
) -> None:
    process = compose_exec_async(config, "target", args)
    stdout, stderr = _communicate(process, timeout)
    if process.returncode == 0:
        raise DeploymentError(f"{name} 未失败，存在越过封闭边界的可能: {stdout.strip()}")


def _expect_command_success(
    config: HostConfig,
    args: list[str],
    *,
    timeout: float,
    name: str,
) -> None:
    process = compose_exec_async(config, "target", args)
    stdout, stderr = _communicate(process, timeout)
    if process.returncode != 0:
        detail = stderr.strip() or stdout.strip()
        raise DeploymentError(f"{name} 未确认本地无路由阻断: {detail}")


def _communicate(process: subprocess.Popen[str], timeout: float) -> tuple[str, str]:
    try:
        return process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        stdout, stderr = process.communicate()
        raise DeploymentError(f"封闭门禁子进程超时: {stderr.strip() or stdout.strip()}") from exc


def _json_response(stdout: str, scheme: str) -> dict[str, Any]:
    try:
        response = json.loads(stdout.strip())
    except json.JSONDecodeError as exc:
        raise DeploymentError(f"{scheme} canary 响应不是 JSON: {stdout[-500:]}") from exc
    if not isinstance(response, dict):
        raise DeploymentError(f"{scheme} canary 响应不是对象")
    return response


def _received_records(config: HostConfig) -> list[dict[str, Any]]:
    path = config.paths.state / "canary" / "received" / "received.jsonl"
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _dns_records(config: HostConfig) -> list[dict[str, Any]]:
    path = config.paths.state / "dns" / "queries.jsonl"
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _start_upstream_capture(
    config: HostConfig, audit: dict[str, Any], test_id: str
) -> _GatewayCapture:
    """Start a short, independently closable capture around the fault request."""
    if config.upstream.kind != "http" or config.upstream.port is None:
        raise DeploymentError("策略故障的上游零到达检查要求 HTTP 上游")
    return _start_gateway_capture(
        config,
        audit,
        test_id,
        capture_filter=f"dst port {config.upstream.port}",
        artifact_kind="upstream",
    )


def _start_gateway_capture(
    config: HostConfig,
    audit: dict[str, Any],
    test_id: str,
    *,
    capture_filter: str,
    artifact_kind: str,
    namespace: str = "gateway",
    direction: str | None = None,
) -> _GatewayCapture:
    namespace_pid = audit.get(f"{namespace}_pid")
    if not isinstance(namespace_pid, int) or namespace_pid <= 0:
        raise DeploymentError(f"无法定位当前 {namespace} 网络命名空间")
    if direction not in {None, "in", "out"}:
        raise DeploymentError(f"无效的抓包方向: {direction}")
    run_id = audit.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise DeploymentError("无法定位当前审计运行")
    evidence_root = config.paths.audit / "pcap" / run_id / "closed-gate"
    if evidence_root.is_symlink():
        raise DeploymentError("封闭门禁证据目录不能是符号链接")
    evidence_root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(evidence_root, 0o700)
    os.chown(evidence_root, 0, 0)
    pcap_path = evidence_root / f"{test_id}.{artifact_kind}.pcap"
    log_path = evidence_root / f"{test_id}.{artifact_kind}.tcpdump.log"
    metadata_path = evidence_root / f"{test_id}.{artifact_kind}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    pcap_descriptor = os.open(pcap_path, flags, 0o600)
    try:
        log_descriptor = os.open(log_path, flags, 0o600)
    except Exception:
        os.close(pcap_descriptor)
        raise
    started_at = _now()
    try:
        command = [
            "nsenter",
            "--target",
            str(namespace_pid),
            "--net",
            "--",
            "tcpdump",
            "-i",
            "any",
            "-U",
            "-s",
            "0",
            "-nn",
            "-Z",
            "root",
            *(["-Q", direction] if direction is not None else []),
            "-w",
            "-",
            capture_filter,
        ]
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=pcap_descriptor,
            stderr=log_descriptor,
            start_new_session=True,
        )
    except Exception:
        os.close(pcap_descriptor)
        os.close(log_descriptor)
        raise
    os.close(pcap_descriptor)
    os.close(log_descriptor)
    capture = _GatewayCapture(
        process=process,
        pcap_path=pcap_path,
        log_path=log_path,
        metadata_path=metadata_path,
        started_at=started_at,
        ready_at=None,
        capture_filter=capture_filter,
    )
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if process.poll() is not None:
            detail = log_path.read_text(encoding="utf-8", errors="replace").strip()
            _discard_gateway_capture(capture)
            raise DeploymentError(f"独立网关抓包启动失败: {detail[-500:]}")
        detail = log_path.read_text(encoding="utf-8", errors="replace")
        if "listening on" in detail.lower():
            return _GatewayCapture(
                process=capture.process,
                pcap_path=capture.pcap_path,
                log_path=capture.log_path,
                metadata_path=capture.metadata_path,
                started_at=capture.started_at,
                ready_at=_now(),
                capture_filter=capture.capture_filter,
            )
        time.sleep(0.05)
    _discard_gateway_capture(capture)
    raise DeploymentError("独立网关抓包未在期限内就绪")


def _finish_upstream_capture(
    config: HostConfig,
    capture: _GatewayCapture,
) -> dict[str, Any]:
    return _finish_gateway_capture(
        capture,
        packet_error="策略故障窗口内网关向宿主上游代理发送了数据包",
    )


def _finish_gateway_capture(
    capture: _GatewayCapture,
    *,
    packet_error: str,
    packet_expectation: str = "zero",
) -> dict[str, Any]:
    """Close the capture before parsing, then enforce the packet expectation."""
    if packet_expectation not in {"zero", "nonzero"}:
        raise DeploymentError(f"无效的抓包期望: {packet_expectation}")
    process = capture.process
    stopped_at: str | None = None
    try:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGINT)
        process.wait(timeout=5)
        stopped_at = _now()
        if process.returncode != 0:
            detail = capture.log_path.read_text(encoding="utf-8", errors="replace").strip()
            raise DeploymentError(f"独立上游抓包没有正常结束: {detail[-500:]}")
        _fsync_file(capture.pcap_path)
        with capture.pcap_path.open("rb") as stream:
            result = subprocess.run(
                ["tcpdump", "-Z", "root", "-nn", "-r", "-"],
                stdin=stream,
                check=False,
                text=True,
                capture_output=True,
                timeout=10,
            )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise DeploymentError(f"无法读取已关闭的上游窗口 PCAP: {detail[-500:]}")
        packet_count = len([line for line in result.stdout.splitlines() if line.strip()])
        passed = packet_count == 0 if packet_expectation == "zero" else packet_count > 0
        evidence = {
            "status": "passed" if passed else "unexpected-packet-count",
            "started_at": capture.started_at,
            "ready_at": capture.ready_at,
            "stopped_at": stopped_at,
            "filter": capture.capture_filter,
            "packet_count": packet_count,
            "packet_expectation": packet_expectation,
            "pcap_path": str(capture.pcap_path),
            "pcap_bytes": capture.pcap_path.stat().st_size,
            "pcap_sha256": hashlib.sha256(capture.pcap_path.read_bytes()).hexdigest(),
            "tcpdump_log_path": str(capture.log_path),
        }
        _write_evidence_json(capture.metadata_path, evidence)
        if not passed:
            raise DeploymentError(packet_error)
    except Exception:
        if not capture.metadata_path.exists():
            _discard_gateway_capture(capture)
        raise
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
    return evidence


def _discard_gateway_capture(
    capture: _GatewayCapture,
) -> None:
    process = capture.process
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGINT)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
    evidence = {
        "status": "aborted",
        "started_at": capture.started_at,
        "ready_at": capture.ready_at,
        "stopped_at": _now(),
        "pcap_path": str(capture.pcap_path),
        "pcap_bytes": capture.pcap_path.stat().st_size,
        "pcap_sha256": hashlib.sha256(capture.pcap_path.read_bytes()).hexdigest(),
        "tcpdump_log_path": str(capture.log_path),
    }
    _write_evidence_json(capture.metadata_path, evidence)


def _write_evidence_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _write_in_place(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _wait_gateway_health(
    config: HostConfig, *, expected: bool, timeout_seconds: float
) -> None:
    deadline = time.monotonic() + max(timeout_seconds, 20)
    while time.monotonic() < deadline:
        if service_is_healthy(config, "gateway") is expected:
            return
        time.sleep(0.5)
    state = "healthy" if expected else "unhealthy"
    raise DeploymentError(f"策略故障注入后网关未在期限内变为 {state}")
