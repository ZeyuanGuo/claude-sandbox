from __future__ import annotations

import argparse
import base64
import http.client
import ipaddress
import json
import os
import socket
import socketserver
import ssl
import struct
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_DNS_HEADER_SIZE = 12
_MAX_DNS_MESSAGE = 65535
_TYPE_A = 1
_TYPE_CNAME = 5
_TYPE_AAAA = 28
_TYPE_OPT = 41
_TYPE_SVCB = 64
_TYPE_HTTPS = 65
_ALLOWED_QUERY_TYPES = frozenset({_TYPE_A, _TYPE_AAAA, _TYPE_SVCB, _TYPE_HTTPS})
_SVCB_IPV4HINT = 4
_SVCB_IPV6HINT = 6
_TCP_CLIENT_TIMEOUT_SECONDS = 2.0
# UDP, TCP and lease servers share one 128-pid container budget. Keep the
# three bounded pools below that limit even when all request types burst.
_DNS_MAX_WORKERS = 48
_LEASE_EXPIRY_GRACE_SECONDS = 60


def public_address(value: str) -> str:
    address = ipaddress.ip_address(value)
    if (
        not address.is_global
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_private
        or address.is_reserved
        or address.is_unspecified
    ):
        raise ValueError(f"DNS 返回了非公网地址: {address}")
    return str(address)


@dataclass(frozen=True)
class _ResourceRecord:
    section: str
    owner: str
    record_type: int
    record_class: int
    ttl: int
    payload_offset: int
    payload_end: int


def checked_response(
    query: bytes, response: bytes
) -> tuple[str, int, tuple[str, ...], int]:
    """Validate a DoH response and return addresses owned by its answer chain."""
    query_name, query_type, query_class, _ = _checked_query(query)
    if len(response) < _DNS_HEADER_SIZE or len(response) > _MAX_DNS_MESSAGE:
        raise ValueError("DoH 响应长度无效")
    if response[:2] != query[:2]:
        raise ValueError("DoH 响应 ID 与查询不一致")
    _, flags, question_count, answer_count, authority_count, additional_count = (
        struct.unpack("!HHHHHH", response[:_DNS_HEADER_SIZE])
    )
    rcode = flags & 0x000F
    if not flags & 0x8000 or flags & 0x7800 or flags & 0x0200 or flags & 0x0040:
        raise ValueError("DoH 响应标志无效或响应被截断")
    if rcode != 0:
        raise ValueError(f"DoH 响应 RCODE 非成功: {rcode}")
    if question_count != 1:
        raise ValueError("DoH 响应必须包含一个问题")
    response_name, response_type, response_class, offset = _question(response)
    if (response_name, response_type, response_class) != (
        query_name,
        query_type,
        query_class,
    ):
        raise ValueError("DoH 响应问题与查询不一致")
    records: list[_ResourceRecord] = []
    sections = (
        ("answer", answer_count),
        ("authority", authority_count),
        ("additional", additional_count),
    )
    for section, count in sections:
        for _ in range(count):
            owner, offset = _decoded_name(response, offset)
            if offset + 10 > len(response):
                raise ValueError("DoH 资源记录头被截断")
            record_type, record_class, ttl, size = struct.unpack(
                "!HHIH", response[offset : offset + 10]
            )
            offset += 10
            end = offset + size
            if end > len(response):
                raise ValueError("DoH 资源记录正文被截断")
            records.append(
                _ResourceRecord(
                    section=section,
                    owner=owner,
                    record_type=record_type,
                    record_class=record_class,
                    ttl=ttl,
                    payload_offset=offset,
                    payload_end=end,
                )
            )
            offset = end
    if offset != len(response):
        raise ValueError("DoH 响应包含无法解释的尾部数据")

    cname_links: dict[str, tuple[str, int]] = {}
    address_records: list[tuple[_ResourceRecord, str]] = []
    hint_records: list[tuple[_ResourceRecord, tuple[str, ...]]] = []
    for record in records:
        payload = response[record.payload_offset : record.payload_end]
        if record.record_class != 1:
            continue
        if record.record_type == _TYPE_A:
            if len(payload) != 4:
                raise ValueError("A 记录长度无效")
            address_records.append(
                (record, public_address(socket.inet_ntop(socket.AF_INET, payload)))
            )
        elif record.record_type == _TYPE_AAAA:
            if len(payload) != 16:
                raise ValueError("AAAA 记录长度无效")
            address_records.append(
                (record, public_address(socket.inet_ntop(socket.AF_INET6, payload)))
            )
        elif record.record_type == _TYPE_CNAME:
            target, end = _decoded_name(response, record.payload_offset)
            if end != record.payload_end:
                raise ValueError("CNAME 记录正文长度无效")
            if record.section == "answer":
                existing = cname_links.get(record.owner)
                if existing is not None and existing[0] != target:
                    raise ValueError("DoH 响应包含歧义 CNAME")
                cname_links[record.owner] = (
                    target,
                    min(record.ttl, existing[1]) if existing is not None else record.ttl,
                )
        elif record.record_type in {_TYPE_SVCB, _TYPE_HTTPS}:
            hints = _checked_svcb_hints(
                response,
                record.payload_offset,
                record.payload_end,
            )
            if record.section == "answer":
                hint_records.append((record, hints))

    cname_ttls: list[int] = []
    terminal_name = query_name
    visited: set[str] = set()
    while terminal_name in cname_links:
        if terminal_name in visited:
            raise ValueError("DoH 响应包含 CNAME 循环")
        visited.add(terminal_name)
        terminal_name, cname_ttl = cname_links[terminal_name]
        cname_ttls.append(cname_ttl)

    addresses: list[str] = []
    address_ttls: list[int] = []
    expected_address_type = {_TYPE_A: _TYPE_A, _TYPE_AAAA: _TYPE_AAAA}.get(query_type)
    if expected_address_type is not None:
        for record, address in address_records:
            if (
                record.section == "answer"
                and record.owner == terminal_name
                and record.record_type == expected_address_type
            ):
                addresses.append(address)
                address_ttls.append(record.ttl)
    elif query_type in {_TYPE_SVCB, _TYPE_HTTPS}:
        for record, hints in hint_records:
            if record.owner == terminal_name:
                addresses.extend(hints)
                address_ttls.extend([record.ttl] * len(hints))

    effective_ttls = [*cname_ttls, *address_ttls] if addresses else []

    return (
        query_name,
        query_type,
        tuple(dict.fromkeys(addresses)),
        min(effective_ttls, default=0),
    )


def _checked_svcb_hints(message: bytes, offset: int, end: int) -> tuple[str, ...]:
    if offset + 3 > end:
        raise ValueError("SVCB/HTTPS 记录长度无效")
    offset += 2
    offset = _skip_name(message, offset)
    if offset > end:
        raise ValueError("SVCB/HTTPS 目标名称越界")
    addresses: list[str] = []
    while offset < end:
        if offset + 4 > end:
            raise ValueError("SVCB/HTTPS 参数头被截断")
        key, size = struct.unpack("!HH", message[offset : offset + 4])
        offset += 4
        value_end = offset + size
        if value_end > end:
            raise ValueError("SVCB/HTTPS 参数正文被截断")
        payload = message[offset:value_end]
        if key == _SVCB_IPV4HINT:
            if not payload or len(payload) % 4:
                raise ValueError("ipv4hint 长度无效")
            for item in range(0, len(payload), 4):
                addresses.append(
                    public_address(socket.inet_ntop(socket.AF_INET, payload[item : item + 4]))
                )
        elif key == _SVCB_IPV6HINT:
            if not payload or len(payload) % 16:
                raise ValueError("ipv6hint 长度无效")
            for item in range(0, len(payload), 16):
                addresses.append(
                    public_address(
                        socket.inet_ntop(socket.AF_INET6, payload[item : item + 16])
                    )
                )
        offset = value_end
    return tuple(addresses)


def _question(packet: bytes) -> tuple[str, int, int, int]:
    if len(packet) < _DNS_HEADER_SIZE:
        raise ValueError("DNS 数据包过短")
    question_count = struct.unpack("!H", packet[4:6])[0]
    if question_count != 1:
        raise ValueError("DNS 查询必须包含一个问题")
    labels, offset = _read_name(packet, _DNS_HEADER_SIZE)
    if offset + 4 > len(packet):
        raise ValueError("DNS 问题被截断")
    query_type, query_class = struct.unpack("!HH", packet[offset : offset + 4])
    name = ".".join(labels).lower()
    if not name:
        raise ValueError("DNS 查询名称为空")
    return name, query_type, query_class, offset + 4


def _checked_query(packet: bytes) -> tuple[str, int, int, int]:
    name, query_type, query_class, offset = _question(packet)
    if query_type not in _ALLOWED_QUERY_TYPES:
        raise ValueError("DNS 查询类型不允许")
    question_end = offset
    _, flags, _, answer_count, authority_count, additional_count = struct.unpack(
        "!HHHHHH", packet[:_DNS_HEADER_SIZE]
    )
    if flags & 0x8000 or flags & 0x7800:
        raise ValueError("DNS 查询标志无效")
    if query_class != 1 or answer_count or authority_count or additional_count > 1:
        raise ValueError("DNS 查询区段无效")
    if not additional_count:
        if offset != len(packet):
            raise ValueError("DNS 查询包含未声明的尾部数据")
        return name, query_type, query_class, question_end

    # glibc uses one empty EDNS0 OPT record. Options remain forbidden so DNS
    # cannot become a second data channel around the policy gateway.
    if offset >= len(packet) or packet[offset] != 0:
        raise ValueError("EDNS OPT 名称必须为空")
    offset += 1
    if offset + 10 > len(packet):
        raise ValueError("EDNS OPT 记录被截断")
    record_type, udp_size, ttl, payload_size = struct.unpack(
        "!HHIH", packet[offset : offset + 10]
    )
    offset += 10
    if record_type != _TYPE_OPT or not 512 <= udp_size <= 4096:
        raise ValueError("EDNS OPT 记录无效")
    if (ttl >> 16) & 0xFF or ttl & ~0x8000:
        raise ValueError("EDNS 版本或标志无效")
    if payload_size:
        raise ValueError("EDNS 选项载荷不允许")
    if offset != len(packet):
        raise ValueError("EDNS OPT 后存在尾部数据")
    return name, query_type, query_class, question_end


def _read_name(packet: bytes, offset: int) -> tuple[list[str], int]:
    labels: list[str] = []
    steps = 0
    while True:
        if offset >= len(packet):
            raise ValueError("DNS 名称被截断")
        size = packet[offset]
        if size & 0xC0:
            raise ValueError("DNS 问题名称不允许压缩")
        offset += 1
        if size == 0:
            return labels, offset
        if size > 63 or offset + size > len(packet):
            raise ValueError("DNS 标签长度无效")
        try:
            labels.append(packet[offset : offset + size].decode("ascii"))
        except UnicodeDecodeError as exc:
            raise ValueError("DNS 查询名称不是 ASCII") from exc
        offset += size
        steps += 1
        if steps > 127:
            raise ValueError("DNS 查询名称标签过多")


def _skip_name(packet: bytes, offset: int) -> int:
    return _decoded_name(packet, offset)[1]


def _decoded_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    next_offset: int | None = None
    visited: set[int] = set()
    wire_size = 1
    while True:
        if offset >= len(packet):
            raise ValueError("DNS 名称被截断")
        if offset in visited:
            raise ValueError("DNS 名称压缩指针形成循环")
        visited.add(offset)
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if offset + 2 > len(packet):
                raise ValueError("DNS 压缩指针被截断")
            pointer = ((size & 0x3F) << 8) | packet[offset + 1]
            if pointer >= len(packet):
                raise ValueError("DNS 压缩指针越界")
            if next_offset is None:
                next_offset = offset + 2
            offset = pointer
            continue
        if size & 0xC0:
            raise ValueError("DNS 名称标签类型无效")
        offset += 1
        if size == 0:
            if not labels:
                return "", next_offset or offset
            return ".".join(labels).lower(), next_offset or offset
        if size > 63 or offset + size > len(packet):
            raise ValueError("DNS 名称标签被截断")
        try:
            labels.append(packet[offset : offset + size].decode("ascii"))
        except UnicodeDecodeError as exc:
            raise ValueError("DNS 名称不是 ASCII") from exc
        offset += size
        wire_size += size + 1
        if wire_size > 255 or len(labels) > 127:
            raise ValueError("DNS 名称过长")


def _servfail(query: bytes) -> bytes:
    try:
        _, _, _, end = _question(query)
    except ValueError:
        return b""
    request_flags = struct.unpack("!H", query[2:4])[0]
    flags = 0x8000 | (request_flags & 0x0100) | 0x0080 | 0x0002
    return query[:2] + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + query[12:end]


@dataclass(frozen=True)
class DohEndpoint:
    proxy_host: str
    proxy_port: int
    address: str
    server_name: str
    path: str

    def __post_init__(self) -> None:
        public_address(self.address)
        if not self.server_name or not self.path.startswith("/"):
            raise ValueError("DoH 服务名称或路径无效")


class DohClient:
    def __init__(self, endpoint: DohEndpoint) -> None:
        self.endpoint = endpoint

    def query(self, packet: bytes) -> tuple[bytes, dict[str, str]]:
        if len(packet) > _MAX_DNS_MESSAGE:
            raise ValueError("DNS 查询超过最大长度")
        return self._query_once(packet)

    def _query_once(self, packet: bytes) -> tuple[bytes, dict[str, str]]:
        endpoint = self.endpoint
        connection = socket.create_connection(
            (endpoint.proxy_host, endpoint.proxy_port), timeout=8
        )
        try:
            authority = f"{endpoint.address}:443"
            connection.sendall(
                (
                    f"CONNECT {authority} HTTP/1.1\r\n"
                    f"Host: {authority}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
            )
            proxy_response = http.client.HTTPResponse(connection)
            proxy_response.begin()
            if proxy_response.status != 200:
                raise OSError(
                    f"父代理拒绝 DoH CONNECT: {proxy_response.status} "
                    f"{proxy_response.reason}"
                )
            proxy_response.close()
            context = ssl.create_default_context()
            tls = context.wrap_socket(connection, server_hostname=endpoint.server_name)
            connection = tls
            request = (
                f"POST {endpoint.path} HTTP/1.1\r\n"
                f"Host: {endpoint.server_name}\r\n"
                "Accept: application/dns-message\r\n"
                "Content-Type: application/dns-message\r\n"
                f"Content-Length: {len(packet)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            tls.sendall(request + packet)
            response = http.client.HTTPResponse(tls)
            response.begin()
            if response.status != 200:
                raise OSError(f"DoH 请求失败: {response.status} {response.reason}")
            headers = _header_mapping(response.getheaders())
            content_type = headers.get("content-type", "").split(";", 1)[0].strip()
            if content_type != "application/dns-message":
                raise OSError(f"DoH 响应类型错误: {content_type!r}")
            if "transfer-encoding" in headers:
                raise OSError("DoH 响应不允许 Transfer-Encoding")
            try:
                content_length = int(headers["content-length"])
            except (KeyError, ValueError) as exc:
                raise OSError("DoH 响应缺少有效 Content-Length") from exc
            if content_length < _DNS_HEADER_SIZE or content_length > _MAX_DNS_MESSAGE:
                raise OSError("DoH 响应长度超出允许范围")
            body = response.read(content_length)
            if len(body) != content_length or response.read(1):
                raise OSError("DoH 响应正文长度与 Content-Length 不一致")
            return body, headers
        finally:
            connection.close()


class LeaseRegistry:
    def __init__(
        self,
        *,
        max_ttl_seconds: int = 300,
        expiry_grace_seconds: int = _LEASE_EXPIRY_GRACE_SECONDS,
    ) -> None:
        if max_ttl_seconds <= 0 or expiry_grace_seconds < 0:
            raise ValueError("DNS 租约时限无效")
        self.max_ttl_seconds = max_ttl_seconds
        self.expiry_grace_seconds = expiry_grace_seconds
        self._lock = threading.Lock()
        self._leases: dict[tuple[str, str], tuple[float, str]] = {}

    def grant(
        self,
        hostname: str,
        addresses: tuple[str, ...],
        ttl: int,
        *,
        lease_id: str | None = None,
    ) -> str | None:
        if not addresses or ttl <= 0:
            return None
        lease_id = lease_id or uuid.uuid4().hex
        if len(lease_id) != 32 or any(
            character not in "0123456789abcdef" for character in lease_id
        ):
            raise ValueError("DNS 租约编号无效")
        expires_at = (
            time.time()
            + min(ttl, self.max_ttl_seconds)
            + self.expiry_grace_seconds
        )
        with self._lock:
            self._purge_locked()
            for address in addresses:
                self._leases[(hostname, address)] = (expires_at, lease_id)
        return lease_id

    def authorize(self, hostname: str, address: str) -> str | None:
        with self._lock:
            self._purge_locked()
            lease = self._leases.get((hostname, address))
            return lease[1] if lease is not None and lease[0] > time.time() else None

    def _purge_locked(self) -> None:
        now = time.time()
        self._leases = {
            key: lease
            for key, lease in self._leases.items()
            if lease[0] > now
        }


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise OSError("连接在响应正文结束前关闭")
        data += chunk
    return data


def _header_mapping(lines: list[tuple[str, str]]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in lines:
        normalized = name.strip().lower()
        if normalized in headers:
            raise OSError(f"DoH 响应包含重复头字段: {normalized}")
        headers[normalized] = value.strip()
    return headers


class DnsGateway:
    def __init__(
        self,
        client: DohClient,
        record_path: Path,
        static_addresses: dict[str, str] | None = None,
        lease_registry: LeaseRegistry | None = None,
        allowed_exact: tuple[str, ...] = (),
        allowed_suffix: tuple[str, ...] = (),
        allow_public_domains: bool = False,
    ) -> None:
        self.client = client
        self.record_path = record_path
        self.static_addresses = static_addresses or {}
        self.lease_registry = lease_registry or LeaseRegistry()
        self.allowed_exact = frozenset(allowed_exact)
        self.allowed_suffix = tuple(allowed_suffix)
        self.allow_public_domains = allow_public_domains
        self._record_lock = threading.Lock()

    def resolve(self, packet: bytes, peer: str) -> bytes:
        record_written = False
        record: dict[str, object] = {
            "created_at": datetime.now(UTC).isoformat(),
            "peer": peer,
            "query_b64": base64.b64encode(packet).decode("ascii"),
        }
        try:
            name, query_type, _, _ = _checked_query(packet)
            record.update({"name": name, "qtype": query_type})
            if name in self.static_addresses:
                response = _static_response(packet, self.static_addresses[name])
                record.update(
                    {
                        "action": "static",
                        "addresses": [self.static_addresses[name]],
                        "response_b64": base64.b64encode(response).decode("ascii"),
                    }
                )
                return response
            if not self._domain_allowed(name):
                raise ValueError("DNS 域名未被当前策略放行")
            response, headers = self.client.query(packet)
            _, _, addresses, ttl = checked_response(packet, response)
            lease_id = uuid.uuid4().hex if addresses and ttl > 0 else None
            record.update(
                {
                    "action": "allow",
                    "addresses": list(addresses),
                    "effective_ttl": ttl,
                    "lease_grace_seconds": self.lease_registry.expiry_grace_seconds,
                    "lease_id": lease_id,
                    "response_b64": base64.b64encode(response).decode("ascii"),
                    "doh_cf_ray": headers.get("cf-ray"),
                }
            )
            self._write_record(record)
            record_written = True
            self.lease_registry.grant(
                name,
                addresses,
                ttl,
                lease_id=lease_id,
            )
            return response
        except Exception as exc:
            record.update({"action": "servfail", "reason": str(exc)})
            return _servfail(packet)
        finally:
            if not record_written:
                self._write_record(record)

    def _write_record(self, record: dict[str, object]) -> None:
        with self._record_lock, self.record_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _domain_allowed(self, name: str) -> bool:
        if self.allow_public_domains or name in self.allowed_exact:
            return True
        return any(name == suffix or name.endswith(f".{suffix}") for suffix in self.allowed_suffix)


class _DnsHandlerMixin:
    gateway: DnsGateway

    def process(self, packet: bytes, peer: str) -> bytes:
        return self.gateway.resolve(packet, peer)


class _UdpHandler(socketserver.BaseRequestHandler, _DnsHandlerMixin):
    def handle(self) -> None:
        packet, sock = self.request
        response = self.process(packet, self.client_address[0])
        if response:
            sock.sendto(response, self.client_address)


class _TcpHandler(socketserver.BaseRequestHandler, _DnsHandlerMixin):
    def handle(self) -> None:
        self.request.settimeout(_TCP_CLIENT_TIMEOUT_SECONDS)
        header = _read_exact(self.request, 2)
        size = struct.unpack("!H", header)[0]
        packet = _read_exact(self.request, size)
        response = self.process(packet, self.client_address[0])
        if response:
            self.request.sendall(struct.pack("!H", len(response)) + response)


class _BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = False
    max_workers = _DNS_MAX_WORKERS

    def __init__(self, *args: object, **kwargs: object) -> None:
        self._worker_slots = threading.BoundedSemaphore(self.max_workers)
        super().__init__(*args, **kwargs)

    def process_request(self, request: object, client_address: object) -> None:
        if not self._worker_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request: object, client_address: object) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


class _UdpServer(_BoundedThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


class _TcpServer(_BoundedThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class _LeaseHandler(socketserver.StreamRequestHandler):
    registry: LeaseRegistry

    def handle(self) -> None:
        raw = self.rfile.readline(4097)
        lease_id: str | None = None
        if raw and len(raw) <= 4096:
            try:
                request = json.loads(raw)
                hostname = request["hostname"]
                address = str(ipaddress.ip_address(request["address"]))
                if not isinstance(hostname, str) or hostname != hostname.lower():
                    raise ValueError("租约主机名无效")
                lease_id = self.registry.authorize(hostname, address)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                lease_id = None
        self.wfile.write(
            json.dumps({"allowed": lease_id is not None, "lease_id": lease_id}).encode(
                "ascii"
            )
            + b"\n"
        )


class _LeaseServer(_BoundedThreadingMixIn, socketserver.UnixStreamServer):
    max_workers = 16
    request_queue_size = 128


def _static_response(query: bytes, address: str) -> bytes:
    _, query_type, query_class, end = _checked_query(query)
    parsed = ipaddress.ip_address(address)
    matching_type = _TYPE_A if parsed.version == 4 else _TYPE_AAAA
    answer_count = 1 if query_type == matching_type and query_class == 1 else 0
    request_flags = struct.unpack("!H", query[2:4])[0]
    flags = 0x8000 | (request_flags & 0x0100) | 0x0080
    response = query[:2] + struct.pack("!HHHHH", flags, 1, answer_count, 0, 0) + query[12:end]
    if answer_count:
        payload = parsed.packed
        response += b"\xc0\x0c" + struct.pack(
            "!HHIH", matching_type, 1, 60, len(payload)
        ) + payload
    return response


def _static_addresses(values: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        name, separator, address = value.partition("=")
        if not separator or not name or name.lower() != name:
            raise ValueError("静态 DNS 地址必须使用 lowercase.name=IP")
        parsed[name] = str(ipaddress.ip_address(address))
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record-path", type=Path, required=True)
    parser.add_argument("--proxy-host", required=True)
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--doh-address", default="1.1.1.1")
    parser.add_argument("--doh-server-name", default="cloudflare-dns.com")
    parser.add_argument("--doh-path", default="/dns-query")
    parser.add_argument("--static-address", action="append", default=[])
    parser.add_argument("--allowed-exact", action="append", default=[])
    parser.add_argument("--allowed-suffix", action="append", default=[])
    parser.add_argument("--allow-public-domains", action="store_true")
    parser.add_argument("--lease-socket", type=Path, required=True)
    args = parser.parse_args()
    args.record_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    endpoint = DohEndpoint(
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        address=args.doh_address,
        server_name=args.doh_server_name,
        path=args.doh_path,
    )
    lease_registry = LeaseRegistry()
    gateway = DnsGateway(
        DohClient(endpoint),
        args.record_path,
        static_addresses=_static_addresses(args.static_address),
        lease_registry=lease_registry,
        allowed_exact=tuple(args.allowed_exact),
        allowed_suffix=tuple(args.allowed_suffix),
        allow_public_domains=args.allow_public_domains,
    )
    _UdpHandler.gateway = gateway
    _TcpHandler.gateway = gateway
    _LeaseHandler.registry = lease_registry
    args.lease_socket.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if args.lease_socket.exists() or args.lease_socket.is_socket():
        if not args.lease_socket.is_socket():
            raise SystemExit(f"租约 socket 路径类型异常: {args.lease_socket}")
        args.lease_socket.unlink()
    lease_server = _LeaseServer(str(args.lease_socket), _LeaseHandler)
    args.lease_socket.chmod(0o666)
    udp = _UdpServer(("0.0.0.0", 53), _UdpHandler)
    tcp = _TcpServer(("0.0.0.0", 53), _TcpHandler)
    threading.Thread(target=lease_server.serve_forever, daemon=True).start()
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    tcp.serve_forever()


if __name__ == "__main__":
    main()
