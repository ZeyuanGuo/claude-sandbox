from __future__ import annotations

import ipaddress
import json
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from controlled_dev_machine.dns_gateway import (
    DnsGateway,
    DohClient,
    DohEndpoint,
    LeaseRegistry,
    _LeaseHandler,
    _LeaseServer,
    _TcpServer,
    _UdpServer,
    checked_response,
    public_address,
)
from controlled_dev_machine.gateway_bindings import (
    ConnectionBindingRegistry,
    DestinationBinding,
)


def _name(value: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in value.split(".")) + b"\0"


def _query(name: str = "example.com", query_type: int = 1) -> bytes:
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + _name(name) + struct.pack(
        "!HH", query_type, 1
    )


def _edns_query(name: str = "example.com", *, payload: bytes = b"") -> bytes:
    question = _name(name) + struct.pack("!HH", 1, 1)
    header = struct.pack("!HHHHHH", 0x1234, 0x0120, 1, 0, 0, 1)
    opt = b"\0" + struct.pack("!HHIH", 41, 1232, 0, len(payload)) + payload
    return header + question + opt


def _response(address: str, *, record_type: int | None = None) -> tuple[bytes, bytes]:
    parsed = ipaddress.ip_address(address)
    record_type = record_type or (1 if parsed.version == 4 else 28)
    query = _query(query_type=record_type)
    payload = parsed.packed
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", record_type, 1, 60, len(payload)) + payload
    return query, header + query[12:] + answer


def _record(owner: bytes, record_type: int, payload: bytes, *, ttl: int = 60) -> bytes:
    return owner + struct.pack("!HHIH", record_type, 1, ttl, len(payload)) + payload


def test_public_address_rejects_every_non_public_range() -> None:
    for value in (
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "192.0.2.1",
        "::1",
        "fc00::1",
        "fe80::1",
    ):
        with pytest.raises(ValueError, match="非公网地址"):
            public_address(value)
    assert public_address("1.1.1.1") == "1.1.1.1"
    assert public_address("2606:4700:4700::1111") == "2606:4700:4700::1111"


def test_checked_response_accepts_public_a_and_aaaa_records() -> None:
    query, response = _response("93.184.216.34")
    assert checked_response(query, response) == (
        "example.com",
        1,
        ("93.184.216.34",),
        60,
    )

    query, response = _response("2606:2800:220:1:248:1893:25c8:1946")
    assert checked_response(query, response)[2] == (
        "2606:2800:220:1:248:1893:25c8:1946",
    )


def test_checked_response_accepts_glibc_empty_edns0_query() -> None:
    query = _edns_query()
    plain_query, response = _response("93.184.216.34")
    response = response[:12] + plain_query[12:] + response[len(plain_query) :]
    assert checked_response(query, response)[2] == ("93.184.216.34",)


def test_checked_response_rejects_edns_option_payload() -> None:
    query = _edns_query(payload=b"hidden")
    _, response = _response("93.184.216.34")
    with pytest.raises(ValueError, match="EDNS 选项载荷"):
        checked_response(query, response)


def test_static_response_to_edns_query_does_not_echo_undeclared_opt(tmp_path) -> None:
    query = _edns_query("canary.test")
    gateway = DnsGateway(
        client=object(),  # type: ignore[arg-type]
        record_path=tmp_path / "dns.jsonl",
        static_addresses={"canary.test": "1.1.1.1"},
    )
    response = gateway.resolve(query, "192.0.2.10")
    assert struct.unpack("!HHHHHH", response[:12])[5] == 0
    assert checked_response(query, response)[2] == ("1.1.1.1",)


def test_dns_lease_is_bound_to_both_hostname_and_address(monkeypatch) -> None:
    now = 1000.0
    monkeypatch.setattr("controlled_dev_machine.dns_gateway.time.time", lambda: now)
    registry = LeaseRegistry(max_ttl_seconds=300, expiry_grace_seconds=0)
    lease_id = registry.grant("api.example.com", ("93.184.216.34",), 60)
    assert lease_id is not None and len(lease_id) == 32
    assert registry.authorize("api.example.com", "93.184.216.34") == lease_id
    assert registry.authorize("other.example.com", "93.184.216.34") is None
    assert registry.authorize("api.example.com", "1.1.1.1") is None

    now = 1061.0
    assert registry.authorize("api.example.com", "93.184.216.34") is None


def test_dns_lease_tolerates_a_bounded_client_cache_overrun(monkeypatch) -> None:
    now = 1000.0
    monkeypatch.setattr("controlled_dev_machine.dns_gateway.time.time", lambda: now)
    registry = LeaseRegistry(max_ttl_seconds=300, expiry_grace_seconds=60)
    lease_id = registry.grant("api.example.com", ("93.184.216.34",), 22)

    now = 1025.0
    assert registry.authorize("api.example.com", "93.184.216.34") == lease_id
    assert registry.authorize("api.example.com", "1.1.1.1") is None

    now = 1083.0
    assert registry.authorize("api.example.com", "93.184.216.34") is None


def test_lease_server_handles_a_normal_parallel_request_burst(tmp_path) -> None:
    registry = LeaseRegistry()
    lease_id = registry.grant("api.example.com", ("93.184.216.34",), 60)
    _LeaseHandler.registry = registry
    socket_path = tmp_path / "lease.sock"
    server = _LeaseServer(str(socket_path), _LeaseHandler)
    assert server.max_workers == 16
    assert server.request_queue_size == 128
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    clients = 64
    barrier = threading.Barrier(clients)
    request = b'{"hostname":"api.example.com","address":"93.184.216.34"}\n'

    def lookup() -> str | None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(2)
                barrier.wait(timeout=2)
                connection.connect(str(socket_path))
                connection.sendall(request)
                response = json.loads(connection.recv(4096))
                return response.get("lease_id") if response.get("allowed") else None
        except (OSError, ValueError, json.JSONDecodeError, threading.BrokenBarrierError):
            return None

    try:
        with ThreadPoolExecutor(max_workers=clients) as executor:
            results = tuple(executor.map(lambda _: lookup(), range(clients)))
        assert results == (lease_id,) * clients
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_dns_worker_pools_fit_the_container_pid_budget() -> None:
    assert _UdpServer.max_workers == 48
    assert _TcpServer.max_workers == 48
    assert _LeaseServer.max_workers == 16
    assert _UdpServer.max_workers + _TcpServer.max_workers + _LeaseServer.max_workers < 128


def test_public_doh_queries_are_not_serialized(monkeypatch) -> None:
    client = DohClient(
        DohEndpoint(
            proxy_host="127.0.0.1",
            proxy_port=11440,
            address="1.1.1.1",
            server_name="cloudflare-dns.com",
            path="/dns-query",
        )
    )
    clients = 8
    barrier = threading.Barrier(clients)

    def query_once(packet: bytes):
        barrier.wait(timeout=2)
        return packet, {}

    monkeypatch.setattr(client, "_query_once", query_once)
    packets = tuple(_query(f"parallel-{index}.example") for index in range(clients))
    with ThreadPoolExecutor(max_workers=clients) as executor:
        results = tuple(executor.map(client.query, packets))

    assert tuple(result[0] for result in results) == packets


def test_connection_binding_survives_dns_lease_expiry() -> None:
    class Connection:
        pass

    connection = Connection()
    other_connection = Connection()
    registry = ConnectionBindingRegistry()
    binding = DestinationBinding(
        hostname="api.example.com",
        address="93.184.216.34",
        port=443,
        scheme="https",
        sni="api.example.com",
        lease_id="a" * 32,
    )

    lookups = 0

    def lease_lookup() -> str | None:
        nonlocal lookups
        lookups += 1
        return binding.lease_id

    assert registry.get_or_authorize(
        connection,
        hostname=binding.hostname,
        address=binding.address,
        port=binding.port,
        scheme=binding.scheme,
        sni=binding.sni,
        lease_lookup=lease_lookup,
    ) == binding
    assert lookups == 1

    def expired_lease_lookup() -> str | None:
        nonlocal lookups
        lookups += 1
        return None

    assert registry.get_or_authorize(
        connection,
        hostname=binding.hostname,
        address=binding.address,
        port=binding.port,
        scheme=binding.scheme,
        sni=binding.sni,
        lease_lookup=expired_lease_lookup,
    ) == binding
    assert lookups == 1

    assert (
        registry.get_or_authorize(
            other_connection,
            hostname=binding.hostname,
            address=binding.address,
            port=binding.port,
            scheme=binding.scheme,
            sni=binding.sni,
            lease_lookup=expired_lease_lookup,
        )
        is None
    )
    assert lookups == 2

    assert (
        registry.find(
            connection,
            "api.example.com",
            "93.184.216.34",
            443,
            "https",
            "api.example.com",
        )
        == binding
    )
    assert (
        registry.find(
            other_connection,
            "api.example.com",
            "93.184.216.34",
            443,
            "https",
            "api.example.com",
        )
        is None
    )
    assert (
        registry.find(
            connection,
            "other.example.com",
            "93.184.216.34",
            443,
            "https",
            "other.example.com",
        )
        is None
    )


def test_dns_zero_ttl_does_not_create_an_egress_lease(monkeypatch) -> None:
    monkeypatch.setattr("controlled_dev_machine.dns_gateway.time.time", lambda: 1000.0)
    registry = LeaseRegistry(max_ttl_seconds=300)

    assert registry.grant("api.example.com", ("93.184.216.34",), 0) is None
    assert registry.authorize("api.example.com", "93.184.216.34") is None


def test_strict_dns_only_allows_declared_exact_and_suffix_domains(tmp_path) -> None:
    gateway = DnsGateway(
        client=object(),  # type: ignore[arg-type]
        record_path=tmp_path / "dns.jsonl",
        allowed_exact=("api.anthropic.com",),
        allowed_suffix=("github.com",),
    )
    assert gateway._domain_allowed("api.anthropic.com")
    assert not gateway._domain_allowed("other.anthropic.com")
    assert gateway._domain_allowed("github.com")
    assert gateway._domain_allowed("raw.github.com")
    assert not gateway._domain_allowed("notgithub.com")


def test_strict_dns_rejects_unknown_name_before_doh(tmp_path) -> None:
    class Client:
        def query(self, _packet: bytes):
            raise AssertionError("strict DNS leaked an unknown name to DoH")

    record_path = tmp_path / "dns.jsonl"
    gateway = DnsGateway(
        client=Client(),  # type: ignore[arg-type]
        record_path=record_path,
        allowed_exact=("api.anthropic.com",),
    )

    response = gateway.resolve(_query("host-secret.attacker.example"), "172.28.0.3")
    assert struct.unpack("!H", response[2:4])[0] & 0x000F == 2
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["name"] == "host-secret.attacker.example"
    assert record["action"] == "servfail"
    assert "未被当前策略放行" in record["reason"]


def test_dns_rejects_unknown_query_type_before_doh(tmp_path) -> None:
    class Client:
        def query(self, _packet: bytes):
            raise AssertionError("DNS leaked a non-address query type to DoH")

    record_path = tmp_path / "dns.jsonl"
    gateway = DnsGateway(
        client=Client(),  # type: ignore[arg-type]
        record_path=record_path,
        allowed_exact=("api.anthropic.com",),
    )

    response = gateway.resolve(_query("api.anthropic.com", query_type=16), "172.28.0.3")
    assert struct.unpack("!H", response[2:4])[0] & 0x000F == 2
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["action"] == "servfail"
    assert "查询类型不允许" in record["reason"]


def test_dns_tcp_server_has_timeout_and_bounded_workers() -> None:
    assert _TcpServer.max_workers == 48


def test_checked_response_rejects_private_metadata_and_rebinding_answers() -> None:
    for value in ("127.0.0.1", "10.23.4.5", "169.254.169.254", "fd00::5"):
        query, response = _response(value)
        with pytest.raises(ValueError, match="非公网地址"):
            checked_response(query, response)


def test_checked_response_rejects_mismatched_or_truncated_response() -> None:
    query, response = _response("93.184.216.34")
    with pytest.raises(ValueError, match="ID"):
        checked_response(query, b"\x99\x99" + response[2:])
    truncated = bytearray(response)
    truncated[2:4] = struct.pack("!H", 0x8380)
    with pytest.raises(ValueError, match="截断"):
        checked_response(query, bytes(truncated))


def test_checked_response_rejects_private_https_ipv4hint() -> None:
    query = _query(query_type=65)
    # priority=1, root target name, ipv4hint key=4, length=4
    rdata = struct.pack("!H", 1) + b"\0" + struct.pack("!HH", 4, 4) + socket.inet_aton(
        "192.168.1.10"
    )
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 65, 1, 60, len(rdata)) + rdata
    with pytest.raises(ValueError, match="非公网地址"):
        checked_response(query, header + query[12:] + answer)


def test_checked_response_ignores_unrelated_additional_address() -> None:
    query = _query()
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 1)
    answer = _record(b"\xc0\x0c", 1, socket.inet_aton("93.184.216.34"))
    additional = _record(
        _name("unrelated.example"),
        1,
        socket.inet_aton("1.1.1.1"),
    )

    assert checked_response(query, header + query[12:] + answer + additional)[2] == (
        "93.184.216.34",
    )


def test_checked_response_rejects_nxdomain_with_additional_address() -> None:
    query = _query()
    header = struct.pack("!HHHHHH", 0x1234, 0x8183, 1, 0, 0, 1)
    additional = _record(
        _name("unrelated.example"),
        1,
        socket.inet_aton("1.1.1.1"),
    )

    with pytest.raises(ValueError, match="RCODE"):
        checked_response(query, header + query[12:] + additional)


def test_checked_response_accepts_only_the_query_cname_chain() -> None:
    query = _query()
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 3, 0, 0)
    cname = _record(b"\xc0\x0c", 5, _name("target.example"))
    target = _record(
        _name("target.example"),
        1,
        socket.inet_aton("93.184.216.34"),
    )
    unrelated = _record(
        _name("unrelated.example"),
        1,
        socket.inet_aton("1.1.1.1"),
    )

    assert checked_response(query, header + query[12:] + cname + target + unrelated)[2] == (
        "93.184.216.34",
    )


def test_checked_response_uses_shortest_cname_chain_ttl() -> None:
    query = _query()
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0)
    cname = _record(b"\xc0\x0c", 5, _name("target.example"), ttl=1)
    target = _record(
        _name("target.example"),
        1,
        socket.inet_aton("93.184.216.34"),
        ttl=300,
    )

    assert checked_response(query, header + query[12:] + cname + target)[3] == 1


def test_checked_response_rejects_ambiguous_cname_owner() -> None:
    query = _query()
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 3, 0, 0)
    first = _record(b"\xc0\x0c", 5, _name("first.example"))
    second = _record(b"\xc0\x0c", 5, _name("second.example"))
    target = _record(
        _name("first.example"),
        1,
        socket.inet_aton("93.184.216.34"),
    )

    with pytest.raises(ValueError, match="歧义 CNAME"):
        checked_response(query, header + query[12:] + first + second + target)


def test_dns_log_failure_cannot_create_a_lease(monkeypatch, tmp_path) -> None:
    query, response = _response("93.184.216.34")

    class Client:
        def query(self, packet: bytes):
            assert packet == query
            return response, {}

    registry = LeaseRegistry()
    gateway = DnsGateway(
        Client(),  # type: ignore[arg-type]
        tmp_path / "dns.jsonl",
        lease_registry=registry,
        allow_public_domains=True,
    )

    def fail_record(_record):
        raise OSError("audit disk failure")

    monkeypatch.setattr(gateway, "_write_record", fail_record)
    with pytest.raises(OSError, match="audit disk failure"):
        gateway.resolve(query, "192.0.2.10")
    assert registry.authorize("example.com", "93.184.216.34") is None


def test_dns_log_records_the_effective_lease_ttl(tmp_path) -> None:
    query, response = _response("93.184.216.34")

    class Client:
        def query(self, packet: bytes):
            assert packet == query
            return response, {"cf-ray": "fixture-region"}

    record_path = tmp_path / "dns.jsonl"
    gateway = DnsGateway(
        Client(),  # type: ignore[arg-type]
        record_path,
        allow_public_domains=True,
    )

    assert gateway.resolve(query, "192.0.2.10") == response
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["effective_ttl"] == 60
    assert record["lease_grace_seconds"] == 60
    assert record["lease_id"]


def test_doh_client_retries_once_on_transient_fixed_path_failure(monkeypatch) -> None:
    client = DohClient(
        DohEndpoint(
            proxy_host="proxy.test",
            proxy_port=11450,
            address="1.1.1.1",
            server_name="cloudflare-dns.com",
            path="/dns-query",
        )
    )
    attempts = 0

    def query_once(packet: bytes):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TimeoutError("cold tunnel handshake timed out")
        return packet, {}

    monkeypatch.setattr(client, "_query_once", query_once)
    assert client.query(b"query") == (b"query", {})
    assert attempts == 2


def test_dns_cached_fallback_cannot_outlive_the_validated_lease(monkeypatch, tmp_path) -> None:
    now = 1000.0
    monkeypatch.setattr("controlled_dev_machine.dns_gateway.time.time", lambda: now)
    first_query, first_response = _response("93.184.216.34")

    class Client:
        calls = 0

        def query(self, packet: bytes):
            self.calls += 1
            if self.calls == 1:
                assert packet == first_query
                return first_response, {}
            raise OSError("temporary DoH failure")

    record_path = tmp_path / "dns.jsonl"
    registry = LeaseRegistry(max_ttl_seconds=300, expiry_grace_seconds=60)
    gateway = DnsGateway(
        Client(),  # type: ignore[arg-type]
        record_path,
        lease_registry=registry,
        allow_public_domains=True,
    )

    assert gateway.resolve(first_query, "192.0.2.10") == first_response
    now = 1090.0
    retry_query = b"\x56\x78" + first_query[2:]
    cached = gateway.resolve(retry_query, "192.0.2.10")
    assert cached[:2] == retry_query[:2]
    assert checked_response(retry_query, cached)[2:] == (("93.184.216.34",), 0)
    assert registry.authorize("example.com", "93.184.216.34") is not None
    records = [json.loads(line) for line in record_path.read_text(encoding="utf-8").splitlines()]
    assert records[-1]["action"] == "cached-pending"
    assert records[-1]["effective_ttl"] == 0
    assert records[-1]["lease_grace_seconds"] == 0
    assert records[-1]["fallback_reason"] == "OSError: temporary DoH failure"
    assert records[-1]["lease_expires_at"] == "1970-01-01T00:18:40+00:00"

    now = 1121.0
    expired = gateway.resolve(retry_query, "192.0.2.10")
    assert struct.unpack("!H", expired[2:4])[0] & 0x000F == 2
    assert registry.authorize("example.com", "93.184.216.34") is None


def test_dns_cached_fallback_rejects_subsecond_remaining_lease(monkeypatch, tmp_path) -> None:
    now = 1000.0
    monkeypatch.setattr("controlled_dev_machine.dns_gateway.time.time", lambda: now)
    query, response = _response("93.184.216.34")

    class Client:
        calls = 0

        def query(self, _packet: bytes):
            self.calls += 1
            if self.calls == 1:
                return response, {}
            raise OSError("temporary DoH failure")

    gateway = DnsGateway(
        Client(),  # type: ignore[arg-type]
        tmp_path / "dns.jsonl",
        allow_public_domains=True,
    )
    assert gateway.resolve(query, "192.0.2.10") == response

    now = 1119.5
    fallback = gateway.resolve(query, "192.0.2.10")
    assert struct.unpack("!H", fallback[2:4])[0] & 0x000F == 2


def test_dns_response_cache_is_bounded_and_purges_expired_entries(monkeypatch, tmp_path) -> None:
    now = 1000.0
    monkeypatch.setattr("controlled_dev_machine.dns_gateway.time.time", lambda: now)
    monkeypatch.setattr("controlled_dev_machine.dns_gateway._DNS_CACHE_MAX_ENTRIES", 2)
    registry = LeaseRegistry(expiry_grace_seconds=0)
    gateway = DnsGateway(
        object(),  # type: ignore[arg-type]
        tmp_path / "dns.jsonl",
        lease_registry=registry,
    )

    gateway._cache_response("first.example", 1, b"first", ("1.1.1.1",), 60)
    gateway._cache_response("second.example", 1, b"second", ("8.8.8.8",), 1)
    gateway._cache_response("third.example", 1, b"third", ("9.9.9.9",), 60)
    assert gateway._cached_response("first.example", 1) is None
    assert len(gateway._response_cache) == 2

    now = 1002.0
    gateway._cache_response("fourth.example", 1, b"fourth", ("1.0.0.1",), 60)
    assert gateway._cached_response("second.example", 1) is None
    assert len(gateway._response_cache) == 2


def test_dns_cached_fallback_ttl_stays_zero_across_slow_audit(monkeypatch, tmp_path) -> None:
    now = 1000.0
    monkeypatch.setattr("controlled_dev_machine.dns_gateway.time.time", lambda: now)
    query, response = _response("93.184.216.34")

    class Client:
        calls = 0

        def query(self, _packet: bytes):
            self.calls += 1
            if self.calls == 1:
                return response, {}
            raise OSError("temporary DoH failure")

    registry = LeaseRegistry(expiry_grace_seconds=60)
    gateway = DnsGateway(
        Client(),  # type: ignore[arg-type]
        tmp_path / "dns.jsonl",
        lease_registry=registry,
        allow_public_domains=True,
    )
    assert gateway.resolve(query, "192.0.2.10") == response
    original_write = gateway._write_record

    def slow_write(record):
        nonlocal now
        original_write(record)
        now += 2.0

    monkeypatch.setattr(gateway, "_write_record", slow_write)
    now = 1110.0
    fallback = gateway.resolve(query, "192.0.2.10")
    assert checked_response(query, fallback)[3] == 0
    assert registry.authorize("example.com", "93.184.216.34") is not None

    now = 1120.0
    assert registry.authorize("example.com", "93.184.216.34") is None


def test_dns_expired_during_audit_never_records_cached_allow(monkeypatch, tmp_path) -> None:
    now = 1000.0
    monkeypatch.setattr("controlled_dev_machine.dns_gateway.time.time", lambda: now)
    query, response = _response("93.184.216.34")

    class Client:
        calls = 0

        def query(self, _packet: bytes):
            self.calls += 1
            if self.calls == 1:
                return response, {}
            raise OSError("temporary DoH failure")

    record_path = tmp_path / "dns.jsonl"
    gateway = DnsGateway(
        Client(),  # type: ignore[arg-type]
        record_path,
        lease_registry=LeaseRegistry(expiry_grace_seconds=0),
        allow_public_domains=True,
    )
    assert gateway.resolve(query, "192.0.2.10") == response
    original_write = gateway._write_record

    def slow_write(record):
        nonlocal now
        original_write(record)
        if record["action"] == "cached-pending":
            now += 3.0

    monkeypatch.setattr(gateway, "_write_record", slow_write)
    now = 1058.0
    failed = gateway.resolve(query, "192.0.2.10")
    assert struct.unpack("!H", failed[2:4])[0] & 0x000F == 2
    records = [json.loads(line) for line in record_path.read_text(encoding="utf-8").splitlines()]
    assert records[-2]["action"] == "cached-pending"
    assert records[-1]["action"] == "servfail"
    assert all(record["action"] != "cached-allow" for record in records)
