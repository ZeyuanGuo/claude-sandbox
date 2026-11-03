from __future__ import annotations

import asyncio

import pytest

from controlled_dev_machine.service_relay import ServiceRelay, _enter_network_namespace


def test_service_relay_forwards_the_same_tcp_port() -> None:
    async def scenario() -> None:
        async def echo(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            data = await reader.read()
            writer.write(data)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        upstream = await asyncio.start_server(echo, "127.0.0.2", 0)
        port = int(upstream.sockets[0].getsockname()[1])
        relay = ServiceRelay("127.0.0.1", port, port, "127.0.0.2")
        try:
            await relay.start()
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"same-port relay")
            await writer.drain()
            writer.write_eof()

            assert await reader.read() == b"same-port relay"

            writer.close()
            await writer.wait_closed()
        finally:
            await relay.close()
            upstream.close()
            await upstream.wait_closed()

    asyncio.run(scenario())


def test_service_relay_rejects_invalid_ranges_and_ipv6() -> None:
    with pytest.raises(ValueError, match="not ordered"):
        ServiceRelay("127.0.0.1", 25001, 25000, "127.0.0.2")
    with pytest.raises(ValueError, match="IPv4"):
        ServiceRelay("::1", 25000, 25001, "127.0.0.2")


def test_service_relay_enters_the_fixed_target_network_namespace(monkeypatch) -> None:
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        "controlled_dev_machine.service_relay.os.open",
        lambda path, flags: calls.append(("open", path, flags)) or 17,
    )
    monkeypatch.setattr(
        "controlled_dev_machine.service_relay.os.setns",
        lambda descriptor, namespace: calls.append(
            ("setns", descriptor, namespace)
        ),
    )
    monkeypatch.setattr(
        "controlled_dev_machine.service_relay.os.close",
        lambda descriptor: calls.append(("close", descriptor)),
    )

    _enter_network_namespace("/proc/4321/ns/net")

    assert calls[0][0:2] == ("open", "/proc/4321/ns/net")
    assert calls[1] == ("setns", 17, 0x40000000)
    assert calls[2] == ("close", 17)
