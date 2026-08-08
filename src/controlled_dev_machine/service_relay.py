from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import signal
import sys
from contextlib import suppress


class ServiceRelay:
    """Expose a fixed host TCP range to the same ports on one target address."""

    def __init__(
        self,
        bind_address: str,
        start_port: int,
        end_port: int,
        target_address: str,
        *,
        max_connections: int = 1024,
    ) -> None:
        self.bind_address = _ipv4(bind_address)
        self.start_port = _port(start_port)
        self.end_port = _port(end_port)
        if self.start_port > self.end_port:
            raise ValueError("service port range is not ordered")
        self.target_address = _ipv4(target_address)
        if max_connections < 1:
            raise ValueError("max_connections must be positive")
        self.max_connections = max_connections
        self._servers: list[asyncio.AbstractServer] = []
        self._connections: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        loop = asyncio.get_running_loop()

        def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            if len(self._connections) >= self.max_connections:
                writer.close()
                return
            port = int(writer.get_extra_info("sockname")[1])
            task = loop.create_task(self._proxy(reader, writer, port))
            self._connections.add(task)
            task.add_done_callback(self._connection_done)

        try:
            for port in range(self.start_port, self.end_port + 1):
                server = await asyncio.start_server(
                    accept,
                    host=self.bind_address,
                    port=port,
                    start_serving=True,
                )
                self._servers.append(server)
        except Exception:
            await self.close()
            raise

    async def close(self) -> None:
        for server in self._servers:
            server.close()
        await asyncio.gather(
            *(server.wait_closed() for server in self._servers), return_exceptions=True
        )
        self._servers.clear()
        if self._connections:
            for task in self._connections:
                task.cancel()
            await asyncio.gather(*self._connections, return_exceptions=True)

    def _connection_done(self, task: asyncio.Task[None]) -> None:
        self._connections.discard(task)
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            print(f"service relay connection failed: {exc}", file=sys.stderr, flush=True)

    async def wait(self) -> None:
        stopped = asyncio.Event()
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGINT, signal.SIGTERM):
            with suppress(NotImplementedError, RuntimeError):
                loop.add_signal_handler(signum, stopped.set)
        await stopped.wait()

    async def _proxy(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        port: int,
    ) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_address, port), timeout=5
            )
            await asyncio.gather(
                _copy(client_reader, upstream_writer),
                _copy(upstream_reader, client_writer),
            )
        except (OSError, TimeoutError):
            pass
        finally:
            client_writer.close()
            if upstream_writer is not None:
                upstream_writer.close()
            waiters = [client_writer.wait_closed()]
            if upstream_writer is not None:
                waiters.append(upstream_writer.wait_closed())
            await asyncio.gather(
                *waiters,
                return_exceptions=True,
            )


async def _copy(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while data := await reader.read(64 * 1024):
        writer.write(data)
        await writer.drain()
    with suppress(AttributeError, OSError):
        writer.write_eof()


def _ipv4(value: str) -> str:
    address = ipaddress.ip_address(value)
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("service relay only accepts IPv4 addresses")
    return str(address)


def _port(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1024 <= value <= 65535:
        raise ValueError("service relay port must be between 1024 and 65535")
    return value


def _drop_privileges(uid: int, gid: int) -> None:
    if os.geteuid() != 0:
        if os.getuid() != uid or os.getgid() != gid:
            raise PermissionError("service relay is not running as its configured user")
        return
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def _enter_network_namespace(path: str) -> None:
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("target network namespace path must be absolute")
    if not hasattr(os, "setns") or not hasattr(os, "CLONE_NEWNET"):
        raise RuntimeError("service relay requires Python with os.setns support")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.setns(descriptor, os.CLONE_NEWNET)
    finally:
        os.close(descriptor)


async def _run(args: argparse.Namespace) -> None:
    relay = ServiceRelay(
        args.bind_address,
        args.start,
        args.end,
        "127.0.0.1",
        max_connections=args.max_connections,
    )
    await relay.start()
    try:
        _enter_network_namespace(args.target_netns)
        _drop_privileges(args.uid, args.gid)
        print("service relay ready", file=sys.stderr, flush=True)
        await relay.wait()
    finally:
        await relay.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="controlled same-port TCP service relay")
    parser.add_argument("--bind-address", required=True)
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--end", type=int, required=True)
    parser.add_argument("--target-netns", required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--max-connections", type=int, default=1024)
    args = parser.parse_args()
    try:
        asyncio.run(_run(args))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"service relay stopped: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
