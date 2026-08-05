from __future__ import annotations

import weakref
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class DestinationBinding:
    """A destination authorized for the lifetime of one client connection."""

    hostname: str
    address: str
    port: int
    scheme: str
    sni: str
    lease_id: str | None


class ConnectionBindingRegistry:
    """Keep DNS authorization scoped to the client connection that used it."""

    def __init__(self) -> None:
        self._bindings: weakref.WeakKeyDictionary[
            object, dict[tuple[str, str, int, str, str], DestinationBinding]
        ] = weakref.WeakKeyDictionary()

    def find(
        self,
        connection: object,
        hostname: str,
        address: str,
        port: int,
        scheme: str,
        sni: str,
    ) -> DestinationBinding | None:
        entries = self._bindings.get(connection)
        if entries is None:
            return None
        return entries.get((hostname, address, port, scheme, sni))

    def target(self, connection: object) -> tuple[str, int] | None:
        entries = self._bindings.get(connection)
        if not entries:
            return None
        binding = next(iter(entries.values()))
        return binding.address, binding.port

    def get_or_authorize(
        self,
        connection: object,
        *,
        hostname: str,
        address: str,
        port: int,
        scheme: str,
        sni: str,
        lease_lookup: Callable[[], str | None] | None,
    ) -> DestinationBinding | None:
        existing = self.find(connection, hostname, address, port, scheme, sni)
        if existing is not None:
            return existing
        lease_id = lease_lookup() if lease_lookup is not None else None
        if lease_lookup is not None and lease_id is None:
            return None
        binding = DestinationBinding(hostname, address, port, scheme, sni, lease_id)
        self.remember(connection, binding)
        return binding

    def remember(self, connection: object, binding: DestinationBinding) -> None:
        entries = self._bindings.setdefault(connection, {})
        entries[
            (binding.hostname, binding.address, binding.port, binding.scheme, binding.sni)
        ] = binding
