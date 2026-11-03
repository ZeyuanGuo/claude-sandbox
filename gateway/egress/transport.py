"""Lease-gated byte transport; HTTP/DNS policy remains in the existing gateway."""
import argparse
import socket

from pinned_relay import RelayConfig, RelayServer, _relay, _respond, exit_lease_valid
import socketserver
import json
from pathlib import Path


class TransportHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        config = server.config
        source = self.client_address[0]
        allowed = source in {config.gateway_source, config.dns_source, "127.0.0.1"}
        allowed = allowed and exit_lease_valid(config, newer_than=server.lease_started)
        try:
            server.audit.write(source=source, result="allow" if allowed else "reject",
                               reason="verified-exit-lease" if allowed else "source-or-exit-lease")
            if not allowed:
                _respond(self.request, 503)
                return
            with socket.create_connection((config.upstream_host, config.upstream_port),
                                          timeout=config.header_timeout) as parent:
                reason = _relay(self.request, parent, config, server.audit, server.lease_started)
            server.audit.write(source=source, result="closed", reason=reason)
        except OSError:
            return


class TransportServer(RelayServer):
    def __init__(self, config, address):
        if not config.expected_exit or config.exit_lease is None:
            raise ValueError("transparent transport requires an exit pin and lease")
        if not config.upstream_host or config.upstream_port is None:
            raise ValueError("transparent transport requires a fixed parent")
        super().__init__(config, address)
        self.RequestHandlerClass = TransportHandler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    config = RelayConfig.from_mapping(json.loads(args.config.read_text()), audit_path=args.audit)
    with TransportServer(config, ("0.0.0.0", args.port)) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
