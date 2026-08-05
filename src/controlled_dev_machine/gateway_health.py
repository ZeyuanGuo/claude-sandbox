from __future__ import annotations

import os
import socket

HEALTH_HOST = "health.cdm.invalid"
HEALTH_PATH = "/__cdm_gateway_health"
HEALTH_REASON = "health-probe"


def probe_gateway() -> None:
    host = os.environ.get("CDM_GATEWAY_HEALTH_HOST", "127.0.0.1")
    port = int(os.environ.get("CDM_GATEWAY_HEALTH_PORT", "8080"))
    request = (
        f"GET http://{HEALTH_HOST}{HEALTH_PATH} HTTP/1.1\r\n"
        f"Host: {HEALTH_HOST}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    with socket.create_connection((host, port), 1) as connection:
        connection.sendall(request)
        response = connection.recv(4096).lower()
    if not response.startswith(b"http/1.1 403"):
        raise SystemExit(f"gateway health status is not 403: {response[:120]!r}")
    expected = f"x-cdm-block-reason: {HEALTH_REASON}".encode("ascii")
    if expected not in response:
        raise SystemExit(f"gateway addon health response is missing: {response[:240]!r}")


if __name__ == "__main__":
    probe_gateway()
