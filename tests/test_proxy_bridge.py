from __future__ import annotations

import socket
import threading

from controlled_dev_machine import proxy_bridge


def test_half_close_preserves_response_after_request_eof():
    client, relay_client = socket.socketpair()
    relay_peer, peer = socket.socketpair()
    for connection in (client, peer):
        connection.settimeout(2)
    worker = threading.Thread(target=proxy_bridge._relay,
                              args=(relay_client, relay_peer), daemon=True)
    worker.start()
    try:
        client.sendall(b"request")
        client.shutdown(socket.SHUT_WR)
        request = bytearray()
        while piece := peer.recv(1024):
            request.extend(piece)
        assert request == b"request"
        peer.sendall(b"response-after-eof")
        peer.shutdown(socket.SHUT_WR)
        response = bytearray()
        while piece := client.recv(1024):
            response.extend(piece)
        assert response == b"response-after-eof"
        worker.join(timeout=2)
        assert not worker.is_alive()
    finally:
        client.close()
        peer.close()
        relay_client.close()
        relay_peer.close()


def test_backpressure_keeps_large_payload_complete():
    client, relay_client = socket.socketpair()
    relay_peer, peer = socket.socketpair()
    relay_peer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    payload = bytes(range(256)) * 16384
    errors = []
    for connection in (client, peer):
        connection.settimeout(3)
    worker = threading.Thread(target=proxy_bridge._relay,
                              args=(relay_client, relay_peer), daemon=True)
    worker.start()

    def send():
        try:
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
        except OSError as exc:
            errors.append(exc)

    sender = threading.Thread(target=send, daemon=True)
    sender.start()
    try:
        received = bytearray()
        while piece := peer.recv(1024):
            received.extend(piece)
        peer.shutdown(socket.SHUT_WR)
        sender.join(timeout=3)
        worker.join(timeout=3)
        assert not errors
        assert not sender.is_alive()
        assert not worker.is_alive()
        assert received == payload
    finally:
        client.close()
        peer.close()
        relay_client.close()
        relay_peer.close()
