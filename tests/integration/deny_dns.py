from __future__ import annotations

import argparse
import json
import socketserver
import struct
import threading
from pathlib import Path


def _question(packet: bytes) -> tuple[str, int, int]:
    if len(packet) < 12:
        raise ValueError("short DNS packet")
    offset = 12
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        size = packet[offset]
        offset += 1
        if size == 0:
            break
        if size & 0xC0 or offset + size > len(packet):
            raise ValueError("compressed or truncated DNS question")
        labels.append(packet[offset : offset + size].decode("ascii", errors="replace"))
        offset += size
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS type")
    qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
    return ".".join(labels).lower(), qtype, offset + 4


def _nxdomain(packet: bytes, question_end: int) -> bytes:
    request_id = packet[:2]
    request_flags = struct.unpack("!H", packet[2:4])[0]
    flags = 0x8000 | (request_flags & 0x0100) | 0x0080 | 0x0003
    return request_id + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + packet[12:question_end]


class DnsHandlerMixin:
    record_path: Path

    def process(self, packet: bytes, peer: str) -> bytes | None:
        try:
            name, qtype, end = _question(packet)
        except ValueError:
            return None
        record = {"peer": peer, "name": name, "qtype": qtype, "action": "nxdomain"}
        with self.record_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return _nxdomain(packet, end)


class UdpHandler(socketserver.BaseRequestHandler, DnsHandlerMixin):
    def handle(self) -> None:
        packet, sock = self.request
        response = self.process(packet, self.client_address[0])
        if response is not None:
            sock.sendto(response, self.client_address)


class TcpHandler(socketserver.BaseRequestHandler, DnsHandlerMixin):
    def handle(self) -> None:
        header = self.request.recv(2)
        if len(header) != 2:
            return
        size = struct.unpack("!H", header)[0]
        packet = b""
        while len(packet) < size:
            chunk = self.request.recv(size - len(packet))
            if not chunk:
                return
            packet += chunk
        response = self.process(packet, self.client_address[0])
        if response is not None:
            self.request.sendall(struct.pack("!H", len(response)) + response)


class UdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record-path", type=Path, required=True)
    args = parser.parse_args()
    args.record_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    UdpHandler.record_path = args.record_path
    TcpHandler.record_path = args.record_path
    udp = UdpServer(("0.0.0.0", 53), UdpHandler)
    tcp = TcpServer(("0.0.0.0", 53), TcpHandler)
    thread = threading.Thread(target=udp.serve_forever, daemon=True)
    thread.start()
    tcp.serve_forever()


if __name__ == "__main__":
    main()
