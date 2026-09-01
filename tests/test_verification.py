import subprocess
from pathlib import Path

from controlled_dev_machine.verification import (
    _finish_gateway_capture,
    _GatewayCapture,
)


def test_nonzero_capture_waits_for_packet_delivery(tmp_path: Path, monkeypatch) -> None:
    pcap_path = tmp_path / "capture.pcap"
    pcap_path.write_bytes(b"0" * 24)
    log_path = tmp_path / "capture.log"
    log_path.write_text("", encoding="utf-8")
    events: list[str] = []

    class Process:
        pid = 123
        returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

    process = Process()
    capture = _GatewayCapture(
        process=process,  # type: ignore[arg-type]
        pcap_path=pcap_path,
        log_path=log_path,
        metadata_path=tmp_path / "capture.json",
        started_at="start",
        ready_at="ready",
        capture_filter="dst port 11450",
    )

    def sleep(_seconds):
        events.append("sleep")
        with pcap_path.open("ab") as stream:
            stream.write(b"1")

    monkeypatch.setattr("controlled_dev_machine.verification.time.sleep", sleep)
    monkeypatch.setattr(
        "controlled_dev_machine.verification.os.killpg",
        lambda _pid, _signal: events.append("signal"),
    )
    monkeypatch.setattr(
        "controlled_dev_machine.verification.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 0, stdout="packet\n", stderr=""
        ),
    )

    evidence = _finish_gateway_capture(
        capture,
        packet_error="missing packet",
        packet_expectation="nonzero",
    )

    assert events[:2] == ["sleep", "signal"]
    assert evidence["packet_count"] == 1
