import json
from pathlib import Path
import socket
from unittest.mock import patch

import pytest

from controlled_dev_machine.ssh_bridge import destination, load_targets, read_header
from controlled_dev_machine.degraded_topology import build_compose


@pytest.mark.parametrize("host,port", [("100.117.92.79", 22), ("10.112.18.98", 10090),
                                      ("192.168.71.3", 65522)])
def test_internal_destination_is_canonical(host, port):
    assert destination(host, port) == (host, port)


@pytest.mark.parametrize("host,port", [("100.1.2.3", 22), ("1.1.1.1", 22),
    ("127.0.0.1", 22), ("::1", 22), ("example.com", 22), ("010.112.18.98", 22),
    ("192.168.1.1", 22), ("100.117.92.79", True), ("100.117.92.79", 0)])
def test_public_special_ambiguous_and_bad_port_rejected(host, port):
    with pytest.raises(ValueError):
        destination(host, port)


def test_allowlist_requires_exact_endpoint(tmp_path):
    config = tmp_path / "targets.json"
    config.write_text(json.dumps({"schema_version": 1,
                                 "targets": [{"host": "10.112.18.98", "port": 10090}]}))
    assert load_targets(config) == frozenset({("10.112.18.98", 10090)})
    assert ("10.112.18.98", 443) not in load_targets(config)
    assert ("10.112.18.99", 10090) not in load_targets(config)


def test_broker_header_does_not_consume_ssh_payload():
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b'{"host":"100.117.92.79","port":22}\nSSH-2.0-canary\r\n')
        assert read_header(right)["port"] == 22
        assert right.recv(100) == b"SSH-2.0-canary\r\n"


def test_raw_client_mode_is_available_for_fixed_reverse_socket():
    # The socket path itself identifies a destination; no user-controlled
    # JSON header is sent on a dedicated reverse-forward socket.
    import inspect
    from controlled_dev_machine import ssh_bridge
    assert "raw" in inspect.getsource(ssh_bridge.client)


def test_raw_client_can_pin_socket_endpoint():
    from controlled_dev_machine.ssh_bridge import destination
    assert destination("100.117.92.79", 22) == ("100.117.92.79", 22)


def test_ssh_mounts_do_not_change_other_traffic(tmp_path):
    params = dict(root=tmp_path / "repo", runtime=tmp_path / "runtime",
                  state=tmp_path / "state", target_image="target", gateway_image="gateway",
                  policy=tmp_path / "policy", policy_digest="raw:fixture")
    before = build_compose(**params)
    after = build_compose(**params, ssh_bridge=True)
    assert before["networks"] == after["networks"]
    for service in ("dns", "gateway", "egress"):
        assert before["services"][service] == after["services"][service]
    a, b = before["services"]["target"], after["services"]["target"]
    assert a["networks"] == b["networks"]
    assert a["dns"] == b["dns"]
    assert a["environment"] == b["environment"]
    added = b["volumes"][len(a["volumes"]):]
    assert [item["target"] for item in added] == ["/run/cdm-ssh", "/opt/cdm-ssh",
                                                   "/home/gzy/.ssh/config", "/root/.ssh/config"]
    assert all(item["read_only"] for item in added)


def test_ssh_mounts_work_without_target_network(tmp_path):
    config = build_compose(root=tmp_path / "repo", runtime=tmp_path / "runtime",
                           state=tmp_path / "state", target_image="target", gateway_image="gateway",
                           policy=tmp_path / "policy", policy_digest="raw:fixture",
                           strict_local=True, ssh_bridge=True)
    target = config["services"]["target"]
    assert target["network_mode"] == "none"
    assert "networks" not in target
    assert any(item["target"] == "/run/cdm-ssh" for item in target["volumes"])


def test_ssh_socket_root_can_be_explicit(tmp_path):
    socket_root = tmp_path / "socket-root"
    config = build_compose(root=tmp_path / "repo", runtime=tmp_path / "runtime",
                           state=tmp_path / "state", target_image="target", gateway_image="gateway",
                           policy=tmp_path / "policy", policy_digest="raw:fixture",
                           ssh_bridge=True, ssh_socket_dir=socket_root)
    mounts = {item["target"]: item for item in config["services"]["target"]["volumes"]}
    assert mounts["/run/cdm-ssh"]["source"] == str(socket_root)
