"""New admission stays strict while admitted streams tolerate probe uncertainty."""
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import threading
import time

import pytest

from controlled_dev_machine.degraded_egress import RelayConfig, _Audit, _relay, exit_lease_valid
from controlled_dev_machine.exit_monitor import atomic_json


def lease(path, *, ok=True, wrong_exit=False, reason='probe-failed'):
    now = time.monotonic()
    value = dict(schema_version=1, ok=ok, expected_exit='198.51.100.87',
                 observed_exit='198.51.100.87' if ok else None,
                 parent_host='127.0.0.1', parent_port=18080,
                 boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                 checked_monotonic=now, expires_monotonic=now + 15, reason=reason,
                 probes=[{'ok': True, 'observed': '198.51.100.87'},
                         {'ok': False, 'error': 'curl-exit-28'}] if not ok else [])
    if wrong_exit:
        value['probes'][1] = {'ok': False, 'observed': '198.51.100.99'}
    atomic_json(path, value)


@contextmanager
def tunnel(tmp_path, grace=1.5):
    path = tmp_path / 'lease.json'
    lease(path)
    config = RelayConfig(audit_path=tmp_path / 'audit.jsonl', expected_exit='198.51.100.87',
                         exit_lease=path, upstream_host='127.0.0.1', upstream_port=18080,
                         established_grace_seconds=grace, idle_timeout=5)
    user, client = socket.socketpair()
    parent, remote = socket.socketpair()
    audit = _Audit(config.audit_path)
    result = []
    def work():
        try:
            result.append(_relay(client, parent, config, audit))
        finally:
            client.close()
            parent.close()
    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    user.settimeout(1)
    remote.settimeout(1)
    user.sendall(b'warm')
    assert remote.recv(4) == b'warm'
    try:
        yield user, remote, config, thread, result, audit
    finally:
        user.close()
        remote.close()
        thread.join(3)
        assert not thread.is_alive()


def retained(config):
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        if config.audit_path.exists() and '"retained"' in config.audit_path.read_text():
            return
        time.sleep(.01)
    pytest.fail('relay did not retain admitted stream')


def test_failed_probe_denies_new_admission_but_keeps_both_established_directions(tmp_path):
    with tunnel(tmp_path) as (user, remote, config, thread, result, audit):
        lease(config.exit_lease, ok=False)
        retained(config)
        assert not exit_lease_valid(config)
        user.sendall(bytes(range(256)))
        remote.sendall(b'already-generating-response')
        assert remote.recv(256) == bytes(range(256))
        assert user.recv(4096) == b'already-generating-response'
        assert thread.is_alive() and not result
        lease(config.exit_lease)
        user.sendall(b'after-recovery')
        assert remote.recv(14) == b'after-recovery'
        deadline = time.monotonic() + 1
        while 'verification-recovered' not in config.audit_path.read_text() and time.monotonic() < deadline:
            time.sleep(.01)
        records = [json.loads(s) for s in config.audit_path.read_text().splitlines()]
        assert [v['result'] for v in records] == ['retained', 'verification-recovered']


def test_probe_failure_cannot_preserve_a_connection_indefinitely(tmp_path):
    with tunnel(tmp_path, grace=.15) as (user, remote, config, thread, result, audit):
        lease(config.exit_lease, ok=False)
        retained(config)
        thread.join(1)
        assert result == ['exit-verification-grace-expired']
        assert user.recv(1) == b'' and remote.recv(1) == b''


@pytest.mark.parametrize('mutation', ['wrong-exit', 'wrong-parent', 'wrong-boot', 'bad-json', 'readiness', 'missing'])
def test_wrong_identity_or_broken_control_state_closes_instead_of_waiting(tmp_path, mutation):
    with tunnel(tmp_path) as (user, remote, config, thread, result, audit):
        if mutation == 'wrong-exit':
            lease(config.exit_lease, ok=False, wrong_exit=True)
        elif mutation == 'readiness':
            lease(config.exit_lease, ok=False, reason='runtime-not-ready')
        elif mutation == 'bad-json':
            config.exit_lease.write_text('broken')
        elif mutation == 'missing':
            config.exit_lease.unlink()
        else:
            value = json.loads(config.exit_lease.read_text())
            if mutation == 'wrong-parent':value['parent_port'] += 1
            else:value['boot_id'] = 'another-boot'
            atomic_json(config.exit_lease, value)
        thread.join(.8)
        assert result == ['exit-lease-revoked']
        assert user.recv(1) == b''


def test_audit_failure_closes_a_retained_connection(tmp_path):
    with tunnel(tmp_path) as (user, remote, config, thread, result, audit):
        lease(config.exit_lease, ok=False)
        retained(config)
        audit.failed = True
        lease(config.exit_lease)
        thread.join(.8)
        assert result == ['audit-unavailable']


def test_expired_verification_does_not_interrupt_an_admitted_stream(tmp_path):
    with tunnel(tmp_path) as (user, remote, config, thread, result, audit):
        value = json.loads(config.exit_lease.read_text())
        value.update(checked_monotonic=time.monotonic() - 2, expires_monotonic=time.monotonic() - .1)
        atomic_json(config.exit_lease, value)
        retained(config)
        assert thread.is_alive() and not exit_lease_valid(config)
        lease(config.exit_lease)
        user.sendall(b'recovered')
        assert remote.recv(9) == b'recovered'


def test_repeated_failed_rounds_cannot_extend_the_established_grace(tmp_path):
    with tunnel(tmp_path, grace=.2) as (user, remote, config, thread, result, audit):
        for _ in range(6):
            lease(config.exit_lease, ok=False)
            time.sleep(.05)
        thread.join(1)
        assert result == ['exit-verification-grace-expired']


def test_restoring_an_old_success_cannot_reset_the_uncertainty_clock(tmp_path):
    with tunnel(tmp_path, grace=.2) as (user, remote, config, thread, result, audit):
        earlier = json.loads(config.exit_lease.read_text())
        lease(config.exit_lease, ok=False)
        retained(config)
        atomic_json(config.exit_lease, earlier)
        assert exit_lease_valid(config)
        thread.join(1)
        assert result == ['exit-verification-grace-expired']
