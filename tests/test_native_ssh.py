import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import threading

import pytest

from controlled_dev_machine.ssh_native_client import delegation_argv, destination_for_audit, host_main
from controlled_dev_machine.ssh_alias_bridge import Server, Transport, header, target_config
from controlled_dev_machine.ssh_client_state import SSHClientState


def profile():
    return {'ssh_host_alias': 'this-machine', 'ssh_host_python': '/private/python',
            'ssh_host_launcher': '/private/release/bin/ssh-native-host',
            'ssh_host_audit': '/private/audit/native.jsonl'}


def test_native_delegation_preserves_arguments_across_remote_shell_boundary():
    original = ['-J', 'one,two', '-oProxyCommand=custom-helper %h %p', 'worker@host',
                "printf '%s' 'a b'; literal=$(value)"]
    args = delegation_argv(original, profile())
    # A shell sees exactly the original inner SSH arguments, not expanded data.
    assert shlex.split(args[-1]) == ['/private/python', '-I',
        '/private/release/bin/ssh-native-host', '--audit', '/private/audit/native.jsonl', '--', *original]
    assert args[-2] == 'this-machine' and args[1] == '-T'
    assert '-oClearAllForwardings=yes' in args and '-e' in args
    assert delegation_argv(original, profile(), terminal=True)[1] == '-tt'
    assert delegation_argv(['-V'], profile()) == ['/opt/sbc/libexec/ssh', '-V']


def test_host_launcher_executes_native_ssh_and_does_not_log_commands(tmp_path, monkeypatch):
    audit = tmp_path / 'audit.jsonl'
    calls = []
    monkeypatch.setattr(os, 'execv', lambda path, argv: calls.append((path, argv)))
    args = ['-oBatchMode=yes', 'host', 'echo private-value']
    host_main(['--audit', str(audit), '--', *args])
    assert calls == [('/usr/bin/ssh', ['/usr/bin/ssh', *args])]
    entry = json.loads(audit.read_text())
    assert entry['destination'] == 'host'
    assert 'private-value' not in audit.read_text()
    assert entry['argc'] == len(args)


def test_audit_failure_does_not_execute_native_client(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(os, 'execv', lambda *args: calls.append(args))
    with pytest.raises(OSError):
        host_main(['--audit', str(tmp_path / 'missing/file'), '--', 'host'])
    assert not calls


def test_destination_metadata_never_controls_argument_acceptance():
    assert destination_for_audit(['-p', '2222', '-oBatchMode=yes', 'user@peer', 'date']) == 'user@peer'
    assert destination_for_audit(['--', 'peer']) == 'peer'
    args = ['-NewFutureOption', 'opaque', 'peer']
    assert shlex.split(delegation_argv(args, profile())[-1])[-len(args):] == args


def test_native_bootstrap_accepts_host_openssh_includes_without_reimplementing_them(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    root = home / '.ssh'
    root.mkdir(parents=True, mode=0o700)
    external = tmp_path / 'operator-config'
    external.write_text('Host this-machine\n HostName 192.0.2.10\n User worker\n'
                        'Host *.example\n ProxyCommand arbitrary-helper %h %p\n')
    (root / 'config').write_text(f'Include {external}\n')
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: home))
    rendered = target_config(root / 'config', '/socket', '/agent',
                             target_home=Path('/home/sandbox'), host_alias='this-machine')
    assert 'Host this-machine' in rendered and 'HostName 192.0.2.10' in rendered
    assert 'arbitrary-helper' not in rendered  # Destination routing stays on host.
    sync = SSHClientState(root, tmp_path / 'client', Path('/home/sandbox'), host_alias='this-machine')
    sync.refresh()
    external.write_text(external.read_text().replace('192.0.2.10', '192.0.2.11'))
    assert sync.refresh()
    assert 'HostName 192.0.2.11' in (tmp_path / 'client/config').read_text()
    assert not sync.refresh()


def test_bridge_rejection_returns_real_reason_instead_of_incomplete_request(tmp_path, monkeypatch):
    config = tmp_path / 'config'
    config.write_text('Host peer\n HostName 192.0.2.99\n ProxyCommand custom-helper %h %p\n')
    config.chmod(0o600)
    tmp_path.chmod(0o700)
    import controlled_dev_machine.ssh_alias_bridge as bridge
    monkeypatch.setattr(bridge, 'route_plan', lambda *a, **kw: (_ for _ in ()).throw(ValueError('Unsupported test route')))
    with Server(tmp_path / 'bridge.sock', config, tmp_path / 'audit', Transport) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(str(tmp_path / 'bridge.sock'))
                client.sendall(b'{"alias":"peer","host":"192.0.2.99","port":22}\n')
                assert header(client) == {'ok': False, 'error': 'Unsupported test route'}
        finally:
            server.shutdown()
            thread.join()
