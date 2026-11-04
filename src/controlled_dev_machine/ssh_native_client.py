"""Delegate ordinary SSH to the host's OpenSSH through the existing host channel.

OpenSSH owns routing, authentication, terminal handling and its configuration
language. The sandbox transport does not interpret individual ProxyCommands.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys
import uuid
from datetime import datetime, timezone

NATIVE_SSH = '/opt/sbc/libexec/ssh'
ALIAS = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')


def delegation_argv(argv, profile, *, terminal=False, native_ssh=NATIVE_SSH):
    alias = profile.get('ssh_host_alias')
    if not alias or argv == ['-V']:
        return [native_ssh, *argv]
    if not ALIAS.fullmatch(alias):
        raise ValueError('invalid configured SSH host alias')
    python, launcher, audit = (profile[k] for k in
                              ('ssh_host_python', 'ssh_host_launcher', 'ssh_host_audit'))
    for path in (python, launcher, audit):
        if not isinstance(path, str) or not path.startswith('/') or '\0' in path:
            raise ValueError('invalid configured host SSH launcher path')
    # One remote command string preserves the original argv across the outer
    # OpenSSH command's remote-shell boundary. The inner OpenSSH gets each
    # original argument unchanged, including spaces and shell metacharacters.
    command = shlex.join([python, '-I', launcher, '--audit', audit, '--', *argv])
    return [native_ssh, '-tt' if terminal else '-T', '-e', 'none',
            '-oClearAllForwardings=yes', '-oForwardAgent=no',
            '-oPermitLocalCommand=no', '-oControlMaster=no', '-S', 'none',
            alias, command]


def destination_for_audit(argv):
    """Best-effort metadata only; unknown options never reject an SSH command."""
    takes_value = set('BbcDEeFIiJLlmOopPRS Ww'.replace(' ', ''))
    flags = set('46AaCfGgKkMNnqsTtVvXxYy')
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == '--':
            i += 1
            break
        if not arg.startswith('-') or arg == '-':
            break
        for position, option in enumerate(arg[1:], 1):
            if option in takes_value:
                if position == len(arg) - 1:
                    i += 1
                break
            if option not in flags:
                return None
        i += 1
    if i < len(argv) and re.fullmatch(r'[A-Za-z0-9_.@:\[\]-]{1,253}', argv[i]):
        return argv[i]
    return None


def host_main(argv=None):
    parser = argparse.ArgumentParser(description='Audited native host OpenSSH launcher')
    parser.add_argument('--audit', required=True, type=Path)
    parser.add_argument('ssh_args', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    ssh_args = args.ssh_args
    if ssh_args[:1] == ['--']:
        ssh_args = ssh_args[1:]
    record = {'time': datetime.now(timezone.utc).isoformat(), 'kind': 'native-ssh',
              'session_id': uuid.uuid4().hex, 'argc': len(ssh_args),
              'destination': destination_for_audit(ssh_args),
              'argv_sha256': hashlib.sha256(json.dumps(ssh_args).encode()).hexdigest(),
              'result': 'exec-native-client'}
    # Never record remote commands, ProxyCommand text, credentials or payload.
    fd = os.open(args.audit, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as file:
        file.write(json.dumps(record) + '\n')
        file.flush()
        os.fsync(file.fileno())
    os.execv('/usr/bin/ssh', ['/usr/bin/ssh', *ssh_args])


def main():
    try:
        profile = json.loads(Path('/run/cdm/sandbox.json').read_text())
        args = delegation_argv(sys.argv[1:], profile,
                               terminal=os.isatty(0) and os.isatty(1))
        os.execv(args[0], args)
    except (OSError, ValueError, KeyError) as error:
        print(f'ssh: sandbox host delegation failed: {error}', file=sys.stderr)
        return 255


if __name__ == '__main__':
    raise SystemExit(main())
