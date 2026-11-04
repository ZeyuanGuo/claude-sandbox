"""Bridge approved SSH aliases through their host-owned routes and fixed agent.

Candidate for review. No remote installation or service activation is performed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import glob
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import threading

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
FIXED_AGENT = Path(f"/run/user/{os.getuid()}/fleet-campus-agent.sock")
HOSTNAME = re.compile(r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?\Z")


def aliases_from_config(config: Path, extra_roots: tuple[Path, ...] = ()) -> set[str]:
    """Read explicit aliases, including bounded Include files, from this Home."""
    root = Path.home()/'.ssh'
    roots = [root.resolve(), *[p.resolve() for p in extra_roots]]
    seen: set[Path] = set()
    names: set[str] = set()

    def read(path: Path) -> None:
        path = path.expanduser().resolve()
        if path in seen:
            return
        if len(seen) >= 32 or not any(path.is_relative_to(p) for p in roots):
            raise ValueError('SSH Include escapes the approved config directory')
        info = path.stat()
        if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise ValueError('SSH config must be owned and not group/world writable')
        seen.add(path)
        for line in path.read_text().splitlines():
            fields = shlex.split(line, comments=True)
            if not fields:
                continue
            if fields[0].lower() == 'host':
                names.update(x for x in fields[1:] if ALIAS.fullmatch(x))
            if fields[0].lower() == 'include':
                for pattern in fields[1:]:
                    item = Path(pattern).expanduser()
                    if not item.is_absolute():
                        item = root/item
                    for match in sorted(glob.glob(str(item))):
                        read(Path(match))

    read(config)
    return names


def effective(alias: str, config: Path, extra_roots: tuple[Path, ...] = (), *, native_config=False) -> dict[str, list[str]]:
    if not isinstance(alias, str) or not ALIAS.fullmatch(alias) or (not native_config and alias not in aliases_from_config(config, extra_roots)):
        raise ValueError('SSH alias is not explicitly configured')
    result = subprocess.run(['/usr/bin/ssh', '-G', '-F', str(config), alias],
                            capture_output=True, text=True, timeout=12, check=True)
    options: dict[str, list[str]] = {}
    for line in result.stdout.splitlines():
        key, value = line.split(' ', 1)
        options.setdefault(key, []).append(value)
    host = options['hostname'][0]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not HOSTNAME.fullmatch(host):
            raise ValueError('Invalid configured SSH hostname')
    if not 1 <= int(options['port'][0]) <= 65535:
        raise ValueError('Invalid configured port')
    return options


def route_plan(alias: str, config: Path, host: str, port: int, extra_roots: tuple[Path, ...] = (), *, host_alias=None):
    """Only three route forms exist; request data never becomes shell code."""
    if host_alias and alias != host_alias:
        raise ValueError('Use the native host SSH entry for destination connections')
    options = effective(alias, config, extra_roots, native_config=True) if host_alias else effective(alias, config, extra_roots)
    if (host, port) != (options['hostname'][0], int(options['port'][0])):
        raise ValueError('SSH alias changed or requested destination differs')
    if host.rstrip('.').lower().endswith('.invalid'):
        raise ValueError('SSH alias is disabled')
    jump = options.get('proxyjump', ['none'])[0]
    command = options.get('proxycommand', ['none'])[0]
    if jump != 'none':
        if not ALIAS.fullmatch(jump) or jump not in aliases_from_config(config, extra_roots):
            raise ValueError('Only one explicitly configured jump alias is supported')
        argv = ['/usr/bin/ssh', '-F', str(config), '-T', '-oBatchMode=yes',
                '-oStrictHostKeyChecking=yes', '-oUpdateHostKeys=no',
                '-oConnectTimeout=15', '-W', f'{host}:{port}', jump]
        return ('process', argv)
    if command != 'none':
        fields = shlex.split(command)
        direct_socks = ['/usr/bin/nc', '-X', '5', '-x', '127.0.0.1:11080', '%h', '%p']
        if fields == direct_socks:
            return ('process', direct_socks[:-2] + [host, str(port)])
        remote_socks = ['/usr/bin/ssh', '-T', '-F', '~/.ssh/a100-gateway.conf',
                        'a100-gateway', *direct_socks]
        if fields == remote_socks:
            gateway_config = Path.home() / '.ssh/a100-gateway.conf'
            effective('a100-gateway', gateway_config, extra_roots)
            return ('process', ['/usr/bin/ssh', '-T', '-F', str(gateway_config),
                '-oBatchMode=yes', '-oStrictHostKeyChecking=yes', '-oUpdateHostKeys=no',
                '-oConnectTimeout=15', 'a100-gateway', *direct_socks[:-2], host, str(port)])
        raise ValueError('Unsupported host ProxyCommand; refusing fallback')
    return ('direct', (host, port))


def open_route(plan):
    kind, value = plan
    if kind == 'process':
        process = subprocess.Popen(value, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL)
        return process.stdout, process.stdin, process
    peer = socket.create_connection(value, timeout=15)
    peer.settimeout(None)
    return peer, peer, None


def relay(left_reader, left_writer, right_reader, right_writer) -> None:
    """Half-close stdin, keep receiving; permit OpenSSH's normal multiplexing."""
    reads = {left_reader.fileno(): (left_reader, right_writer, False),
             right_reader.fileno(): (right_reader, left_writer, True)}
    while reads:
        ready, _, _ = select.select(list(reads), [], [], 900)
        if not ready:
            raise TimeoutError('SSH bridge idle timeout')
        for fd in ready:
            source, destination, remote_eof = reads[fd]
            data = os.read(source.fileno(), 65536)
            if data:
                remaining = memoryview(data)
                while remaining:
                    remaining = remaining[os.write(destination.fileno(), remaining):]
            else:
                del reads[fd]
                if remote_eof:
                    return
                if isinstance(destination, socket.socket):
                    destination.shutdown(socket.SHUT_WR)
                else:
                    destination.close()


def header(connection: socket.socket) -> dict:
    line = bytearray()
    while len(line) < 1024:
        data = connection.recv(1)
        if not data:
            raise ValueError('Incomplete request')
        line.extend(data)
        if data == b'\n':
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError('Invalid request')
            return value
    raise ValueError('Oversized request')


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path: Path, config: Path, audit: Path, handler, extra_roots: tuple[Path, ...] = (), host_alias=None):
        self.config, self.audit = config, audit
        self.extra_roots = extra_roots
        self.host_alias = host_alias
        self.path = path
        self.socket_identity = None
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(32)
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o022:
            raise ValueError('Socket directory must be owned and not writable by others')
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError('Existing endpoint is not an owned socket')
            with socket.socket(socket.AF_UNIX) as probe:
                probe.settimeout(1)
                try:
                    probe.connect(str(path))
                except ConnectionRefusedError:
                    current = path.lstat()
                    if (current.st_dev,current.st_ino) != (info.st_dev,info.st_ino):
                        raise ValueError('Stale socket was replaced during validation')
                    path.unlink()
                else:
                    raise ValueError('Existing socket is active')
        super().__init__(str(path), handler)
        os.chmod(path, 0o666)

    def server_bind(self):
        super().server_bind()
        info = self.path.lstat()
        self.socket_identity = (info.st_dev,info.st_ino)

    def server_close(self):
        super().server_close()
        if self.socket_identity is not None and self.path.exists():
            info = self.path.lstat()
            if (info.st_dev,info.st_ino) == self.socket_identity:
                self.path.unlink()
        self.socket_identity = None

    def log(self, item: dict) -> None:
        item['time'] = datetime.now(timezone.utc).isoformat()
        with self.lock, self.audit.open('a') as file:
            file.write(json.dumps(item, sort_keys=True)+'\n')
            file.flush()
            os.fsync(file.fileno())


class Transport(socketserver.BaseRequestHandler):
    def handle(self):
        peer = process = None
        acknowledged = False
        item = {'kind': 'transport', 'result': 'rejected'}
        if not self.server.slots.acquire(blocking=False):
            try:
                self.request.sendall(b'{"ok":false,"error":"SSH host bridge is busy"}\n')
            except OSError:
                pass
            return
        try:
            self.request.settimeout(15)
            value = header(self.request)
            if set(value) != {'alias', 'host', 'port'} or type(value['port']) is not int:
                raise ValueError('Invalid transport request fields')
            item.update({k: value[k] for k in ('alias', 'host', 'port')})
            plan = route_plan(value['alias'], self.server.config, value['host'], value['port'], self.server.extra_roots,
                              host_alias=self.server.host_alias)
            item['result'] = 'approved'
            self.server.log(item)
            reader, writer, process = open_route(plan)
            peer = reader
            self.request.sendall(b'{"ok":true}\n')
            acknowledged = True
            self.request.settimeout(None)
            relay(self.request, self.request, reader, writer)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            item['result'] = 'closed' if acknowledged else 'rejected-or-unreachable'
            item['error_type'] = type(error).__name__
            try:
                # Do not include command text or subprocess output in the reply.
                message = str(error) if isinstance(error, ValueError) else type(error).__name__
                if not acknowledged:
                    self.request.sendall(json.dumps({'ok': False, 'error': message[:300]}).encode() + b'\n')
            except OSError:
                pass
            try:
                self.server.log(item)
            except OSError:
                # A failed audit path is a fail-closed condition; do not open a route.
                pass
        finally:
            if peer is not None:
                peer.close()
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            self.server.slots.release()


class Agent(socketserver.BaseRequestHandler):
    def handle(self):
        # No input selects a path: only the existing campus agent can be reached.
        info = FIXED_AGENT.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
            return
        if not self.server.slots.acquire(blocking=False):
            return
        try:
            with socket.socket(socket.AF_UNIX) as peer:
                self.server.log({'kind': 'fixed-campus-agent', 'result': 'approved'})
                peer.connect(str(FIXED_AGENT))
                relay(self.request, self.request, peer, peer)
        finally:
            self.server.slots.release()


def target_config(config: Path, socket_path: str, agent_path: str, *, target_home: Path | None = None, extra_roots: tuple[Path, ...] = (), host_alias=None) -> str:
    lines = []
    for alias in [host_alias] if host_alias else sorted(aliases_from_config(config, extra_roots)):
        options = effective(alias, config, extra_roots, native_config=True) if host_alias else effective(alias, config, extra_roots)
        host, port = options['hostname'][0], options['port'][0]
        if host.rstrip('.').lower().endswith('.invalid'):
            lines += [f'Host {alias}', f'    HostName {host}',
                      '    ProxyCommand /usr/bin/false',
                      '    StrictHostKeyChecking yes',
                      '    BatchMode yes', '']
            continue
        args = ['/usr/bin/python3', '/opt/cdm-ssh/controlled_dev_machine/ssh_alias_bridge.py',
                'client', '--socket', socket_path, alias, host, port]
        lines += [f'Host {alias}', f'    HostName {host}', f'    Port {port}',
                  f'    User {options["user"][0]}', '    ProxyCommand '+shlex.join(args),
                  '    StrictHostKeyChecking yes', '    UpdateHostKeys no',
                  '    BatchMode yes', '    IdentitiesOnly yes', '    ConnectTimeout 20']
        for key, label in [('hostkeyalias','HostKeyAlias'),('identityfile','IdentityFile'),('certificatefile','CertificateFile'),('userknownhostsfile','UserKnownHostsFile'),('globalknownhostsfile','GlobalKnownHostsFile')]:
            for value in options.get(key, []):
                if target_home is not None and key != 'hostkeyalias':
                    value = re.sub(re.escape(str(config.parent)) + r'(?=/|$|\s)', str(target_home / '.ssh'), value)
                    for index, root in enumerate(extra_roots):
                        value = re.sub(re.escape(str(root)) + r'(?=/|$|\s)', str(target_home / '.ssh' / f'.cdm-host-{index}'), value)
                lines.append(f'    {label} {value}')
        identity_agent = options.get('identityagent', ['none'])[0]
        if identity_agent != 'none':
            if identity_agent != str(FIXED_AGENT):
                raise ValueError('Unsupported IdentityAgent; refusing fallback')
            lines.append(f'    IdentityAgent {agent_path}')
        lines.append('')
    lines += ['Host *', '    ProxyCommand /usr/bin/false',
              '    StrictHostKeyChecking yes', '    BatchMode yes', '']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='mode', required=True)
    client = sub.add_parser('client')
    client.add_argument('--socket', required=True, type=Path)
    client.add_argument('alias');client.add_argument('host');client.add_argument('port', type=int)
    serve = sub.add_parser('serve')
    serve.add_argument('--config', type=Path)
    serve.add_argument('--socket', type=Path)
    serve.add_argument('--agent-socket', type=Path)
    serve.add_argument('--audit', type=Path)
    serve.add_argument('--deployment-config', type=Path)
    serve.add_argument('--client-directory', type=Path)
    serve.add_argument('--client-home', type=Path)
    serve.add_argument('--extra-root', action='append', type=Path, default=[])
    serve.add_argument('--host-alias')
    generate = sub.add_parser('config')
    generate.add_argument('--config', required=True, type=Path)
    args = parser.parse_args()
    if args.mode == 'serve':
        if args.deployment_config:
            c = json.loads(args.deployment_config.read_text())
            if Path(c['host_home']) != Path.home():
                parser.error('deployment profile belongs to another host user')
            private = Path(c['private_root'])
            args.config = Path(c['host_home']) / '.ssh/config'
            args.socket = private / 'control/ssh/alias.sock'
            args.agent_socket = private / 'control/ssh/campus-agent.sock'
            args.audit = private / 'control/audit/ssh/aliases.jsonl'
            args.client_directory = private / 'apps/ssh'
            args.client_home = Path(c['target_home'])
            args.extra_root = [Path(x) for x in c.get('ssh_extra_roots', [])]
            args.host_alias = c.get('ssh_host_alias')
        if not all([args.config, args.socket, args.agent_socket, args.audit]):
            parser.error('serve requires a deployment profile or explicit config/socket/agent-socket/audit')
    if args.mode == 'client':
        with socket.socket(socket.AF_UNIX) as peer:
            peer.connect(str(args.socket))
            peer.sendall(json.dumps({'alias': args.alias, 'host': args.host, 'port': args.port}).encode()+b'\n')
            try:
                reply = header(peer)
            except (ValueError, OSError) as error:
                raise SystemExit('ssh: host bridge closed before route acknowledgement: ' + str(error)) from None
            if reply != {'ok': True}:
                raise SystemExit('ssh: host bridge rejected route: ' + str(reply.get('error', 'unknown reason')))
            reader = sys.stdin.buffer
            writer = sys.stdout.buffer
            relay(reader, writer, peer, peer)
        return
    if args.mode == 'config':
        rendered = target_config(args.config, '/run/cdm-ssh/alias.sock', '/run/cdm-ssh/campus-agent.sock')
        disabled = [alias for alias in sorted(aliases_from_config(args.config))
                    if effective(alias,args.config)['hostname'][0].rstrip('.').lower().endswith('.invalid')]
        print(json.dumps({'aliases':len(aliases_from_config(args.config)),'disabled_aliases':disabled}),file=sys.stderr)
        print(rendered, end='')
        return
    refresher = None
    if args.client_directory:
        if not args.client_home:
            parser.error('--client-directory requires --client-home')
        from controlled_dev_machine.ssh_client_state import SSHClientState
        refresher = SSHClientState(args.config.parent, args.client_directory, args.client_home, tuple(args.extra_root), host_alias=args.host_alias)
        refresher.refresh()
    refresh_stop = threading.Event()
    def refresh_client():
        last_error = None
        while not refresh_stop.wait(2):
            try:
                if refresher.refresh():
                    print('SSH client configuration refreshed', flush=True)
                last_error = None
            except Exception as error:
                message = f'SSH client refresh failed: {type(error).__name__}: {error}'
                if message != last_error:
                    print(message, file=sys.stderr, flush=True)
                last_error = message
    with Server(args.socket, args.config, args.audit, Transport, tuple(args.extra_root), args.host_alias) as transport, Server(args.agent_socket, args.config, args.audit, Agent, tuple(args.extra_root)) as agent:
        def stop(signum,frame):
            refresh_stop.set()
            threading.Thread(target=transport.shutdown,daemon=True).start()
        signal.signal(signal.SIGTERM,stop)
        signal.signal(signal.SIGINT,stop)
        thread = threading.Thread(target=agent.serve_forever, daemon=True)
        thread.start()
        watcher = threading.Thread(target=refresh_client, daemon=True) if refresher else None
        if watcher:
            watcher.start()
        try:
            transport.serve_forever()
        finally:
            refresh_stop.set()
            if watcher:
                watcher.join(timeout=5)
            agent.shutdown()
            thread.join(timeout=2)


if __name__ == '__main__':
    main()
