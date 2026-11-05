"""Move only new connections to a versioned relay; retain every existing relay."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit

from .development import DevelopmentSandbox
from .exit_monitor import atomic_json


CONNECT = r'''import socket,sys
s=socket.create_connection((sys.argv[1],8080),timeout=4);s.settimeout(8)
a=sys.argv[2];s.sendall(('CONNECT '+a+' HTTP/1.1\r\nHost: '+a+'\r\n\r\n').encode());d=b''
while b'\r\n\r\n' not in d:
 p=s.recv(4096)
 if not p:raise RuntimeError('relay closed before CONNECT reply')
 d+=p
print(d.split(b'\r\n',1)[0].decode());s.close()
'''
IP_PROBE = r'''import socket,ssl,http.client,sys,json,ipaddress
relay,ip,host,path=sys.argv[1:];s=socket.create_connection((relay,8080),timeout=5);s.settimeout(10)
a=ip+':443';s.sendall(('CONNECT '+a+' HTTP/1.1\r\nHost: '+a+'\r\n\r\n').encode());d=b''
while b'\r\n\r\n' not in d:
 p=s.recv(4096)
 if not p:raise RuntimeError('relay closed before CONNECT reply')
 d+=p
assert b' 200 ' in d.split(b'\r\n',1)[0]
t=ssl.create_default_context().wrap_socket(s,server_hostname=host)
t.sendall(('GET '+path+' HTTP/1.1\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode())
r=http.client.HTTPResponse(t);r.begin();assert r.status==200;body=r.read(4097).decode().strip();assert len(body)<=4096
if body.startswith('{'):body=json.loads(body)['ip']
print(str(ipaddress.IPv4Address(body)));t.close()
'''


def brief(info):
    return {'id': info['Id'], 'pid': info['State']['Pid'],
            'started_at': info['State']['StartedAt'], 'image': info['Image']}


def handoff(app, image, generation, source_release):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image) or not re.fullmatch(r'[0-9]{8}', generation):
        raise ValueError('require an immutable image and an eight-digit generation')
    record = json.loads((source_release / 'RELEASE.json').read_text())
    run = app.run
    docker = app.docker
    def inspect(name):
        return json.loads(run(docker + ['inspect', name]).stdout)[0]
    built = json.loads(run(docker + ['image', 'inspect', image]).stdout)[0]
    if built['Id'] != image or (built.get('Config', {}).get('Labels') or {}).get('cdm.source_digest') != record['commit']:
        raise RuntimeError('relay image does not match the installed handoff source')
    manifest = app.private / 'configs' / ('egress-capacity-hotfix-' + generation + '.json')
    if manifest.exists():
        raise RuntimeError('generation already registered; inspect instead of repeating')
    table = 'cdm_egress_resume_' + generation
    created, switched, namespaces = [], [], {}
    report = {'applied': False, 'source_commit': record['commit'], 'image': image,
              'purpose': 'strict new admission with bounded tolerance of probe uncertainty for established tunnels',
              'established_grace_seconds': 300, 'audit_paths': [], 'new_containers': {}}
    with app.lock(), ExitStack() as stack:
        if manifest.exists():
            raise RuntimeError('generation already registered; inspect instead of repeating')
        old = {r: inspect(app.project + '-' + r + '-1') for r in ['target', 'gateway', 'dns', 'egress']}
        if not all(i['State']['Running'] for i in old.values()):
            raise RuntimeError('the current instance is not running')
        if any((i.get('Config', {}).get('Labels') or {}).get('com.docker.compose.project') != app.project
               for i in old.values()):
            raise RuntimeError('current component ownership differs')
        protected = {i['Name']: brief(i) for i in old.values()}
        for registration in (app.private / 'configs').glob('egress-capacity-hotfix-*.json'):
            data = json.loads(registration.read_text())
            if data.get('applied'):
                for value in data.get('new_containers', {}).values():
                    info = inspect(value['id'])
                    if not info['State']['Running']:
                        raise RuntimeError('registered forwarder is not running')
                    protected[info['Name']] = brief(info)
        current = json.loads((app.state / 'config/exit-monitor.json').read_text())
        pin = app.config['exit']
        if any(current[k] != pin[k] for k in ['parent_host', 'parent_port', 'expected_exit']):
            raise RuntimeError('operational parent/exit differs from selected host profile')
        upstream = next(n for n in old['egress']['NetworkSettings']['Networks'] if n in old['gateway']['NetworkSettings']['Networks'])
        external = next(n for n in old['egress']['NetworkSettings']['Networks'] if n != upstream)
        network = json.loads(run(docker + ['network', 'inspect', upstream]).stdout)[0]
        if not network['Internal'] or network.get('EnableIPv6'):
            raise RuntimeError('the current upstream network is not IPv4-only/internal')
        if json.loads(run(docker + ['network', 'inspect', external]).stdout)[0]['Internal']:
            raise RuntimeError('no existing external parent network')
        subnet = ipaddress.ip_network(network['IPAM']['Config'][0]['Subnet'])
        occupied = {x['IPv4Address'].split('/')[0] for x in (network.get('Containers') or {}).values()}
        old_ip = old['egress']['NetworkSettings']['Networks'][upstream]['IPAddress']
        available = [str(ipaddress.IPv4Address(old_ip) + n) for n in range(1, 10)
                     if ipaddress.IPv4Address(old_ip) + n in subnet
                     and str(ipaddress.IPv4Address(old_ip) + n) not in occupied]
        if len(available) < 2:
            raise RuntimeError('no two free upstream addresses')
        names = {r: app.project + '-capacity-' + r + '-' + generation for r in ['web', 'dns']}
        for name in names.values():
            if run(docker + ['inspect', name], check=False).returncode == 0:
                raise RuntimeError('unexpected existing generation container')
        for role in ['gateway', 'dns']:
            pid = old[role]['State']['Pid']
            namespaces[role] = tuple(stack.enter_context(open(f'/proc/{pid}/ns/{kind}', 'rb', buffering=0)).fileno()
                                     for kind in ['user', 'net'])
        def nft(role, args, input=None):
            uf, nf = namespaces[role]
            return subprocess.run(['nsenter', f'--user=/proc/self/fd/{uf}', f'--net=/proc/self/fd/{nf}',
                                   '--', '/usr/sbin/nft', *args], input=input, capture_output=True,
                                  text=True, pass_fds=(uf, nf))
        backup = app.private / 'backups' / ('egress-handoff-' + generation)
        backup.mkdir(mode=0o700, parents=True)
        for role in namespaces:
            if nft(role, ['list', 'table', 'ip', table]).returncode == 0:
                raise RuntimeError('unexpected existing handoff table')
            before = nft(role, ['list', 'ruleset'])
            if before.returncode:
                raise RuntimeError('cannot snapshot sandbox namespace rules')
            (backup / (role + '-before.nft')).write_text(before.stdout)
        report.update(before=protected, parent_host=current['parent_host'], parent_port=current['parent_port'],
                      expected_exit=current['expected_exit'], table=table, backup=str(backup))
        atomic_json(manifest, report)
        try:
            for role, address, peer, capacity in [
                ('web', available[0], old['gateway']['NetworkSettings']['Networks'][upstream]['IPAddress'], 256),
                ('dns', available[1], old['dns']['NetworkSettings']['Networks'][upstream]['IPAddress'], 16)]:
                cfg = {'parent_host': current['parent_host'], 'parent_port': current['parent_port'],
                       'trusted_gateway_ips': [peer] if role == 'web' else [],
                       'trusted_dns_ips': [peer] if role == 'dns' else [], 'max_sessions': capacity,
                       'expected_exit': current['expected_exit'], 'exit_lease': '/run/cdm-exit/lease.json',
                       'established_grace_seconds': 300}
                path = app.state / 'config' / ('egress-resilience-' + role + '-' + generation + '.json')
                audit = 'events-resilience-' + role + '-' + generation + '.jsonl'
                atomic_json(path, cfg)
                run(docker + ['create', '--name', names[role], '--network', upstream, '--ip', address,
                    '--user', '0:0', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                    '--init', '--restart', 'unless-stopped', '--dns', '127.0.0.1',
                    '--log-opt', 'max-size=10m', '--log-opt', 'max-file=3',
                    '--label', 'org.controlled-dev-machine.hotfix=capacity-' + generation,
                    '--label', 'org.controlled-dev-machine.source=' + record['commit'],
                    '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'CDM_DEGRADED_TEST_MODE=0',
                    '--mount', f'type=bind,source={path},target=/run/cdm-relay.json,readonly',
                    '--mount', f'type=bind,source={app.state}/exit-control,target=/run/cdm-exit,readonly',
                    '--mount', f'type=bind,source={app.state}/audit/egress,target=/audit/egress',
                    '--entrypoint', 'python3', image, '-m', 'controlled_dev_machine.degraded_egress',
                    '--config', '/run/cdm-relay.json', '--audit', '/audit/egress/' + audit])
                created.append(names[role])
                run(docker + ['network', 'connect', external, names[role]])
                run(docker + ['start', names[role]])
                report['audit_paths'].append(str(app.state / 'audit/egress' / audit))
            report['new_containers'] = {r: brief(inspect(n)) for r, n in names.items()}
            atomic_json(manifest, report)
            def connect(role, address, target):
                return run(docker + ['exec', old[role]['Id'], 'python3', '-c', CONNECT, address, target], timeout=15).stdout.strip()
            for attempt in range(30):
                try:
                    if '403' in connect('gateway', available[0], '[2606:4700:4700::1111]:443'):
                        break
                except Exception:
                    pass
                time.sleep(.5)
            else:
                raise RuntimeError('new relay did not become ready')
            checks = {'ipv6': connect('gateway', available[0], '[2606:4700:4700::1111]:443'),
                      'web_cannot_use_dns': connect('gateway', available[1], '1.1.1.1:443'),
                      'dns_cannot_use_web': connect('dns', available[0], '1.1.1.1:443'),
                      'dns_destination': connect('dns', available[1], '1.0.0.1:443')}
            if not all('403' in value for value in checks.values()):
                raise RuntimeError('new relay isolation checks failed')
            report['negative_checks'] = checks
            report['exit_checks'] = []
            import socket
            for endpoint in current['probe_urls']:
                url = urlsplit(endpoint)
                numeric = socket.getaddrinfo(url.hostname, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
                if not ipaddress.ip_address(numeric).is_global:
                    raise RuntimeError('configured exit probe did not resolve to a public IPv4')
                path = (url.path or '/') + ('?' + url.query if url.query else '')
                observed = run(docker + ['exec', old['gateway']['Id'], 'python3', '-c', IP_PROBE,
                                        available[0], numeric, url.hostname, path], timeout=25).stdout.strip()
                if observed != current['expected_exit']:
                    raise RuntimeError('new relay exact exit verification failed')
                report['exit_checks'].append({'endpoint': endpoint, 'observed_exit': observed})
            if '200' not in connect('dns', available[1], '1.1.1.1:443'):
                raise RuntimeError('new DNS forwarder did not admit its only allowed destination')
            # Register ownership before any routing can put real sessions on
            # these containers, so a later failed receipt write cannot orphan
            # live translations at the next planned main restart.
            report.update(applied=True, route_active=False, stage='prepared')
            atomic_json(manifest, report)
            for role, address in [('dns', available[1]), ('gateway', available[0])]:
                if any(brief(inspect(value['id'])) != value for value in protected.values()):
                    raise RuntimeError('a protected live component changed; refusing handoff')
                rules = (f'add table ip {table}\n'
                         f'add chain ip {table} output {{ type nat hook output priority -110; policy accept; }}\n'
                         f'add rule ip {table} output ip daddr {old_ip} tcp dport 8080 tcp flags & (syn | ack) == syn dnat to {address}:8080\n')
                checked = nft(role, ['-c', '-f', '-'], input=rules)
                if checked.returncode:
                    raise RuntimeError('new namespace route preflight failed')
                applied = nft(role, ['-f', '-'], input=rules)
                if applied.returncode:
                    raise RuntimeError('new namespace route failed')
                switched.append(role)
                report['switched_namespaces'] = list(switched)
                atomic_json(manifest, report)
            report.update(applied=True, route_active=True, stage='active',
                          after={name: brief(inspect(value['id'])) for name, value in protected.items()})
            if report['after'] != protected:
                raise RuntimeError('live component changed during handoff')
            atomic_json(manifest, report)
        except Exception:
            for role in reversed(switched):
                nft(role, ['delete', 'table', 'ip', table])
            if not switched:
                for name in created:
                    run(docker + ['rm', '-f', name], check=False)
            # A used generation must remain registered/alive for conntrack and
            # later planned retirement, even after new-flow routing rolls back.
            report.update(applied=bool(switched), route_active=False, failed=True,
                          route_rollback=True, new_forwarders_kept_for_sessions=bool(switched))
            atomic_json(manifest, report)
            raise
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--image', required=True)
    p.add_argument('--generation', required=True)
    args = p.parse_args()
    app = DevelopmentSandbox(args.config)
    report = handoff(app, args.image, args.generation, Path(__file__).resolve().parents[2])
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
