from contextlib import nullcontext
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import controlled_dev_machine.egress_handoff as module


def fixture(tmp_path, monkeypatch, failure=None):
    private = tmp_path / 'private'
    state = private / 'control'
    (private / 'configs').mkdir(parents=True)
    (state / 'config').mkdir(parents=True)
    release = tmp_path / 'release'
    release.mkdir()
    revision = 'a' * 40
    image = 'sha256:' + 'b' * 64
    (release / 'RELEASE.json').write_text(json.dumps({'commit': revision}))
    pin = {'parent_host': '192.0.2.10', 'parent_port': 26963, 'expected_exit': '198.51.100.87'}
    (state / 'config/exit-monitor.json').write_text(json.dumps(dict(pin, probe_urls=['https://example.com/ip'])))
    project = 'sandbox-test'
    def info(name, index, networks):
        return {'Name': '/' + name, 'Id': name + '-id', 'Image': 'old-image',
                'Config': {'Labels': {'com.docker.compose.project': project}},
                'State': {'Pid': os.getpid(), 'StartedAt': 'original-start', 'Running': True},
                'NetworkSettings': {'Networks': networks}}
    objects = {}
    for role, index in [('target', 2), ('gateway', 3), ('dns', 4), ('egress', 30),
                        ('capacity-web-20261104', 31), ('capacity-dns-20261104', 32)]:
        name = project + '-' + (role if role.startswith('capacity') else role + '-1')
        net = {'upstream': {'IPAddress': '172.31.1.' + str(index)}}
        if role == 'egress':net['external'] = {'IPAddress': '172.31.0.2'}
        objects[name] = info(name, index, net)
    protected = list(objects)
    (private / 'configs/egress-capacity-hotfix-20261104.json').write_text(json.dumps({
        'applied': True, 'new_containers': {r: {'id': project + '-capacity-' + r + '-20261104-id'} for r in ['web', 'dns']}}))
    calls, nft_calls = [], []
    def run(args, **kwargs):
        args = [str(x) for x in args]
        calls.append(args)
        operation = args[3:]
        code, output = 0, ''
        if operation[:2] == ['image', 'inspect']:
            output = json.dumps([{'Id': image, 'Config': {'Labels': {'cdm.source_digest': revision}}}])
        elif operation[0] == 'inspect':
            selected = next((v for k, v in objects.items() if operation[1] in (k, v['Id'])), None)
            if selected is None:code = 1
            else:output = json.dumps([selected])
        elif operation[:2] == ['network', 'inspect']:
            output = json.dumps([{'Internal': operation[2] == 'upstream', 'EnableIPv6': False,
                'IPAM': {'Config': [{'Subnet': '172.31.1.0/24'}]},
                'Containers': {k: {'IPv4Address': v['NetworkSettings']['Networks']['upstream']['IPAddress'] + '/24'}
                               for k, v in objects.items() if 'upstream' in v['NetworkSettings']['Networks']}}])
        elif operation[0] == 'create':
            name = operation[operation.index('--name') + 1]
            address = operation[operation.index('--ip') + 1]
            objects[name] = info(name, 0, {'upstream': {'IPAddress': address}})
        elif operation[0] == 'exec':
            script = operation[4]
            if script == module.IP_PROBE:output = pin['expected_exit'] + '\n'
            else:
                address, target = operation[-2:]
                is_dns_peer = '-dns-1-id' in operation[1]
                allowed = is_dns_peer and address == '172.31.1.34' and target == '1.1.1.1:443'
                output = 'HTTP/1.1 ' + ('200' if allowed else '403') + '\n'
        return SimpleNamespace(returncode=code, stdout=output, stderr='')
    applied = 0
    def nft(args, **kwargs):
        nonlocal applied
        nft_calls.append((args, kwargs.get('input')))
        code = 0
        if args[-5:-2] == ['list', 'table', 'ip']:code = 1
        elif 'table' in args and 'list' in args:code = 1
        if '-c' in args and failure == 'preflight':code = 1
        if '-f' in args and '-c' not in args:
            applied += 1
            if failure == 'second-switch' and applied == 2:code = 1
        return SimpleNamespace(returncode=code, stdout='baseline rules\n', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', nft)
    import socket
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))])
    app = SimpleNamespace(private=private, state=state, project=project, docker=['docker', '--context', 'rootless'],
                          config={'exit': pin}, run=run, lock=lambda: nullcontext())
    return app, image, release, objects, protected, calls, nft_calls


def test_handoff_only_routes_new_syns_and_keeps_all_six_live_components(tmp_path, monkeypatch):
    app, image, release, objects, protected, calls, nft_calls = fixture(tmp_path, monkeypatch)
    before = {objects[k]['Name']: module.brief(objects[k]) for k in protected}
    result = module.handoff(app, image, '20261105', release)
    assert result['applied'] and result['after'] == before
    assert result['new_containers'].keys() == {'web', 'dns'}
    assert all(not any(v in c[3:] for v in ['stop', 'restart', 'kill', 'rm']) for c in calls)
    rules = [text for args, text in nft_calls if text]
    assert all('tcp flags & (syn | ack) == syn' in text and 'priority -110' in text for text in rules)
    assert all(objects[k]['State']['Running'] for k in protected)


def test_used_handoff_rolls_back_new_routes_but_keeps_translated_sessions_alive(tmp_path, monkeypatch):
    app, image, release, objects, protected, calls, nft_calls = fixture(tmp_path, monkeypatch, 'second-switch')
    with pytest.raises(RuntimeError, match='namespace route failed'):
        module.handoff(app, image, '20261105', release)
    result = json.loads((app.private / 'configs/egress-capacity-hotfix-20261105.json').read_text())
    assert result['applied'] and not result['route_active'] and result['new_forwarders_kept_for_sessions']
    assert any('delete' in args for args, _ in nft_calls)
    assert all('rm' not in c and 'stop' not in c for c in calls)
    assert all(objects[k]['State']['Running'] for k in protected)


def test_unused_failed_generation_removes_only_its_own_new_containers(tmp_path, monkeypatch):
    app, image, release, objects, protected, calls, nft_calls = fixture(tmp_path, monkeypatch, 'preflight')
    with pytest.raises(RuntimeError, match='preflight failed'):
        module.handoff(app, image, '20261105', release)
    removed = [c[-1] for c in calls if 'rm' in c]
    assert set(removed) == {app.project + '-capacity-' + r + '-20261105' for r in ['web', 'dns']}
    assert set(removed).isdisjoint(protected)
    assert all('stop' not in c for c in calls)
