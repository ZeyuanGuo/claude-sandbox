import json
import os
from types import SimpleNamespace

import pytest
from controlled_dev_machine.handoff_routes import expected_expression, reconcile_active_handoffs
import controlled_dev_machine.handoff_routes as module


def fixture(tmp_path, monkeypatch):
    private = tmp_path / 'private'
    state = private / 'control'
    (private / 'configs').mkdir(parents=True)
    (state / 'config').mkdir(parents=True)
    pin = {'expected_exit': '198.51.100.87', 'parent_host': '192.0.2.10', 'parent_port': 18080}
    table = 'cdm_egress_resume_20261105'
    objects = {}
    for role, ip in [('gateway', 23), ('dns', 22), ('egress', 30), ('web-relay', 33), ('dns-relay', 34)]:
        name = 'test-' + role + '-1'
        objects[name] = {'Id': name, 'Image': 'image', 'Config': {'Labels': {'com.docker.compose.project': 'test'}},
                         'State': {'Running': True, 'Pid': os.getpid()},
                         'NetworkSettings': {'Networks': {'internal': {'IPAddress': '172.31.1.' + str(ip)}}}}
    for role, peer in [('web', '172.31.1.23'), ('dns', '172.31.1.22')]:
        p = state / 'config' / (role + '.json')
        p.write_text(json.dumps(dict(pin, **{'trusted_gateway_ips' if role == 'web' else 'trusted_dns_ips': [peer]})))
        objects['test-' + role + '-relay-1']['Mounts'] = [{'Source': str(p), 'Destination': '/run/cdm-relay.json', 'RW': False}]
    registration = private / 'configs/egress-capacity-hotfix-20261105.json'
    registration.write_text(json.dumps(dict(pin, applied=True, route_active=True, stage='active', table=table,
         image='image', new_containers={'web': {'id': 'test-web-relay-1'}, 'dns': {'id': 'test-dns-relay-1'}})))
    def run(args):
        if args[1] == 'inspect':value = objects[args[2]]
        else:value = {'Internal': True, 'EnableIPv6': False}
        return SimpleNamespace(stdout=json.dumps([value]))
    rules = {}; applied = []
    def nft(args, **kwargs):
        # Each namespace FD remains pinned throughout reconciliation.
        ns = args[2]
        if 'list' in args:
            return SimpleNamespace(returncode=0, stdout=json.dumps({'nftables': rules.get(ns, [])}), stderr='')
        if '-c' not in args and '-f' in args:
            dest = kwargs['input'].split('dnat to ')[1].split(':')[0]
            applied.append(dest)
            rules[ns] = [{'table': {'name': table, 'family': 'ip'}},
                         {'chain': {'table': table, 'name': 'output', 'type': 'nat', 'hook': 'output', 'prio': -110, 'policy': 'accept'}},
                         {'rule': {'table': table, 'chain': 'output', 'expr': expected_expression('172.31.1.30', dest)}}]
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', nft)
    app = SimpleNamespace(private=private, state=state, project='test', config={'exit': pin}, docker=['docker'], run=run)
    return app, objects, registration, rules, applied


def test_missing_routes_restored_and_second_pass_is_idempotent(tmp_path, monkeypatch):
    app, objects, registration, rules, applied = fixture(tmp_path, monkeypatch)
    result = reconcile_active_handoffs(app)
    assert result['restored'] == ['gateway', 'dns']
    assert applied == ['172.31.1.33', '172.31.1.34']
    assert reconcile_active_handoffs(app)['restored'] == []
    data = json.loads(registration.read_text())
    assert len(data['reconciliations']) == 1
    assert data['active_namespaces']['gateway']['id'] == 'test-gateway-1'


@pytest.mark.parametrize('bad', ['parent', 'image', 'peer', 'stopped', 'unexpected-rule'])
def test_drift_is_rejected_before_any_route_is_changed(tmp_path, monkeypatch, bad):
    app, objects, registration, rules, applied = fixture(tmp_path, monkeypatch)
    if bad == 'parent':app.config['exit']['parent_port'] += 1
    elif bad == 'image':objects['test-web-relay-1']['Image'] = 'other-image'
    elif bad == 'peer':objects['test-gateway-1']['NetworkSettings']['Networks']['internal']['IPAddress'] = '172.31.1.99'
    elif bad == 'stopped':objects['test-dns-relay-1']['State']['Running'] = False
    else:
        def fail(*args):raise RuntimeError('unexpected rules')
        monkeypatch.setattr(module, 'route_present', fail)
    with pytest.raises(RuntimeError):reconcile_active_handoffs(app)
    assert applied == []


def test_no_registered_handoff_is_a_noop(tmp_path):
    app = SimpleNamespace(private=tmp_path)
    assert reconcile_active_handoffs(app) == {'registered': False, 'restored': []}
