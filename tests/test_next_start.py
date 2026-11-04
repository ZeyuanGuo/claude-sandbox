from contextlib import nullcontext
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import controlled_dev_machine.next_start as module
from controlled_dev_machine.development import DevelopmentSandbox


def staging_fixture(tmp_path, monkeypatch):
    root = tmp_path / 'private'
    home = tmp_path / 'home'
    configs = root / 'configs'
    configs.mkdir(parents=True)
    old = configs / 'old.json'
    new = configs / 'new.json'
    old.write_text('{"version":"old"}')
    new.write_text('{"version":"new"}')
    release = root / 'releases' / ('b' * 40)
    for name in ['bin/ssh-native-host', 'bin/development-next-start',
                 'src/controlled_dev_machine/ssh_native_client.py',
                 'src/controlled_dev_machine/next_start.py']:
        p = release / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('# fixture\n')
    record = release / 'RELEASE.json'
    record.write_text(json.dumps({'commit': 'b' * 40}))
    record.chmod(0o600)
    calls = []
    def run(args, **kwargs):
        args = [str(x) for x in args]
        calls.append(args)
        if args[:4] == ['docker', '--context', 'rootless', 'image']:
            return SimpleNamespace(stdout=json.dumps([{'Id': args[-1], 'Config': {'Labels': {
                'org.controlled-dev-machine.source': 'b' * 40}}}]), returncode=0)
        return SimpleNamespace(stdout='', returncode=0)
    shared = dict(private=root, home=home, project='test-sandbox', unit_dir=home / '.config/systemd/user',
                  python='/usr/bin/python3', release=release, docker=['docker', '--context', 'rootless'],
                  run=run, status=lambda: {'container_id': 'unchanged-container', 'running': True},
                  lock=lambda: nullcontext())
    exit = {'expected_exit': '198.51.100.20', 'parent_host': '192.0.2.10', 'parent_port': 18080}
    config = {'exit': exit, 'target_image': 'sha256:target', 'gateway_image': 'sha256:gateway', 'release_id': 'b' * 40}
    apps = {old: SimpleNamespace(**shared, config_path=old, config=config),
            new: SimpleNamespace(**shared, config_path=new, config=config)}
    for app in apps.values():
        app.start = lambda: pytest.fail('stage must not start a sandbox')
        app.prepare = lambda: pytest.fail('stage must not write runtime configuration')
    monkeypatch.setattr(module, 'DevelopmentSandbox', lambda p: apps[Path(p)])
    return root, old, new, release, calls, apps


def test_stage_only_prepares_future_start_and_keeps_runtime_selected(tmp_path, monkeypatch):
    root, old, new, release, calls, apps = staging_fixture(tmp_path, monkeypatch)
    result = module.stage(old, new)
    assert result['state'] == 'staged'
    assert (root / 'configs/runtime.json').resolve() == old
    assert json.loads((root / 'startup/controller.json').read_text())['controller_release'] == str(release)
    dropin = apps[old].unit_dir / 'test-sandbox.service.d/99-next-start.conf'
    assert 'development-next-start activate' in dropin.read_text()
    assert all('stop' not in c and 'restart' not in c and 'up' not in c for c in calls)
    assert ['systemctl', '--user', 'daemon-reload'] in calls
    assert not (root / 'control').exists()


def test_profile_edit_after_staging_is_rejected_before_activation(tmp_path, monkeypatch):
    root, old, new, release, calls, apps = staging_fixture(tmp_path, monkeypatch)
    module.stage(old, new)
    calls.clear()
    old.write_text('{"version":"user-edited"}')
    with pytest.raises(RuntimeError, match='current host profile changed'):
        module.activate(root / 'configs/next-start.json')
    assert calls == []
    assert (root / 'configs/runtime.json').resolve() == old


def test_candidate_tampering_is_rejected_before_any_runtime_operation(tmp_path, monkeypatch):
    root, old, new, release, calls, apps = staging_fixture(tmp_path, monkeypatch)
    module.stage(old, new)
    calls.clear()
    new.write_text('changed')
    with pytest.raises(RuntimeError, match='staged profile changed'):
        module.activate(root / 'configs/next-start.json')
    assert calls == []


def test_shared_home_units_resolve_ssh_alias_from_local_profile(tmp_path, monkeypatch):
    from test_development_release import profile
    path, value = profile(tmp_path)
    private = Path(value['private_root'])
    (private / 'startup').mkdir(parents=True)
    pointer = private / 'startup/controller.json'
    pointer.write_text(json.dumps({'controller_release': str(private / 'releases' / ('b' * 40)),
                                   'runtime_config': str(private / 'configs/runtime.json')}))
    pointer.chmod(0o600)
    contents = []
    for alias in ['campus-one', 'campus-two']:
        value['ssh_host_alias'] = alias
        path.write_text(json.dumps(value))
        app = DevelopmentSandbox(path)
        monkeypatch.setattr(app, 'run', lambda *a, **k: None)
        app.install_units()
        text = (app.unit_dir / 'test-sandbox-ssh.service').read_text()
        assert '--deployment-config' in text and alias not in text
        contents.append(text)
    assert contents[0] == contents[1]


def test_controller_selection_cannot_escape_private_source_directory(tmp_path):
    from test_development_release import profile
    path, value = profile(tmp_path)
    app = DevelopmentSandbox(path)
    pointer = app.private / 'startup/controller.json'
    pointer.parent.mkdir()
    pointer.write_text(json.dumps({'controller_release': '/tmp/foreign',
                                   'runtime_config': str(app.private / 'configs/runtime.json')}))
    pointer.chmod(0o600)
    with pytest.raises(RuntimeError, match='escapes'):
        app.controller_selection()


def test_capacity_retirement_refuses_foreign_container_before_stopping_anything(tmp_path):
    root = tmp_path / 'private'
    configs = root / 'configs'
    configs.mkdir(parents=True)
    p = configs / 'egress-capacity-hotfix-example.json'
    p.write_text(json.dumps({'applied': True, 'new_containers': {'web': {'id': 'foreign'}, 'dns': {'id': 'dns'}}}))
    p.chmod(0o600)
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout=json.dumps([{'Name': '/foreign-container', 'Config': {'Labels': {}}}]))
    app = SimpleNamespace(private=root, project='owned', docker=['docker'], run=run)
    with pytest.raises(RuntimeError, match='ownership differs'):
        module.retire_registered_capacity(app)
    assert all('stop' not in c and 'update' not in c and 'disconnect' not in c for c in calls)
