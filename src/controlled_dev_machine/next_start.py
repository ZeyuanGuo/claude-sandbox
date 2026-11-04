"""Stage a release without changing running containers; activate at the next main start."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
import time

from .development import DevelopmentSandbox, write_file
from .exit_monitor import atomic_json


def stamp():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def owned_json(path):
    path = Path(path)
    info = path.lstat()
    if path.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise RuntimeError('unsafe next-start metadata owner or permissions')
    return json.loads(path.read_text())


def select_profile(alias, destination):
    alias, destination = Path(alias), Path(destination)
    alias.parent.mkdir(parents=True, exist_ok=True)
    temporary = alias.with_name(alias.name + '.next')
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(destination)
    temporary.replace(alias)


def validate_plan(plan_path):
    plan = owned_json(plan_path)
    if plan.get('schema_version') != 1:
        raise RuntimeError('unsupported next-start plan')
    private = Path(plan['private_root'])
    if Path(plan_path) != private / 'configs/next-start.json':
        raise RuntimeError('next-start plan must be in its private configuration directory')
    candidate = Path(plan['candidate_config'])
    release = Path(plan['controller_release'])
    if candidate.parent != private / 'configs' or release.parent != private / 'releases':
        raise RuntimeError('next-start candidate escapes private release/profile directories')
    if digest(candidate) != plan['candidate_config_sha256']:
        raise RuntimeError('staged profile changed; restage before activation')
    if digest(release / 'src/controlled_dev_machine/next_start.py') != plan['activation_code_sha256']:
        raise RuntimeError('staged activation code changed')
    return plan


def stage(current_config, candidate_config):
    current, candidate = DevelopmentSandbox(Path(current_config)), DevelopmentSandbox(Path(candidate_config))
    if current.private != candidate.private or current.home != candidate.home or current.project != candidate.project:
        raise RuntimeError('staged release must belong to the existing instance')
    if current.config_path == candidate.config_path:
        raise RuntimeError('candidate must be a separate immutable profile')
    if current.config['exit']['expected_exit'] != candidate.config['exit']['expected_exit']:
        raise RuntimeError('next-start staging must preserve the exact exit')
    old_parent = current.config['exit']
    new_parent = candidate.config['exit']
    if (old_parent['parent_host'], old_parent['parent_port']) != (new_parent['parent_host'], new_parent['parent_port']):
        raise RuntimeError('next-start staging must preserve the configured parent')
    for key in ['target_image', 'gateway_image']:
        image = json.loads(candidate.run(candidate.docker + ['image', 'inspect', candidate.config[key]]).stdout)[0]
        if not candidate.config[key].startswith('sha256:') or image['Id'] != candidate.config[key]:
            raise RuntimeError('next-start images must be locally available immutable digests')
        if key == 'target_image' and image.get('Config', {}).get('Labels', {}).get('org.controlled-dev-machine.source') != candidate.config['release_id']:
            raise RuntimeError('target image does not match the staged source revision')
    release_record = owned_json(candidate.release / 'RELEASE.json')
    if release_record['commit'] != candidate.config['release_id']:
        raise RuntimeError('candidate source identity differs')
    for name in ['bin/ssh-native-host', 'bin/development-next-start', 'src/controlled_dev_machine/ssh_native_client.py']:
        if not (candidate.release / name).is_file():
            raise RuntimeError('candidate native SSH/activation source is incomplete')
    root = current.private
    (root / 'startup').mkdir(mode=0o700, parents=True, exist_ok=True)
    plan_path = root / 'configs/next-start.json'
    backup = root / 'backups' / ('next-start-stage-' + str(time.time_ns()))
    backup.mkdir(mode=0o700, parents=True)
    dropin = current.unit_dir / (current.project + '.service.d/99-next-start.conf')
    for file in [plan_path, root / 'startup/controller.json', dropin]:
        if file.exists():
            shutil.copy2(file, backup / (file.parent.name + '-' + file.name))
    alias = root / 'configs/runtime.json'
    if alias.exists() or alias.is_symlink():
        if alias.resolve() != current.config_path:
            raise RuntimeError('host-local runtime profile differs from the selected instance')
    else:
        select_profile(alias, current.config_path)
    plan = {'schema_version': 1, 'state': 'staged', 'staged_at': stamp(),
            'private_root': str(root), 'current_config': str(current.config_path),
            'current_config_sha256': digest(current.config_path),
            'candidate_config': str(candidate.config_path),
            'candidate_config_sha256': digest(candidate.config_path),
            'controller_release': str(candidate.release), 'release_id': candidate.config['release_id'],
            'activation_code_sha256': digest(candidate.release / 'src/controlled_dev_machine/next_start.py'),
            'before': current.status(), 'stage_backup': str(backup),
            'activation_trigger': 'next main service start/restart; sbc restart after selector installation',
            'running_services_restarted': False}
    atomic_json(plan_path, plan)
    atomic_json(root / 'startup/controller.json', {'controller_release': str(candidate.release), 'runtime_config': str(alias)})
    command = shlex.join([current.python, '-I', str(candidate.release / 'bin/development-next-start'),
                          'activate', '--plan', str(plan_path)]).replace('%', '%%')
    # Only future startup is changed. Do not prepare(), install units/entries,
    # write generated runtime files, or restart any running service here.
    write_file(dropin, '[Service]\nExecStart=\nExecStart=' + command + '\nTimeoutStartSec=600\n', 0o644)
    current.run(['systemctl', '--user', 'daemon-reload'])
    after = current.status()
    if after.get('container_id') != plan['before'].get('container_id'):
        raise RuntimeError('unexpected target replacement during read-only staging')
    plan['after_stage'] = after
    atomic_json(plan_path, plan)
    return plan


def retire_registered_capacity(app):
    """Only called by an explicitly selected future main-start activation."""
    for path in (app.private / 'configs').glob('egress-capacity-hotfix-*.json'):
        data = owned_json(path)
        if not data.get('applied'):
            continue
        expected = data.get('new_containers', {})
        if set(expected) != {'web', 'dns'}:
            raise RuntimeError('capacity registration is incomplete; refusing automatic retirement')
        owned = []
        for role, record in expected.items():
            result = app.run(app.docker + ['inspect', record['id']], check=False)
            if result.returncode:
                continue
            info = json.loads(result.stdout)[0]
            labels = info.get('Config', {}).get('Labels') or {}
            if not info['Name'].startswith('/' + app.project + '-capacity-' + role + '-') or not str(labels.get('org.controlled-dev-machine.hotfix', '')).startswith('capacity-'):
                raise RuntimeError('registered capacity container ownership differs')
            owned.append(info)
        # Main activation is a restart window, not a connection-preserving hot
        # repair. Stop this instance before retiring its namespace-scoped route.
        for role in ['target', 'gateway', 'dns']:
            result = app.run(app.docker + ['inspect', app.project + '-' + role + '-1'], check=False)
            if result.returncode:
                continue
            info = json.loads(result.stdout)[0]
            labels = info.get('Config', {}).get('Labels') or {}
            if labels.get('com.docker.compose.project') != app.project:
                raise RuntimeError('refusing to stop a foreign sandbox component')
        app.run(app.docker + ['stop', '--timeout', '20', *[app.project + '-' + r + '-1' for r in ['target', 'gateway', 'dns']]], timeout=120)
        for info in owned:
            app.run(app.docker + ['update', '--restart=no', info['Id']])
            app.run(app.docker + ['stop', '--timeout', '10', info['Id']], timeout=30)
            for network in info['NetworkSettings']['Networks']:
                app.run(app.docker + ['network', 'disconnect', '-f', network, info['Id']], check=False)
        # Gateway/DNS network namespaces (and the temporary NAT table) are now
        # gone. Do not flush host rules or touch unrelated containers/networks.
        data.update(applied=False, retired_at=stamp(), retired_for_release=app.config['release_id'])
        atomic_json(path, data)


def activate(plan_path):
    plan = validate_plan(Path(plan_path))
    root = Path(plan['private_root'])
    profile = root / 'configs/runtime.json' if plan['state'] == 'applied' else Path(plan['candidate_config'])
    app = DevelopmentSandbox(profile)
    with app.lock():
        if plan['state'] != 'applied':
            if digest(plan['current_config']) != plan['current_config_sha256']:
                raise RuntimeError('current host profile changed since staging; restage instead of overwriting it')
            # This code is never called by stage or an observation heartbeat.
            app.run(['systemctl', '--user', 'stop', app.project + '-health.timer',
                     app.project + '-health.service', app.project + '-exit-monitor.service'], check=False, timeout=90)
            retire_registered_capacity(app)
            select_profile(root / 'configs/runtime.json', app.config_path)
        try:
            app.start()
            for _ in range(60):
                if app.status().get('exit_verified'):
                    break
                time.sleep(.5)
            app.install_entries()
            plan.update(state='applied', applied_at=stamp(), after_activation=app.status())
            atomic_json(plan_path, plan)
        except Exception:
            if app.admitted:
                atomic_json(app.state / 'readiness.json', {'ok': False, 'config_sha256': app.config_sha, 'reason': 'next-start activation failed'})
                (app.state / 'exit-control/lease.json').unlink(missing_ok=True)
            raise
    return plan


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    s = sub.add_parser('stage')
    s.add_argument('--current-config', required=True, type=Path)
    s.add_argument('--candidate-config', required=True, type=Path)
    a = sub.add_parser('activate')
    a.add_argument('--plan', required=True, type=Path)
    args = p.parse_args(argv)
    result = stage(args.current_config, args.candidate_config) if args.command == 'stage' else activate(args.plan)
    print(json.dumps({'state': result['state'], 'release_id': result['release_id'],
                      'running_services_restarted_during_stage': result['running_services_restarted']}))


if __name__ == '__main__':
    main()
