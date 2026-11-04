import json
from pathlib import Path
import threading

import pytest

from controlled_dev_machine.development import DevelopmentSandbox, install_entry, load_config, write_file
from controlled_dev_machine.exit_monitor import atomic_json, refresh, validate_exit_config


def exit_config():
    return {"parent_proxy": "http://192.0.2.10:18080", "expected_exit": "198.51.100.20",
            "probe_urls": ["https://probe-one.example/ip", "https://probe-two.example/ip"]}


def profile(tmp_path):
    home = tmp_path / "host"
    apps = tmp_path / "private/apps"
    (home / "project-a").mkdir(parents=True)
    apps.mkdir(parents=True)
    identity = tmp_path / "identity.json"
    identity.write_text(json.dumps({"hostname": "same-workstation", "machine_id": "a" * 32,
        "mac_address": "02:00:00:00:00:01", "timezone": "UTC", "lang": "en_US.UTF-8", "lc_all": "en_US.UTF-8",
        "boot_id": "12345678-1234-1234-1234-123456789012", "hostid": "01020304"}))
    root = Path(__file__).parents[1]
    value = {"schema_version": 2, "release": str(root), "release_id": "abcdef1234", "private_root": str(tmp_path / "private"),
        "host_home": str(home), "target_home": "/home/developer", "user": "developer", "uid": 1234, "gid": 1234,
        "project": "test-sandbox", "docker_context": "rootless", "python": "/usr/bin/python3", "uid_tools": str(tmp_path / "tools"),
        "target_image": "target:fixture", "gateway_image": "gateway:fixture", "mapper_image": "mapper:fixture",
        "identity_profile": str(identity), "mounts": [{"path": "project-a"}], "exit": exit_config(), "gpu": "none"}
    path = tmp_path / "deployment.json"
    path.write_text(json.dumps(value))
    return path, value


def test_native_launcher_install_does_not_overwrite_symlink_target(tmp_path):
    real = tmp_path / "vendor"
    real.write_bytes(b"native vendor program")
    entry = tmp_path / "claude"
    entry.symlink_to(real)
    install_entry(entry, "#!/bin/sh\nexit 2\n")
    assert not entry.is_symlink()
    assert real.read_bytes() == b"native vendor program"
    install_entry(entry, "#!/bin/sh\nexit 3\n")
    assert real.read_bytes() == b"native vendor program"


def test_generated_public_mounts_remain_readable_with_private_deploy_umask(tmp_path):
    import os
    old = os.umask(0o077)
    try:
        p = tmp_path / "public-profile"
        write_file(p, "first", 0o644)
        assert p.stat().st_mode & 0o777 == 0o644
        write_file(p, "updated", 0o644)
        assert p.stat().st_mode & 0o777 == 0o644
        write_file(tmp_path / "private-config", "secret")
        assert (tmp_path / "private-config").stat().st_mode & 0o777 == 0o600
        atomic_json(tmp_path / "public-identity", {"ready": True}, 0o444)
        assert (tmp_path / "public-identity").stat().st_mode & 0o777 == 0o444
    finally:
        os.umask(old)


def test_render_mounts_private_home_and_only_explicit_host_paths(tmp_path):
    path, value = profile(tmp_path)
    app = DevelopmentSandbox(path)
    compose = app.render()
    target = compose["services"]["target"]
    mounts = {m["target"]: m for m in target["volumes"]}
    assert mounts["/home/developer"]["source"] == str(tmp_path / "private/uid-app/view/home")
    assert mounts["/home/developer/project-a"]["source"] == str(tmp_path / "private/uid-home/view/project-a")
    assert not any(m["source"] == str(tmp_path / "private/uid-home/view") for m in target["volumes"])
    assert "/var/tmp/claude-work" in mounts
    assert mounts["/home/developer/.claude"]["source"].endswith("uid-app/view/.claude")
    assert target["environment"]["CLAUDE_CODE_TMPDIR"] == "/var/tmp/claude-work"
    assert target["devices"] == []
    assert set(target["networks"]) == {"target_net"}
    assert compose["services"]["egress"]["environment"]["CDM_RELAY_EXPECTED_EXIT"] == value["exit"]["expected_exit"]
    assert "+/audit/plaintext/flows-%Y%m%d-%H.mitm" in compose["services"]["gateway"]["command"]


@pytest.mark.parametrize("bad", [".", "../private", ".ssh", ".local/share/docker", "/home/host"])
def test_config_refuses_whole_home_and_control_mounts(tmp_path, bad):
    path, value = profile(tmp_path)
    value["mounts"] = [{"path": bad}]
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        load_config(path)


def test_exit_is_an_exact_configured_address_not_a_hardcoded_provider():
    for address in ("198.51.100.20", "203.0.113.55"):
        config = dict(exit_config(), expected_exit=address)
        result = refresh(config, boot_id="test", probe_fn=lambda c, url: {"ok": True, "observed": c["expected_exit"]})
        assert result["ok"] and result["observed_exit"] == address
    with pytest.raises(ValueError):
        validate_exit_config(dict(exit_config(), expected_exit="198.51.100.0/24"))


def test_shared_credentials_keep_history_local_and_both_locks_shared(tmp_path):
    path, value = profile(tmp_path)
    value["mounts"].append({"path": ".local/share/sandbox-auth"})
    value["claude_credentials_path"] = ".local/share/sandbox-auth/account"
    (Path(value["host_home"]) / value["claude_credentials_path"]).mkdir(parents=True)
    path.write_text(json.dumps(value))
    target = DevelopmentSandbox(path).render()["services"]["target"]
    assert target["environment"]["CLAUDE_SECURESTORAGE_CONFIG_DIR"] == "/home/developer/.local/share/sandbox-auth/account"
    mounts = {m["target"]: m for m in target["volumes"]}
    assert mounts["/home/developer/.claude"]["source"].endswith("uid-app/view/.claude")
    assert mounts["/home/developer/.local/share/sandbox-auth"]["read_only"] is False
    value["mounts"][-1]["read_only"] = True
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="sibling lock"):
        load_config(path)
    value["mounts"][-1] = {"path": value["claude_credentials_path"]}
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="sibling lock"):
        load_config(path)


def test_first_failed_probe_revokes_before_other_probe_finishes():
    revoked = threading.Event()
    def probe(config, endpoint):
        if endpoint.endswith("one.example/ip"):
            return {"ok": False, "error": "timeout"}
        assert revoked.wait(1), "failure must publish before waiting for the slow successful probe"
        return {"ok": True, "observed": config["expected_exit"]}
    published = []
    def publish(value):
        published.append(value)
        if not value["ok"]:
            revoked.set()
    value = refresh(exit_config(), boot_id="test", probe_fn=probe, publish=publish)
    assert not value["ok"]
    assert published and all(not record["ok"] for record in published)


def test_missing_runtime_readiness_denies_without_any_probe(tmp_path):
    config = dict(exit_config(), readiness_path=str(tmp_path / "missing"), required_config_sha256="test")
    def forbidden(*args):
        raise AssertionError("unready runtime must not probe or issue a valid lease")
    value = refresh(config, boot_id="test", probe_fn=forbidden)
    assert not value["ok"] and value["reason"] == "runtime-not-ready"


def test_exit_display_is_opt_in_interactive_and_uses_the_controlled_proxy(tmp_path):
    path, value = profile(tmp_path)
    shell, env = DevelopmentSandbox(path).shell_content()
    assert "curl " not in shell
    value["interactive_exit_probe_url"] = "https://probe.example/ip"
    path.write_text(json.dumps(value))
    shell, env = DevelopmentSandbox(path).shell_content()
    assert "case $- in *i*) ( curl " in shell
    assert "--proxy http://172.31.0.23:8080" in shell
    assert "--max-time 5" in shell
    assert env["PYTHONNOUSERSITE"] == "1"
    assert env["PATH"].startswith("/opt/sbc/bin:")


def test_native_updater_absolute_link_is_resolved_in_persistent_home(tmp_path):
    path, _ = profile(tmp_path)
    app = DevelopmentSandbox(path)
    entry = app.apps / "home/.local/bin/claude"
    entry.parent.mkdir(parents=True)
    real = app.apps / "home/.local/share/claude/versions/new"
    real.parent.mkdir(parents=True)
    real.write_bytes(b"new native version")
    entry.symlink_to("/home/developer/.local/share/claude/versions/new")
    assert app.native_host_path() == real


def test_mount_preparation_refuses_to_hide_unmapped_private_work(tmp_path):
    path, _ = profile(tmp_path)
    app = DevelopmentSandbox(path)
    work = app.apps / "home/project-a"
    work.mkdir(parents=True)
    (work / "unsaved-work.txt").write_text("preserve")
    with pytest.raises(RuntimeError, match="hide private Home"):
        app.prepare_mountpoints()
    assert (work / "unsaved-work.txt").read_text() == "preserve"


def test_private_checkpoint_preserves_transcripts_and_skips_sockets(tmp_path):
    import socket
    import tarfile
    from controlled_dev_machine.state_archive import checkpoint
    apps = tmp_path / "apps"
    (apps / ".claude/projects/project").mkdir(parents=True)
    (apps / ".claude/projects/project/session.jsonl").write_text('{"message":"keep"}\n')
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(apps / "runtime.sock"))
    try:
        result = checkpoint(apps, tmp_path / "archive", quiesced=True)
    finally:
        listener.close()
    assert result["consistent"]
    assert result["skipped_runtime_objects"] == ["runtime.sock"]
    with tarfile.open(Path(result["path"]) / "apps.tar.gz") as archive:
        assert archive.extractfile(".claude/projects/project/session.jsonl").read() == b'{"message":"keep"}\n'


def test_failed_admission_does_not_revoke_an_existing_instance(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace
    import controlled_dev_machine.development as module
    writes = []
    app = SimpleNamespace(admitted=False, lock=lambda: nullcontext(), start=lambda: (_ for _ in ()).throw(RuntimeError("preflight rejected")), state=tmp_path, config_sha="new")
    monkeypatch.setattr(module, "DevelopmentSandbox", lambda path: app)
    monkeypatch.setattr(module, "atomic_json", lambda *args: writes.append(args))
    with pytest.raises(RuntimeError, match="preflight rejected"):
        module.main(["--config", "/unused", "start"])
    assert writes == []


def test_failed_admitted_start_revokes_readiness_and_old_lease(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace
    import controlled_dev_machine.development as module
    lease = tmp_path / "exit-control/lease.json"
    lease.parent.mkdir()
    lease.write_text("old lease")
    app = SimpleNamespace(admitted=True, lock=lambda: nullcontext(), start=lambda: (_ for _ in ()).throw(RuntimeError("identity failed")), state=tmp_path, config_sha="new")
    monkeypatch.setattr(module, "DevelopmentSandbox", lambda path: app)
    with pytest.raises(RuntimeError, match="identity failed"):
        module.main(["--config", "/unused", "start"])
    assert not lease.exists()
    assert json.loads((tmp_path / "readiness.json").read_text())["ok"] is False


def test_legacy_home_keeps_project_and_application_paths_with_same_identity(tmp_path):
    path, value = profile(tmp_path)
    value['home_aliases'] = ['/home/legacy']
    path.write_text(json.dumps(value))
    app = DevelopmentSandbox(path)
    mounts = {m['target']: m for m in app.render()['services']['target']['volumes']}
    for name in ['', '/project-a', '/.claude', '/.ssh', '/.bashrc']:
        assert mounts['/home/legacy'+name]['source'] == mounts['/home/developer'+name]['source']
    assert app.render()['services']['target']['environment']['HOME'] == '/home/developer'


def test_local_environment_override_uses_separate_uid_view(tmp_path):
    path, value = profile(tmp_path)
    source = tmp_path/'private/data/miniconda3'
    source.mkdir(parents=True)
    value['mounts'].append({'path':'miniconda3','source':str(source)})
    path.write_text(json.dumps(value))
    app = DevelopmentSandbox(path)
    mounts = {m['target']:m for m in app.render()['services']['target']['volumes']}
    assert mounts['/home/developer/miniconda3']['source']==str(tmp_path/'private/uid-data/view/miniconda3')
    assert (tmp_path/'private/data','uid-data') in app.mapper_sources()
    value['mounts'][-1]['source']='/unrelated/place'
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='local data overrides'):
        load_config(path)


def test_interactive_shell_has_common_aliases_and_user_extension(tmp_path):
    import subprocess
    import os
    path, _ = profile(tmp_path)
    shell, _ = DevelopmentSandbox(path).shell_content()
    rc=tmp_path/'bashrc';rc.write_text(shell)
    p=subprocess.run(['/bin/bash','--noprofile','--rcfile',str(rc),'-ic','alias ll la l lh ca cab; shopt histappend checkwinsize'],text=True,capture_output=True,env=dict(os.environ,HOME=str(tmp_path)))
    assert p.returncode==0
    assert "alias ll='ls -alF'" in p.stdout
    assert 'histappend' in p.stdout and 'checkwinsize' in p.stdout
    assert '"$HOME/.bash_aliases"' in shell


def test_external_data_keeps_original_path_without_exposing_control(tmp_path, monkeypatch):
    path,value=profile(tmp_path)
    value['external_mounts']=[{'source':'/data/project','target':'/data/project'}]
    path.write_text(json.dumps(value))
    original=Path.exists
    monkeypatch.setattr(Path,'exists',lambda p: True if str(p)=='/data/project' else original(p))
    app=DevelopmentSandbox(path)
    mounts={m['target']:m for m in app.render()['services']['target']['volumes']}
    assert mounts['/data/project']['source']==str(tmp_path/'private/uid-extra-0/view')
    assert (Path('/data/project'),'uid-extra-0') in app.mapper_sources()
    value['private_root']='/data/private'
    value['external_mounts']=[{'source':'/data','target':'/data'}]
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='expose a Home or control'):
        load_config(path)


def test_shared_root_permission_is_explicit_and_not_a_general_owner_bypass(tmp_path, monkeypatch):
    import stat
    from types import SimpleNamespace
    import controlled_dev_machine.rootless_uid_mount as module
    source=tmp_path/'shared';source.mkdir();state=tmp_path/'state';state.mkdir();view=state/'view';view.mkdir()
    original=Path.stat
    owner={'uid':65534}
    monkeypatch.setattr(Path,'stat',lambda p,**kw: SimpleNamespace(st_uid=owner['uid'],st_gid=65534,st_mode=stat.S_IFDIR|0o755) if p==source else original(p,**kw))
    monkeypatch.setattr(module,'ALLOW_SHARED_ROOT',False)
    with pytest.raises(RuntimeError,match='not owned'):
        module._paths(source,view,state)
    monkeypatch.setattr(module,'ALLOW_SHARED_ROOT',True)
    module._paths(source,view,state)
    owner['uid']=12345
    with pytest.raises(RuntimeError,match='not owned'):
        module._paths(source,view,state)


def test_current_and_legacy_claude_temp_paths_share_persistent_storage(tmp_path):
    path,value=profile(tmp_path)
    value['tmp_compat_path']='/tmp/claude-999'
    path.write_text(json.dumps(value))
    mounts={m['target']:m for m in DevelopmentSandbox(path).render()['services']['target']['volumes']}
    assert mounts['/tmp/claude-1234']['source']==mounts['/tmp/claude-999']['source']==mounts['/var/tmp/claude-work']['source']
    value['tmp_compat_path']='/tmp/claude-1234'
    path.write_text(json.dumps(value))
    DevelopmentSandbox(path).render()  # No duplicate bind when old and current IDs match.


def test_nvm_is_available_without_changing_the_configured_node_selection(tmp_path):
    import os,subprocess
    path,_=profile(tmp_path)
    nvm=tmp_path/'.nvm';nvm.mkdir()
    (nvm/'nvm.sh').write_text('NVM_TEST_OPTIONS="$*"\nnvm(){ :; }\n')
    text,_=DevelopmentSandbox(path).shell_content();rc=tmp_path/'bashrc';rc.write_text(text)
    r=subprocess.run(['/bin/bash','--noprofile','--rcfile',str(rc),'-ic','type -t nvm; printf "%s %s %s\\n" "$NVM_TEST_OPTIONS" "$HISTSIZE" "$HISTFILESIZE"'],env=dict(os.environ,HOME=str(tmp_path)),text=True,capture_output=True)
    assert r.returncode==0 and 'function' in r.stdout and '--no-use 1000 2000' in r.stdout


def test_dns_has_reserved_egress_capacity_and_writable_data_cannot_be_ssh_control(tmp_path):
    path,value=profile(tmp_path)
    app=DevelopmentSandbox(path);services=app.render()['services']
    assert services['dns']['depends_on']==['egress-dns']
    dns_host=services['dns']['command'][services['dns']['command'].index('--proxy-host')+1]
    assert dns_host==services['egress-dns']['networks']['upstream_net']['ipv4_address']
    assert dns_host!=services['egress']['networks']['upstream_net']['ipv4_address']
    assert services['egress']['environment']['CDM_RELAY_EXPECTED_EXIT']==services['egress-dns']['environment']['CDM_RELAY_EXPECTED_EXIT']
    value['ssh_extra_roots']=[str(tmp_path/'host/project-a/ssh')]
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='outside writable'):
        load_config(path)


def test_single_role_relays_have_no_implicit_other_peer(tmp_path):
    from controlled_dev_machine.degraded_egress import RelayConfig
    web=RelayConfig.from_mapping({'trusted_gateway_ips':['192.0.2.2'],'trusted_dns_ips':[],'max_sessions':256},audit_path=tmp_path/'web')
    dns=RelayConfig.from_mapping({'trusted_gateway_ips':[],'trusted_dns_ips':['192.0.2.3'],'max_sessions':16},audit_path=tmp_path/'dns')
    assert web.dns_source is None and web.gateway_source=='192.0.2.2'
    assert dns.gateway_source is None and dns.dns_source=='192.0.2.3'
    with pytest.raises(ValueError):RelayConfig.from_mapping({'trusted_gateway_ips':[],'trusted_dns_ips':[]},audit_path=tmp_path/'closed')
