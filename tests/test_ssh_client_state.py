from pathlib import Path
import socket
import pytest

from controlled_dev_machine.ssh_client_state import SSHClientState


def fixture(tmp_path, monkeypatch):
    home = tmp_path / 'host'
    source = home / '.ssh'
    source.mkdir(parents=True)
    source.chmod(0o700)
    (source / 'config').write_text('Host first\n HostName 192.0.2.10\n User worker\n')
    (source / 'config').chmod(0o600)
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: home))
    destination = tmp_path / 'client'
    return source, destination, SSHClientState(source, destination, Path('/home/sandbox'))


def test_added_host_key_and_alias_appear_without_replacing_the_mounted_directory(tmp_path, monkeypatch):
    source, dest, sync = fixture(tmp_path, monkeypatch)
    sync.refresh()
    inode = dest.stat().st_ino
    (source / 'new-key').write_text('private-test-key')
    (source / 'known-new').write_text('new-host test-host-key')
    with (source / 'config').open('a') as stream:
        stream.write(f'Host added\n HostName 192.0.2.11\n User another\n IdentityFile {source}/new-key\n UserKnownHostsFile {source}/known-new\n')
    assert sync.refresh()
    config = (dest / 'config').read_text()
    assert 'Host added' in config
    assert 'IdentityFile /home/sandbox/.ssh/new-key' in config
    assert 'UserKnownHostsFile /home/sandbox/.ssh/known-new' in config
    assert (dest / 'new-key').read_text() == 'private-test-key'
    assert dest.stat().st_ino == inode
    assert not sync.refresh()


def test_removed_keys_disappear_and_host_control_sockets_are_not_copied(tmp_path, monkeypatch):
    source, dest, sync = fixture(tmp_path, monkeypatch)
    (source / 'old-key').write_text('private-test-key')
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(source / 'cm.sock'))
    try:
        sync.refresh()
        assert not (dest / 'cm.sock').exists()
        assert (dest / 'old-key').exists()
        (source / 'old-key').unlink()
        sync.refresh()
        assert not (dest / 'old-key').exists()
    finally:
        sock.close()


def test_invalid_configuration_preserves_last_usable_client_files(tmp_path, monkeypatch):
    source, dest, sync = fixture(tmp_path, monkeypatch)
    sync.refresh()
    before = (dest / 'config').read_bytes()
    (source / 'config').write_text('Host bad\n UnsupportedOption yes\n')
    with pytest.raises(Exception):
        sync.refresh()
    assert (dest / 'config').read_bytes() == before


def test_existing_remote_socks_gateway_stays_an_argument_vector(tmp_path, monkeypatch):
    import controlled_dev_machine.ssh_alias_bridge as bridge
    calls=[]
    def effective(alias, config):
        calls.append((alias,config))
        if alias=='a100-gateway':return {'hostname':['192.0.2.2'],'port':['22']}
        return {'hostname':['10.0.0.10'],'port':['22'],'proxycommand':['/usr/bin/ssh -T -F ~/.ssh/a100-gateway.conf a100-gateway /usr/bin/nc -X 5 -x 127.0.0.1:11080 %h %p']}
    monkeypatch.setattr(bridge,'effective',effective)
    kind,args=bridge.route_plan('a100a',tmp_path/'config','10.0.0.10',22)
    assert kind=='process' and args[0]=='/usr/bin/ssh'
    assert args[-2:]==['10.0.0.10','22']
    assert '-oStrictHostKeyChecking=yes' in args
    assert calls[-1][0]=='a100-gateway'
    with pytest.raises(ValueError,match='destination differs'):
        bridge.route_plan('a100a',tmp_path/'config','10.0.0.11',22)
