from types import SimpleNamespace
import pytest
import controlled_dev_machine.rootless_uid_mount as module


@pytest.mark.parametrize('check_status', [0, 2])
def test_health_under_keyring_exhaustion_preserves_real_check_result(tmp_path, monkeypatch, check_status):
    """Creating any container fails; checking the existing mapper still works."""
    monkeypatch.setattr(module, 'UID', module.UID)
    monkeypatch.setattr(module, 'GID', module.GID)
    monkeypatch.setattr(module, 'ALLOW_SHARED_ROOT', module.ALLOW_SHARED_ROOT)
    calls = []
    def runtime(command, **kwargs):
        calls.append(command)
        if command[:2] == ['docker', 'run']:
            return SimpleNamespace(returncode=125)  # runc session keyring quota exhausted
        assert command[:4] == ['docker', 'exec', '--user=0:0', 'fixture-mapper']
        assert 'check' in command and '--daemon-pid' in command
        assert '--source' in command and '--view' in command
        return SimpleNamespace(returncode=check_status)
    monkeypatch.setattr(module.subprocess, 'run', runtime)
    result = module.main(['status', '--daemon-pid', '123', '--source', str(tmp_path/'source'),
                          '--view', str(tmp_path/'view'), '--state', str(tmp_path/'state'),
                          '--tools', str(tmp_path/'tools'), '--name', 'fixture-mapper'])
    assert result == check_status
    assert len(calls) == 1
