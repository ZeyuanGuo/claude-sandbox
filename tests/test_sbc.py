from pathlib import Path
import runpy
import sys


def test_sbc_help_does_not_require_an_installed_instance(monkeypatch, capsys):
    module = runpy.run_path(str(Path("bin/sbc")), run_name="sbc_test")
    monkeypatch.setattr(sys, "argv", ["sbc", "--help"])
    assert module["main"]() == 0
    assert "recover" in capsys.readouterr().out


def test_rootless_entry_uses_the_registered_release_and_configuration(monkeypatch):
    from types import SimpleNamespace
    import json
    import os
    import pwd
    import pytest
    module = runpy.run_path(str(Path("bin/sbc")), run_name="sbc_test")
    monkeypatch.setattr(sys, "argv", ["sbc", "status"])
    monkeypatch.setattr(os, "getuid", lambda: 1234)
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name="developer", pw_gid=1234, pw_dir="/home/developer"))
    monkeypatch.setattr(Path, "is_file", lambda p: True)
    entry = {"uid": 1234, "gid": 1234, "home": "/home/developer", "backend": "rootless-development",
             "python": "/private/controller/python", "controller": "/private/releases/abc/bin/development-sandbox", "config": "/private/host.json"}
    monkeypatch.setattr(Path, "read_text", lambda p: json.dumps(entry))
    captured = []
    def execute(executable, args):
        captured.append(args)
        raise SystemExit(0)
    monkeypatch.setattr(os, "execv", execute)
    with pytest.raises(SystemExit):
        module["main"]()
    assert captured == [[entry["python"], "-I", entry["controller"], "--config", entry["config"], "status"]]
