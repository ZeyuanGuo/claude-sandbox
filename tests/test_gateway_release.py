import json
from types import SimpleNamespace
import pytest
from controlled_dev_machine.development import DevelopmentSandbox


def app(tmp_path):
    obj = object.__new__(DevelopmentSandbox)
    obj.state = tmp_path
    obj.config = {"gateway_image": "original"}
    obj.config_sha = "a" * 64
    obj.docker = ["docker"]
    image = "sha256:" + "b" * 64
    obj.run = lambda args: SimpleNamespace(stdout=json.dumps([{
        "Id": image, "Config": {"Labels": {"cdm.source_digest": "c" * 40}}}]))
    return obj


def select(tmp_path, **changes):
    value = {"image": "sha256:" + "b" * 64, "source_commit": "c" * 40,
             "base_config_sha256": "a" * 64}
    value.update(changes)
    path = tmp_path / "gateway-release.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def test_gateway_selection_preserves_target_profile(tmp_path):
    obj = app(tmp_path)
    assert obj.gateway_image() == "original"
    select(tmp_path)
    assert obj.gateway_image() == "sha256:" + "b" * 64
    assert obj.config_sha == "a" * 64
    assert obj.config == {"gateway_image": "original"}


@pytest.mark.parametrize("change", [
    {"image": "gateway:latest"}, {"source_commit": "d" * 40},
    {"base_config_sha256": "e" * 64},
])
def test_gateway_selection_rejects_unverified_release(tmp_path, change):
    select(tmp_path, **change)
    with pytest.raises(RuntimeError):
        app(tmp_path).gateway_image()


def test_gateway_selection_rejects_shared_permissions(tmp_path):
    select(tmp_path).chmod(0o644)
    with pytest.raises(RuntimeError):
        app(tmp_path).gateway_image()
