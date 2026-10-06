from pathlib import Path

import pytest

from controlled_dev_machine.degraded_topology import build_compose


def compose(tmp_path: Path, *, upstream: bool = False):
    return build_compose(root=tmp_path / "repo", runtime=tmp_path / "runtime",
                         state=tmp_path / "state", target_image="target@sha256:fixture",
                         gateway_image="gateway@sha256:fixture", policy=tmp_path / "policy.yaml",
                         policy_digest="raw:fixture", upstream_host="192.168.71.10" if upstream else "",
                         upstream_port="8080" if upstream else "",
                         dns_suffixes=("api.anthropic.com",) if upstream else ())


def test_target_has_no_direct_external_or_relay_network(tmp_path):
    config = compose(tmp_path, upstream=True)
    target = config["services"]["target"]
    assert set(target["networks"]) == {"target_net"}
    assert config["networks"]["target_net"]["internal"]
    assert config["networks"]["upstream_net"]["internal"]
    assert "ALL" in target["cap_drop"]
    assert "ports" not in target and "network_mode" not in target


def test_strict_local_target_has_only_loopback_and_proxy_bridges(tmp_path):
    config = build_compose(root=tmp_path / "repo", runtime=tmp_path / "runtime",
                           state=tmp_path / "state", target_image="target",
                           gateway_image="gateway", policy=tmp_path / "policy",
                           policy_digest="raw:fixture", upstream_host="192.168.71.10",
                           upstream_port="8080", dns_suffixes=("api.ipify.org",),
                           strict_local=True)
    target = config["services"]["target"]
    assert target["network_mode"] == "none"
    assert "networks" not in target
    assert target["environment"]["HTTP_PROXY"] == "http://127.0.0.1:8080"
    assert set(config["services"]) == {"dns", "gateway", "egress", "target",
                                        "net-bridge", "local-bridge"}
    assert config["services"]["local-bridge"]["network_mode"] == "service:target"
    assert config["services"]["net-bridge"]["networks"]["target_net"]["ipv4_address"] == "172.31.0.5"


def test_only_relay_has_external_network_even_with_parent_configured(tmp_path):
    config = compose(tmp_path, upstream=True)
    external_services = {name for name, service in config["services"].items()
                         if "egress_net" in service["networks"]}
    assert external_services == {"egress"}
    assert config["networks"]["egress_net"]["internal"] is False
    assert config["networks"]["egress_net"]["enable_ipv6"] is False


def test_no_parent_means_no_external_network(tmp_path):
    config = compose(tmp_path)
    assert "egress_net" not in config["networks"]
    assert all("egress_net" not in item["networks"] for item in config["services"].values())


def test_external_parent_requires_explicit_dns_allowlist(tmp_path):
    with pytest.raises(ValueError, match="DNS suffix allowlist"):
        build_compose(root=tmp_path / "repo", runtime=tmp_path / "runtime",
                      state=tmp_path / "state", target_image="target",
                      gateway_image="gateway", policy=tmp_path / "policy",
                      policy_digest="raw:fixture", upstream_host="192.0.2.1",
                      upstream_port="8080")


def test_gateway_entrypoint_arguments_and_health_gate_are_explicit(tmp_path):
    gateway = compose(tmp_path)["services"]["gateway"]
    assert gateway["command"][0] == "--mode"
    assert "mitmdump" not in gateway["command"]
    assert "upstream_cert=false" in gateway["command"]
    assert "ssl_insecure=false" in gateway["command"]
    assert gateway["healthcheck"]["test"][-1] == "controlled_dev_machine.gateway_health"


def test_dns_uses_fixed_relay_without_recursing_through_gateway(tmp_path):
    services = compose(tmp_path)["services"]
    dns_args = services["dns"]["command"]
    assert dns_args[dns_args.index("--proxy-host") + 1] == "172.31.1.10"
    assert dns_args[dns_args.index("--doh-address") + 1] == "1.1.1.1"
    assert services["gateway"]["dns"] == ["172.31.0.2"]
    assert services["target"]["dns"] == ["172.31.0.2"]
    assert services["gateway"]["environment"]["CDM_DNS_LEASE_SOCKET"] == "/run/cdm-dns/lease.sock"


def test_runtime_preserves_original_absolute_paths_locale_timezone(tmp_path):
    target = compose(tmp_path)["services"]["target"]
    env = target["environment"]
    assert target["user"] == "0:0"
    assert target["hostname"] == "devbox"
    assert target["working_dir"] == env["HOME"] == "/home/gzy"
    assert env["USER"] == "gzy"
    assert env["CLAUDE_CONFIG_DIR"] == "/home/gzy/.claude"
    assert env["TZ"] == "America/Los_Angeles"
    assert env["LANG"] == env["LC_ALL"] == "en_US.UTF-8"
    assert env["CDM_CONDA_ROOT"] == "/home/gzy/miniconda3"
    assert env["CDM_DEFAULT_CONDA_ENV"] == "pthgnn"
    assert env["CONDA_DEFAULT_ENV"] == "pthgnn"
    assert env["PATH"].startswith("/home/gzy/miniconda3/envs/pthgnn/bin:/home/gzy/miniconda3/bin:")
    assert env["LD_LIBRARY_PATH"] == "/run/cdm-nvidia:/home/gzy/miniconda3/lib"
    assert target["command"] == ["sleep", "infinity"]  # Original container inspect.
    volumes = {item["target"]: item for item in target["volumes"]}
    assert volumes["/home/gzy"]["source"] == str(tmp_path / "runtime/home")
    assert volumes["/etc/ssl/certs/ca-certificates.crt"]["read_only"]
    assert all(not item["bind"]["create_host_path"] for item in volumes.values())
