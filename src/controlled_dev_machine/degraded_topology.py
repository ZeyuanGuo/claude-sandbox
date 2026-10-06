"""Rootless topology: an internal target and a fixed-parent egress relay."""
from __future__ import annotations

from pathlib import Path


def _rootless_gpu_mounts() -> tuple[list[str], list[dict]]:
    """Expose only pre-existing NVIDIA devices and driver libraries.

    Rootless Docker cannot use ``--gpus`` without a CDI installation. Direct
    device binds remain user-controlled and work when the host device nodes are
    world-readable, while the target still has all capabilities dropped.
    """
    device_names = sorted(path.name for path in Path("/dev").glob("nvidia[0-9]*"))
    device_names.extend(name for name in (
        "nvidiactl", "nvidia-uvm", "nvidia-uvm-tools", "nvidia-modeset"
    ) if (Path("/dev") / name).exists())
    devices = [f"/dev/{name}:/dev/{name}" for name in dict.fromkeys(device_names)]
    mounts = []
    library_names = ("libcuda.so.1", "libnvidia-ml.so.1")
    for name in library_names:
        for directory in (Path("/lib/x86_64-linux-gnu"),
                          Path("/usr/lib/x86_64-linux-gnu")):
            source = directory / name
            if source.exists():
                mounts.append({"type": "bind", "source": str(source),
                               "target": "/run/cdm-nvidia/" + name,
                               "read_only": True,
                               "bind": {"create_host_path": False}})
                break
    nvidia_smi = Path("/usr/bin/nvidia-smi")
    if nvidia_smi.is_file() and nvidia_smi.stat().st_mode & 0o111:
        mounts.append({"type": "bind", "source": str(nvidia_smi),
                       "target": "/usr/local/bin/nvidia-smi",
                       "read_only": True,
                       "bind": {"create_host_path": False}})
    return devices, mounts


def build_compose(
    *, root: Path, runtime: Path, state: Path, target_image: str,
    gateway_image: str, policy: Path, policy_digest: str,
    upstream_host: str = "", upstream_port: str = "", dns_suffixes: tuple[str, ...] = (),
    projects: Path | None = None, strict_local: bool = False,
) -> dict:
    if upstream_host and not dns_suffixes:
        raise ValueError(
            "an external parent requires an explicit DNS suffix allowlist"
        )
    audit = state / "audit"

    def mount(source: Path, target: str, readonly: bool = True) -> dict:
        return {"type": "bind", "source": str(source), "target": target,
                "read_only": readonly, "bind": {"create_host_path": False}}

    def service(image: str, command: list[str]) -> dict:
        return {"image": image, "user": "0:0", "command": command,
                "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
                "restart": "unless-stopped", "init": True}

    dns_command = ["python3", "/opt/cdm/dns_gateway.py", "--record-path",
                   "/audit/dns/queries.jsonl", "--proxy-host", "172.31.1.10",
                   "--proxy-port", "8080", "--doh-address", "1.1.1.1",
                   "--doh-server-name", "cloudflare-dns.com", "--lease-socket",
                   "/run/cdm-dns/lease.sock"]
    if dns_suffixes:
        for suffix in dns_suffixes:
            dns_command += ["--allowed-suffix", suffix]
    else:
        # Offline mode has no egress network; this is only useful for local
        # canaries and cannot send packets outside the internal networks.
        dns_command += ["--allow-public-domains"]
    dns = service(target_image, dns_command)
    dns.update({
        "volumes": [mount(root / "src/controlled_dev_machine/dns_gateway.py", "/opt/cdm/dns_gateway.py"),
                    mount(audit / "dns", "/audit/dns", False),
                    mount(state / "dns-control", "/run/cdm-dns", False)],
        "networks": {"target_net": {"ipv4_address": "172.31.0.2"},
                     "upstream_net": {"ipv4_address": "172.31.1.2"}},
        "dns": ["127.0.0.1"],
    })
    gateway = service(gateway_image, [
        "--mode", "regular@8080", "--set", "connection_strategy=lazy", "--set",
        "rawtcp=false", "--set", "upstream_cert=false", "--set", "ssl_insecure=false",
        "--set", "block_global=false",
        "--set", "confdir=/ca", "-w", "/audit/plaintext/flows.mitm",
        "-s", "/opt/cdm/gateway/cdm_addon.py",
    ])
    gateway.update({
        "environment": {
            "PYTHONPATH": "/opt/cdm/src", "CDM_DEGRADED_MODE": "1",
            "CDM_POLICY_PATH": "/run/cdm/policy.yaml", "CDM_EXPECTED_POLICY_DIGEST": policy_digest,
            "CDM_REVIEW_DIR": "/audit/review", "CDM_REVIEW_TTL_SECONDS": "300",
            "CDM_REVIEW_POLL_SECONDS": "0.25", "CDM_CANARY_ADDRESS": "127.0.0.1",
            "CDM_DNS_LEASE_SOCKET": "/run/cdm-dns/lease.sock",
            "CDM_UPSTREAM_HOST": "172.31.1.10", "CDM_UPSTREAM_PORT": "8080",
        },
        "volumes": [mount(policy, "/run/cdm/policy.yaml"),
                    mount(audit / "review", "/audit/review", False),
                    mount(audit / "plaintext", "/audit/plaintext", False),
                    mount(state / "dns-control", "/run/cdm-dns"),
                    mount(state / "proxy-ca", "/ca", False)],
        "networks": {"target_net": {"ipv4_address": "172.31.0.3"},
                     "upstream_net": {"ipv4_address": "172.31.1.3"}},
        "dns": ["172.31.0.2"],
        "healthcheck": {"test": ["CMD", "python3", "-m", "controlled_dev_machine.gateway_health"],
                        "interval": "5s", "timeout": "2s", "retries": 3},
    })
    relay = service(gateway_image, ["python3", "-m", "controlled_dev_machine.degraded_egress"])
    relay.update({
        "entrypoint": [],
        "environment": {"PYTHONPATH": "/opt/cdm/src", "CDM_RELAY_AUDIT": "/audit/egress/events.jsonl",
                        "CDM_RELAY_UPSTREAM_HOST": upstream_host,
                        "CDM_RELAY_UPSTREAM_PORT": upstream_port,
                        "CDM_RELAY_DNS_SOURCE": "172.31.1.2",
                        "CDM_RELAY_GATEWAY_SOURCE": "172.31.1.3"},
        "volumes": [mount(audit / "egress", "/audit/egress", False)],
        "networks": {"upstream_net": {"ipv4_address": "172.31.1.10"}},
        "dns": ["127.0.0.1"],
    })
    target = service(target_image, ["sleep", "infinity"])
    gpu_devices, gpu_mounts = _rootless_gpu_mounts()
    target.update({
        "hostname": "devbox", "working_dir": "/home/gzy",
        "environment": {
            "USER": "gzy", "HOME": "/home/gzy", "CLAUDE_CONFIG_DIR": "/home/gzy/.claude",
            "CDM_CONDA_ROOT": "/home/gzy/miniconda3", "CDM_DEFAULT_CONDA_ENV": "pthgnn",
            "PATH": "/home/gzy/miniconda3/envs/pthgnn/bin:/home/gzy/miniconda3/bin:/home/gzy/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "CONDA_DEFAULT_ENV": "pthgnn",
            "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TZ": "America/Los_Angeles",
            "NODE_USE_SYSTEM_CA": "1", "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
            "REQUESTS_CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt",
            "NODE_EXTRA_CA_CERTS": "/etc/ssl/certs/ca-certificates.crt",
            "LD_LIBRARY_PATH": "/run/cdm-nvidia:/home/gzy/miniconda3/lib",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
            "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
            "DISABLE_UPDATES": "1",
            "HTTP_PROXY": "http://127.0.0.1:8080" if strict_local else "http://172.31.0.3:8080",
            "HTTPS_PROXY": "http://127.0.0.1:8080" if strict_local else "http://172.31.0.3:8080",
            "http_proxy": "http://127.0.0.1:8080" if strict_local else "http://172.31.0.3:8080",
            "https_proxy": "http://127.0.0.1:8080" if strict_local else "http://172.31.0.3:8080",
            "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
        },
        "devices": gpu_devices,
        "volumes": [mount(runtime / "home", "/home/gzy", False),
                    mount(runtime / "miniconda3", "/home/gzy/miniconda3"),
                    mount(state / "trust/ca-certificates.crt", "/etc/ssl/certs/ca-certificates.crt"),
                    *gpu_mounts],
        "dns": ["172.31.0.2"],
        "networks": {"target_net": {"ipv4_address": "172.31.0.4"}},
    })
    project_root = projects or (runtime / "projects")
    for project in ("newdfm", "dfm"):
        path = project_root / project
        if path.is_dir():
            target["volumes"].append(mount(path, "/home/gzy/" + project, False))
    networks = {
        "target_net": {"internal": True, "enable_ipv6": False,
                       "ipam": {"config": [{"subnet": "172.31.0.0/24"}]}},
        "upstream_net": {"internal": True, "enable_ipv6": False,
                         "ipam": {"config": [{"subnet": "172.31.1.0/24"}]}},
    }
    if upstream_host:
        networks["egress_net"] = {"internal": False, "enable_ipv6": False}
        relay["networks"]["egress_net"] = {}
    services = {"dns": dns, "gateway": gateway, "egress": relay, "target": target}
    if strict_local:
        bridge_dir = state / "proxy-bridge"
        bridge_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        bridge_script = root / "src/controlled_dev_machine/proxy_bridge.py"
        net_bridge = service(gateway_image, ["python3", "/opt/cdm/proxy_bridge.py",
                                             "unix-listen", "--socket", "/run/cdm-proxy/gateway.sock",
                                             "--host", "172.31.0.3", "--port", "8080"])
        net_bridge.update({"volumes": [mount(bridge_script, "/opt/cdm/proxy_bridge.py"),
                                        mount(bridge_dir, "/run/cdm-proxy", False)],
                           "entrypoint": [],
                           "networks": {"target_net": {"ipv4_address": "172.31.0.5"}},
                           "dns": ["172.31.0.2"]})
        local_bridge = service(gateway_image, ["python3", "/opt/cdm/proxy_bridge.py",
                                               "tcp-listen", "--listen", "127.0.0.1:8080",
                                               "--socket", "/run/cdm-proxy/gateway.sock"])
        local_bridge.update({"network_mode": "service:target",
                             "entrypoint": [],
                             "volumes": [mount(bridge_script, "/opt/cdm/proxy_bridge.py"),
                                         mount(bridge_dir, "/run/cdm-proxy")],
                             "depends_on": ["target", "net-bridge"]})
        target["network_mode"] = "none"
        target.pop("networks", None)
        target.pop("dns", None)
        services["net-bridge"] = net_bridge
        services["local-bridge"] = local_bridge
    return {"name": "cdm-degraded", "services": services, "networks": networks}
