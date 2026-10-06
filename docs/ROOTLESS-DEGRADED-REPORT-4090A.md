# Rootless degraded sandbox acceptance report

Date: 2026-10-04 (Asia/Shanghai)

Primary host: 4090a, user `gzy`, rootless Docker

Peer host: 4090b, user-scoped rootless Docker parity copy

## Decision boundary

This report covers the non-root fallback for the recovered Claude/CDM
sandbox. It is an offline acceptance, not a claim of equivalence with the
5090 root/transparent deployment. No Claude login, API request, user
credential, or unreviewed public upstream was started.

The target filesystem and its persistent runtime are retained. The control
plane is deliberately fail-closed: an unset parent makes all external proxy
and DNS requests fail, and a configured parent is accepted only after a
separate 5090 egress/DNS/CA/policy comparison.

## Current topology

The generated Compose document has four services and two always-internal
networks:

```text
target (.4) -- target_net (internal) -- gateway (.3)
       |                              -- dns (.2)
       |
       +-- no default route, no host ports, no external network

dns (.2) and gateway (.3) -- upstream_net (internal) -- egress relay (.10)
egress relay -- optional egress_net (the only external network)
```

Services are `target`, `dns`, `gateway`, and `egress`. The target uses an
explicit regular HTTP(S) proxy; it does not receive `NET_ADMIN`, raw packet
access, or a direct external network. The relay accepts only the fixed DNS
and gateway source addresses and forwards only to the configured fixed parent.
When no parent is configured, the `egress_net` network is omitted entirely.

The target is started as an idle long-lived container (`sleep infinity`) and
commands are run through the reviewed control path. Its recovered Home,
Conda tree, project mounts, Claude launcher/configuration, locale, timezone,
and trust bundle are preserved at the original absolute paths. This makes it
possible to test the restored runtime without starting a credentialed Claude
session.

## Versioned artifacts

The source and build inputs in this checkout have the following SHA-256
values. Deployment scripts record image IDs separately; image IDs must match
on both hosts before promotion.

```text
src/controlled_dev_machine/degraded_rootless.py
9d6b89daf9a46ce29d7ddc423ce93406cc32f0052b6d54006ff5deaf71a9906b
src/controlled_dev_machine/degraded_topology.py
45ed7a04be473a978370c874aa6c2530e13fa9bd1fe2977e9b2473898f5d6dac
src/controlled_dev_machine/degraded_egress.py
3ef315a5c928fdf1a2d2ab26d6c05ad2515656e84622a012a580a3722c3000c6
gateway/mitmproxy/cdm_addon.py
1ac0507af5c0e6965e45cd9695b2dfd86b6367ba282d87898ee5cc8d93d909b5
images/gateway/Dockerfile.degraded
e944ccc1f033178516b12ff5a9825e861a51baead4ac3a768ab84c39df054aed
bin/sandboxctl-degraded
7be39ad202efc07587c70340756546e2ac14ce45582dac44605cbf619288a1a0
tests/rootless_e2e.py
de41f3cc68320315e59c22ff053ff448a3d09396972afb46fbac6774d0b450eb
tests/rootless_runtime_smoke.py
d7e30d331e8583ee705c871e93cc34de2aa5e44823569a6ea976ef2f012abb05
```

The verified image references used by the deployment were:

```text
target:  cdm-degraded-target:5090-rootfs
         sha256:d52a88b46be8d7399e354135b787ce2b6d6deaf545c84d6636887c95eb551d31
gateway: cdm-degraded-gateway:5090
         sha256:56c2c9c158f8704713934de8ad814a7b9cf7e196ad50da88b62dbfed90dff5c4
```

## Automated evidence

The final checkout acceptance used the isolated Python 3.11 test runtime:

```text
236 passed, 0 failed, 0 skipped
```

This count includes the rootless topology, relay, addon, policy, runtime, and
daily-work smoke unit tests. The 14-check live internal E2E below is run
separately against Docker on each acceptance host. No test starts a logged-in
Claude session or opens a public network connection.

The structural checker in `tests/verify_degraded_compose.py` validates both
render modes: no-parent mode has no `egress_net`; configured-parent mode has
the relay as the sole external-network service and rejects permissive public
DNS mode. It does not start Compose.

## Credential-free internal E2E

`tests/rootless_e2e.py` uses a synthetic parent, DNS-over-HTTPS endpoint, and
HTTP/HTTPS origin on the private Docker network. It does not use the public
network or any user credential. The 14 checks passed on the acceptance target:

1. HTTP positive proxy request.
2. HTTPS positive proxy request.
3. Direct IP destination rejected.
4. Non-80/443 port rejected.
5. DNS result and lease validation.
6. Parent receives only the fixed destination IP.
7. Original HTTP Host/SNI identity is preserved.
8. Target has no default route.
9. Clearing proxy variables cannot bypass the topology.
10. Raw packet socket/spoofing is unavailable.
11. Direct relay and external DNS sockets are unreachable from target.
12. Policy digest drift fails closed.
13. Relay outage fails closed.
14. Gateway outage fails closed.

The same artifact/image/policy digests were copied to 4090b over the private
link. 4090b has passed offline doctor, Compose configuration, route
isolation, no-parent 502/SERVFAIL checks, gateway-stop fail-closed behavior,
the addon destination matrix, and the live 14-check credential-free E2E after
the final image/source refresh.

## Restored runtime checks

Without making an external request, the target runtime was inspected on the
acceptance host:

```text
Claude Code: 2.1.283
base Python: 3.13.13
pthgnn Python: 3.10.9
HOME: /home/gzy
CLAUDE_CONFIG_DIR: /home/gzy/.claude
LANG/LC_ALL: en_US.UTF-8
TZ: America/Los_Angeles (PDT)
```

The recovered Claude launcher is a real symlink to the preserved
`2.1.283` version tree, and `.claude` is readable and writable inside the
rootless target. These are offline process/file checks only; they are not a
Claude account or upstream API test.

The runtime `miniconda3` mount is a user-owned decoded copy of the verified
Conda restore, separate from `5090-recovery`. Until a complete decoded project
copy is intentionally materialized, `newdfm` and `dfm` are mounted from the
user-owned recovery mirror so the full data set is available without a second
430GB copy; this source is recorded in `mode.json` and can later be replaced
by `5090-runtime/projects/` without changing the container contract.

Final offline environment evidence on both 4090a and 4090b:

```text
base Python: 3.13.13; import urllib.parse: PASS
pthgnn Python: 3.10.9; numpy 1.23.5; torch 2.11.0+cu128: PASS
```

Daily-work acceptance on both hosts also passed with
`tests/rootless_runtime_smoke.py`: hidden-file/symlink/permission/rename and
delete operations, a local Git commit/status cycle, Node/npm execution,
Claude/Codex version and help startup, deterministic Python training, NumPy
and Torch CPU training, and a real CUDA matrix/training step. The target now
uses the recovered `pthgnn` environment in `PATH` and binds the host NVIDIA
device nodes plus driver libraries through the rootless user daemon; no
`--privileged`, `NET_ADMIN`, login, prompt, or external account request was
used.

## Rootless limitations

The following 5090 root-mode guarantees are unavailable for a normal-user
Docker daemon and must not be implied by this report:

- host nftables and transparent redirect;
- cgroup eBPF and root lifecycle/watchdog locks;
- host/namespace tcpdump or packet-level PCAP;
- root-owned network namespace and arbitrary socket interception.

Evidence is therefore limited to the explicit proxy, audited DNS/relay,
application flow records, policy digest checks, and Docker network isolation.
The target's container `0:0` is the rootless daemon user's mapped privilege,
not host root; it is used so the restored Home can be read and written.

## Promotion rules

Keep `CDM_DEGRADED_UPSTREAM_HOST` and `CDM_DEGRADED_UPSTREAM_PORT` unset until
the original 5090 proxy address, DNS route, CA trust, locale/timezone,
policy digest, and exit identity have been compared and recorded. A real
parent also requires an explicit reviewed `CDM_DEGRADED_DNS_SUFFIXES`
allowlist; do not use `--allow-public-domains` with an external parent.
Only after those checks may an operator perform a separately approved,
credentialed Claude test. Until then the offline 14-check fixture is the
highest permitted E2E level.
