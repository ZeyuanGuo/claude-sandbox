# Versioned development sandbox

This release supports the rootful controller and a versioned rootless development
controller. The latter replaces host-Home sharing with a separate persistent Home
and an explicit project/environment allowlist. Existing account state is required;
initialization does not import or overwrite another Claude account.

## Configuration and release boundary

`examples/development.example.json` is a template, not a usable deployment. Replace
its documentation addresses, paths, IDs and image references with reviewed local
values. `exit.expected_exit` is one exact canonical IPv4 address. It is not a
provider constant, address range or fallback list. Every configured probe must
succeed through the same configured parent and return that address. A completed
failure revokes access before waiting for other probes; a sibling success never
cancels the failure. Missing or stale leases and IPv6 destinations are denied.

Keep the real host configuration and identity profile outside Git, owned by the
host operator and inaccessible from the target. Rootful and rootless deployments
have different audit capabilities; status reports this rather than calling them
identical. The rootless target has only an internal network. DNS and gateway reach
the external parent through the lease-gated egress service. It has no Docker
socket and does not mount the whole host Home.

The installed code is a Git archive in `releases/<commit>`. Manual entry, systemd
startup and recovery use the same interpreter, release and configuration.
`bin/development-sandbox --config <host.json> status` reports the desired and actual
release, image ID, persistent Home source and current exit verification.

## Data layout

Within `private_root`:

- `apps/home`: persistent sandbox Home, including newly created directories.
- `apps/.claude` and `apps/.claude.json`: the existing private account and history.
- `apps/claude-work`: persistent Claude temporary work outputs. The controller
  configures `CLAUDE_CODE_TMPDIR`; a reviewed old temporary path may also be bound
  for history compatibility. Do not restore another process's sockets/PIDs.
- `control`: generated Compose, system identity, verification and audit state.
- `archive`: private recovery checkpoints. These can contain credentials; never
  publish them or use them as a cross-host configuration synchronization package.

Projects and environment directories are bound individually at their original
container paths. A new mount must not hide nonempty private Home data. On NFS
hosts, choose genuinely local storage for hot application state and environments;
retain deliberate NFS sharing for projects. Never use bidirectional file copying
as a substitute for release management or concurrent database coordination.

Claude's own automatic cleanup setting is unchanged by this release.

## Adding SSH hosts without restarting the sandbox

Native SSH profiles set `ssh_host_alias` to this host's existing reachable SSH
alias. The target uses one bootstrap connection back to the host, then the host's
native OpenSSH handles the destination using its current configuration. Scripts,
ProxyCommand, multi-hop ProxyJump, Match, wildcard aliases and Includes are not a
sandbox-specific route language. Add or change normal host SSH configuration and
keys; the next destination connection reads them, with no per-helper exception,
image build or container restart. Bootstrap client material remains a same-host
read-only snapshot; control sockets are not copied and private state is never a
fleet synchronization artifact.

This is an audited host-user SSH capability. Destination-side identity paths,
local forwarding listeners, ControlMaster sockets and local hooks use the host
context. OpenSSH handles binary stdio, terminal modes and window resizing across
the bootstrap connection. The host launcher records a session ID, destination
when identifiable, argument count and digest, not credentials or command bodies.
Native SSH diagnostics reach the caller. The legacy bridge remains available to
older profiles, while native profiles render only their bootstrap alias.

The same-host snapshot refresh also regenerates the bootstrap configuration from
OpenSSH so edits to included configuration are observed. The separate HTTP/DNS
proxy and exact-exit verification remain unchanged. SSH must not be used to run
Claude tests outside an approved target or bypass the required model exit.

## Native Claude and updates

The image-owned `/opt/sbc/bin/claude` validates the sandbox marker and executes the
native installation under the persistent Home. It forwards all arguments,
including update commands. Vendor-managed links and native versions are separate
from the host launcher. `prepare-development-home` verifies the real ELF binary's
hash and never writes through an existing vendor symlink. Legitimate absolute
links created by native updates are resolved against the persistent Home during
host admission checks.

The optional `interactive_exit_probe_url` preserves an operator's quick exit
check when entering an interactive shell. It uses the controlled gateway and a
short timeout. It does not inject asynchronous output into non-interactive tool
results.

## Build and migrate

1. Preserve the old repository, code, Compose definition, images and application
   state. Record any unreadable historical files; do not delete originals.
2. Build the gateway from `images/gateway/Dockerfile.degraded` using the recorded
   gateway base image. Build the target from `images/target/Dockerfile.development`
   using an explicit, preserved base image and `SOURCE_COMMIT`. Offline builds may
   use `--network=none --pull=false`. No running-container patch is a build input.
3. Populate a private host configuration, native program input and exact data
   allowlist. Run `bin/prepare-development-home` with a reviewed binary/version/hash.
4. Quiesce this target before its final state checkpoint and preserve ordinary
   temporary work files. Do not stop unrelated containers, host Docker or jobs.
5. Run `prepare`, inspect the generated mounts, then `start`. Configure the same
   release for systemd and `install-entries`. Explicit retired units may only name
   this project's old services. Preserve the host SSH agent and network services.
6. Verify strict egress, actual identity, environments, SSH and persistence before
   making any real Claude request. Real requests must originate inside the target.
7. Recreate the target from the same release and verify file/history hashes again.
   Publish the tested Git commit and release tag; keep a rollback receipt.

`checkpoint` archives private application files and skips special runtime objects.
A checkpoint taken while the target is running is marked non-quiescent; it is not
claimed to be an application-consistent rollback image. No cleanup policy is run.

## Rollback

Keep the old images and generated configuration. If validation fails, fail closed
and restore only this instance's previous code/configuration. Application state is
not automatically rolled back over newer files. Preserve new work and reconcile
it explicitly. Never restore a global firewall snapshot or a different/unverified
exit to make recovery appear successful.

## Fleet profiles and interactive shells

Interactive Bash keeps common listing/color/Conda aliases, history append, window
size updates and available shell completion. A private `.bash_aliases`, `.inputrc`
or `.dircolors` can extend this without importing host-specific proxy/admin shell
startup code. Existing history files are preserved.

A common container user, UID and Home can coexist with legacy project paths.
`home_aliases` duplicates the reviewed Home/application/data mounts at the old
Home path; it does not expose the host Home wholesale. This preserves old Python
interpreter paths and Claude project working directories while keeping the
configured container identity stable.

On NFS hosts, copy hot environments to the private local `data/<relative-path>`
first and set that exact path as the mount's `source`. The controller uses a
separate UID view for local data. Keep deliberate shared project/data mounts on
NFS. The private root, controller, active application state and Docker data root
must be genuinely local, even where user Homes and startup files are shared.

`images/target/Dockerfile.portable-base` creates a smaller image from an explicitly
recorded existing image, retaining its OS/toolchain and package database while
excluding Home data, historical temporary files and generated private host keys.
It never commits a live container. Back up actual temporary work before any
cutover, and keep the original image as a recovery input.

The audited SSH bridge also supports the established remote SOCKS gateway route
through an owned `~/.ssh/a100-gateway.conf`, using argument vectors and strict
host-key checking. Unconfigured request-supplied routes remain rejected.

External data such as `/data` or `/local/<user>` can remain at its original path
using explicit `external_mounts`. Each gets a separate UID view. Home and control
roots are rejected. An accessible root-owned shared directory uses an explicit
shared-root mapper check; the underlying host-user permissions still apply, and
foreign files are not recursively chowned. The target receives neither a host
root filesystem nor Docker control access.

For a new rootless host, install the distribution's `uidmap` package and use the
account's existing subordinate UID/GID range. Keep Docker data on a local disk,
enable the existing per-user Docker service and linger, and verify the selected
Docker context before deployment. With a shared NFS Home, identical user entry
files must refer to identical *host-local* path names, and all candidate hosts
must be ready before selecting that shared entry. Preserve existing rootful
workloads; only retire the reviewed old sandbox instance after backups.

Both the current UID's `/tmp/claude-<uid>` and an optional legacy temporary path
point at persistent work storage. This also preserves output when a native
component uses its conventional temporary path. Startup failures retry the same
release/configuration after ten seconds, remaining fail-closed while the parent
is unavailable; successful running work is not restarted by this startup retry.

`ssh_extra_roots` can declare host-local SSH configuration/key directories used
by shared-Home hosts. They must be operator/root-owned, not writable by others,
and outside writable target data. Includes and identity/known-host paths from
those roots are rendered into the same read-only client snapshot; key rotation
and newly added files still need no target remount. Keys remain local to each host.

Web egress and DNS egress have independent worker pools (defaults 256 and 16).
Each trusts only its configured role; DNS still reaches only the fixed DoH
endpoint, and both require the same fresh exact-exit lease. Web connection pools
cannot exhaust DNS's reserved workers. `web_sessions` and `dns_sessions` are
bounded configuration values. A registered live capacity hotfix blocks lifecycle
admission until it is retired during an explicitly approved cutover; do not stop
its forwarders while translated sessions are still active.

## Staging the next restart without interrupting current work

`bin/development-next-start stage --current-config OLD --candidate-config NEW`
requires an installed immutable release and locally available digest-pinned
images. It writes a private `configs/next-start.json`, a host-local runtime-profile
selector and a future main-service ExecStart drop-in, then reloads unit metadata.
It never runs prepare/start, rewrites generated runtime files, stops a service,
or selects new user entries during staging. The existing sandbox keeps running.

Stage every host sharing an NFS Home before installing the shared startup drop-in.
All those hosts must have the same release/interpreter paths on genuinely local
storage. At the next main-service start/restart or host boot, the prepared plan
activates. It checks profile/source hashes, retains the exact parent/exit, handles
only registered owned capacity-hotfix components during that restart window,
starts the candidate, checks exit readiness and selects normal entries. It does
not pull floating Git branches or download an image at boot. Edited profiles must
be restaged rather than silently overwritten.

After activation, `sbc restart` restarts the main service through this selector.
A plain Docker container restart does not rebuild Compose or select a release;
use the main service restart for the prepared upgrade. `sbc start`/shell/status
continue to use the selected runtime profile. Staging itself is not authorization
to interrupt work now; activation runs only on the subsequent explicit main start.

Shared unit and entry files refer to `configs/runtime.json`, which is local to
each host. The controller's immutable source version can be common while one host
still runs the previous profile until its approved restart. Shared SSH units read
host-specific bootstrap aliases from that local profile, not from a value embedded
by whichever NFS host last wrote the unit. `sbc status` reports actual runtime
release; a selector entry's `release_id=host-local-runtime` is not a fixed revision.
