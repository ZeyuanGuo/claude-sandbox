# 0.3.1 — native host SSH configuration

Set `ssh_host_alias` to the existing, directly reachable SSH alias for this host.
The target's `ssh` entry uses its preserved native OpenSSH only to reach that
bootstrap alias. It then runs the versioned audited launcher on the host, which
executes the host's `/usr/bin/ssh` with the original arguments.

Destination routing and authentication belong to native host OpenSSH. Host
configuration can use ProxyCommand scripts, multi-hop ProxyJump, Match, wildcard
aliases and ordinary includes; no per-helper allowlist or route rewriting is
needed for destination connections. Changes are read by native SSH on the next
connection. The legacy parser remains only for older profiles and the bootstrap
transport; native profiles render only their one bootstrap alias. Includes for
that alias are resolved by OpenSSH, including changes outside the snapshot tree.

The outer connection preserves argument boundaries, propagates exit status, and
lets OpenSSH implement interactive terminals, resizing and binary stdio. Outer
forwarding and local commands are disabled; the destination client retains its
normal configuration. The host is the context for destination-side SSH options:
local forwards, ControlMaster sockets, identity paths and local hooks refer to
the host. SCP/SFTP and rsync use the same SSH entry through binary stdio. `ssh -V`
reports the preserved target OpenSSH version.

SSH is an audited host-user capability, including that user's configured local
proxy helpers. The existing ability to SSH back to this host already grants that
host-user context; this entry does not pretend to sandbox an untrusted SSH
configuration language. It exposes no Docker socket and changes neither HTTP
egress nor exact-exit verification. Never use it to run Claude tests outside an
approved target or to bypass the configured exit.

The host launcher audits a session ID, destination when identifiable, argument
count and argument digest, without logging commands, passwords or SSH payload.
Audit failure prevents launch. Native SSH errors and exit codes return to the
caller. Bootstrap route rejection now returns a clear structured error instead
of closing the socket and producing a misleading `Incomplete request` traceback.

Publishing or syncing this source does not activate it in a running sandbox.
The deployment must stage the new image, immutable release and per-host profile
for the next approved restart. Keep current jobs and bridges running until then.

The next-start staging command prepares source/image/profile selection without
restarting current services. Shared-Home startup units resolve host-local runtime
profiles so staggered restarts do not select another host's release or SSH alias.
A staged capacity hotfix is retired only inside that later main restart window;
the current running forwarders and established sessions are left intact by stage.
