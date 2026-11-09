# Exit probe OR policy and namespace route reconciliation

A development sandbox now accepts a fresh probe round when at least one
configured HTTPS observer returns the exact configured exit address. Timeouts,
transport failures and invalid replies from other observers are retained in the
record without vetoing that match. Any explicit different observed address
revokes admission immediately and overrides all matching observers. Successful
leases are published after all observations in the bounded round settle.
All observers failing still denies new connections. Existing same-parent,
same-boot, readiness and lease-age checks remain effective.

The exit monitor journals the complete credential-free probe result, including
per-observer errors and timings, so failures remain diagnosable after the next
lease replaces the control file.

Registered resilience handoffs are reconciled during lifecycle startup and
health checks while holding the lifecycle lock. Replacing a gateway namespace
therefore restores its missing SYN-only route to the registered relay. The
reconciler verifies container ownership, relay image, parent/exit, trusted peer,
internal network and exact nftables expression. Unexpected existing rules are
reported as drift. Original namespace rules and registration are backed up
before repair. Existing relays and conntrack entries are retained.

This is a host-controller update. Apply the source release to every installed
controller and restart its exit monitor; update the scheduled health controller
and future startup selection as well. Target images, application state and the
published proxy subscription do not need rebuilding for these changes. A legacy
controller backport carries identical probe and reconciliation modules for hosts
whose main runtime upgrade remains staged.

Mapper health checks now execute inside the existing owned mapper container.
Repeated temporary container creation could exhaust the host user's session
keyring quota and falsely close network admission despite healthy FUSE mounts.
The check still validates the daemon namespace, mount identity and mapped owner;
its actual failure status is propagated. Controllers use the helper from their
own source release so a controller-only update also updates this health path.
