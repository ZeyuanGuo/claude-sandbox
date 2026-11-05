# 0.3.2 — separate connection admission from established-stream control

The old network controller destroyed every active tunnel as soon as one exit
probe timed out. A partially received response was cut by our own egress control,
even if the tunnel itself was healthy. Restoring the permit could not restore it.

New connections still require a fresh, exact-exit lease; the existing 15-second
lease limit, same-parent requirement and all-probes-must-match rule are unchanged.
A failed probe is never canceled by a successful sibling. No lease is extended or
fabricated, and no alternative parent, exit, direct route or IPv6 path is added.

An already admitted connection now retains its existing route through an intact
probe timeout or lease expiry. It is neither paused nor destroyed by that event.
Its separate established-connection grace defaults to 300 seconds, configurable
from 0 to 900 with `egress_established_grace_seconds`; 0 restores immediate
closure. Repeated unsuccessful rounds cannot extend this grace. Resetting the
clock requires a new matching verification after the failure. Confirmed wrong
exit, changed parent/boot, broken or missing control metadata, readiness failure,
and audit failure still close immediately. Prolonged inability to verify closes
when the established grace expires. Idle time, memory and worker limits remain.

This deliberately changes the old policy for established connections while
keeping new admission strict. Admission leases are not a periodic global kill
switch for healthy active TCP streams. Audit records distinguish retained streams,
verification recovery and grace expiry. No client change or response replay is
part of this fix.

`development-egress-handoff` installs a pinned, source-matched relay image and
changes only new SYN routing in this instance's gateway and DNS namespaces.
Existing target, gateway, DNS, original egress and registered capacity containers
remain running. Existing conntrack entries retain their old relays; new tunnels
use the new generation. It verifies the current configured exit endpoints and
isolation boundaries before switching. Rollback retains any new relay that may
already own sessions. The next approved main restart retires registered temporary
generations and uses this same implementation in the normal versioned topology.
A response that was already broken is not resurrected by this handoff.
