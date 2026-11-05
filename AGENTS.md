# Development and deployment rules

- Long-lived behavior changes belong in version-controlled source, build inputs and reviewed host configuration. Build and deploy them; do not patch running containers, use `docker commit` as a software release, or rely on startup patch scripts. An explicit user request may authorize a narrowly documented live repair.
- Preserve existing application state, transcripts, working files and credentials. Never overwrite one host's application state with another host's directory. Common functional configuration has a separate versioned source.
- Never mount the whole host Home or the Docker control socket into a target. Use a separate persistent sandbox Home and an explicit project/environment allowlist. Do not recursively chown project data to fix UID mapping.
- Exit identity is a mandatory exact configuration value. New admission with missing, failed, wrong, stale or inconsistent verification must fail closed; established tunnels follow their separately bounded uncertainty grace below. Never fall back to another parent, another node or direct Internet. A failed probe cannot be canceled by a successful sibling probe.
- Real Claude requests may only originate inside the configured target after its required exit and enforcement have been verified. Host-side diagnostic tools must not call Claude APIs.
- Manual startup, service startup and recovery must load the same release and host configuration. Admission failures are no-ops for existing running instances. Lifecycle mutations are serialized.
- Back up before changing deployment or state. Preserve other users' services and jobs. Do not change GPU drivers, reset GPUs or restart the host Docker daemon to repair one sandbox.
- Use an isolated checkout for integration. Never force-push shared history. Keep local commits and remote publication evidence distinct.
- Public examples contain placeholders/documentation addresses, not personal IPs, Home paths, account state or tokens. Keep private host profiles outside Git.
- Native SSH profiles delegate destination routing/authentication to host OpenSSH through one configured host bootstrap alias. Do not add per-ProxyCommand helper exceptions or reimplement destination SSH configuration. This is an audited host-user SSH capability, independent of the strict HTTP egress boundary.
- Claude's own automatic cleanup behavior is outside the current change; do not modify it without a new user request.

- New connections require a fresh exact-exit lease. An admitted connection may retain its fixed route for the configured bounded established-connection grace through an intact probe timeout or expiry. Confirmed wrong exits, parent/boot changes, malformed/missing control metadata, readiness failure and audit failure still close immediately. Never extend or fabricate a lease to keep existing streams alive.
