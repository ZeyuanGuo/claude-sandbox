# 0.2.0 — reproducible development sandbox and persistent Home

The previous deployments mixed Git changes, image-only patches and multiple
startup controllers. This release brings the reviewed DNS, WebSocket, rootful
profile/audit and rootless restoration work into one source history.

- Separate persistent sandbox Home and explicit project/environment mounts.
- Preserve account/history data and temporary Claude work outputs across rebuilds.
- One configured release for manual entry, systemd startup and recovery.
- Provider-independent exact-exit configuration, strict probe aggregation,
  immediate failure publication and production IPv4-only lease enforcement.
- Native Claude launcher separated from the vendor binary and update paths.
- Configured interactive exit display without contaminating non-interactive output.
- Audited WebSocket support built into the gateway; no startup patch injection.
- Append-mode hourly flow logs and compatible rootful audit-retention fields.
- Private state checkpoints, symlink-safe entry installation and protection against
  mounting over existing unregistered private Home work.
- Source-first deployment rules and explicit rootless audit limitations.

Host profiles, tokens, private keys, transcripts, checkpoints and research data
are not release contents. See `docs/versioned-development.md` and the example
host profile. Deployment on one host does not imply deployment on the fleet.
