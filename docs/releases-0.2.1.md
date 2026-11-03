# 0.2.1 — add SSH hosts and keys without container recreation

Adding a host previously required a new individual key/known-host bind mount and
regenerated client configuration. The development sandbox now mounts one private
SSH client directory and refreshes it from the host configuration automatically.
New aliases, key files and trusted host records appear without restarting the
target. Host control sockets remain excluded; strict host-key verification and
the existing audited LAN/VPN/jump routes remain in place.

All persistent Home, history preservation, native update, configured exact-exit,
DNS/WebSocket and audit changes from 0.2.0 remain included.
