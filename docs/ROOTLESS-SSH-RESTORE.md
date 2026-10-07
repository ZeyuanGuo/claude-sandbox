# Rootless SSH Restoration

Goal: restore container SSH to known campus/Tailscale hosts on 4090a/b without
changing the Los Angeles HTTP(S)/DNS path or campus host networking.

## Plan And Status

- Reproduced: both 4090 hosts lack a route to campus 10/100 SSH endpoints;
  mainstorage already has working campus and Tailscale routes.
- Implemented: a dedicated, audited Unix-socket broker with
  exact address/port allowlists. User services maintain reverse Unix forwards
  from mainstorage to each 4090 host. No generic SOCKS or public TCP listener.
- Campus aliases default to their existing 100.64.0.0/10 addresses; lan aliases
  keep their existing 10/8 addresses. The 4090 pair keeps its private LAN path.
- mainstorage user services `cdm-ssh-relay-4090a.service` and
  `cdm-ssh-relay-4090b.service` maintain the reverse sockets and reconnect
  after link or host restart.
- 4090a/b have been deployed and tested with the same SSH configuration. SSH to
  `mainstorage`, `nas`, `4090`, and `a800` works on both; matching `lan-*` 10.*
  aliases work as well. 3090 remains unavailable because its remote SSH service
  currently times out, not because the broker rejects it. HTTP(S), DNS, LA exit
  and GPU remain independently functional.

The socket root is `/tmp/cdm-ssh-bridge` on 4090a/b. This avoids a rootless
Docker bind-mount namespace quirk that can hide Unix sockets below the Docker
state directory; the systemd services recreate the sockets after reboot.

## Security Boundary

Only configured IP/port pairs may be connected. No hostname resolution,
public destination, or fallback route is accepted by the SSH broker. The
target mounts only the dedicated socket directory read-only; no Docker socket,
gateway control socket, or host network is exposed. HTTP_PROXY/HTTPS_PROXY,
controlled DNS, default routes and the parent proxy are unchanged.

The remote SSH server verifies authentication and host keys end to end. The
broker logs connection metadata, not credentials or decrypted commands.
SSH grants access to trusted remote shells: a user can run networking commands
on those hosts or request SSH forwarding where the remote server permits it.
This is not a claim of cross-host prevention of all Internet access.

## Acceptance Evidence

- Both hosts: container `ssh mainstorage` and `ssh nas` exit 0.
- Both hosts: SCP can upload a canary through the fixed socket and remove it.
- Both hosts: `ssh -p 23 mainstorage` and `ssh 1.1.1.1` fail closed.
- Both hosts: HTTPS identity is `204.1.123.50`; target route remains the
  internal `172.31.0.0/24` route only.
- Strict-local canary on 4090a: SSH, HTTPS identity, direct-IP failure, and
  Python/Torch/CUDA smoke all passed together.
- Full repository pytest: all tests passed after the SSH additions.

Container loopback remains available for local development and distributed
training. It is not transparently redirected by this SSH feature. The optional
network-none mode can also use the Unix broker without restoring a network
interface.
