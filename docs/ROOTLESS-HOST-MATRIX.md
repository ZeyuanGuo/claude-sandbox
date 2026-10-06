# Rootless Host Matrix

This matrix separates hosts with direct deployment evidence from hosts that
are only reachable over SSH. It prevents a 4090 result from being presented as
an acceptance result for another machine.

| Host | Rootless Docker | Degraded stack | Daily/CUDA smoke | Status |
| --- | --- | --- | --- | --- |
| `4090a` | yes | four services running, gateway healthy | passed; CUDA available, Torch training passed | accepted |
| `4090b` | yes | four services running, gateway healthy | passed; CUDA available, Torch training passed | accepted |
| `mainstorage` | no; default Docker is rootful | not deployed | no rootless deployment claim | out of scope |
| `a800` | yes; A800 GPUs visible | recovery tree/images absent on host | not run | pending deployment |

The accepted 4090 evidence is credential-free: file operations, hidden files,
symlinks, permissions, rename/delete, local Git commit/status, Python training,
NumPy/Torch, a real CUDA training step, Claude/Codex `--version` and `--help`,
locale/timezone, project and `.claude` writes, network isolation, and the
14-check internal HTTP/HTTPS/DNS fail-closed E2E. No login, prompt, account, or
unreviewed public upstream was used.

`mainstorage` and `a800` must not be called accepted until a rootless runtime,
the verified images, and the same smoke suite are actually deployed there.
