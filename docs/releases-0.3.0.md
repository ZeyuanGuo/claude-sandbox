# 0.3.0 — consistent fleet shells and local persistent state

Restore interactive Bash aliases and completion, support a common container Home
with legacy path aliases, and allow explicit local environment copies on NFS
hosts. Preserve the audited remote SOCKS gateway SSH route used by existing
fleet hosts. A reproducible portable base retains the verified OS and tools while
excluding user data and historical temporary files from image distribution.

All 0.2.x strict-exit, dynamic SSH, persistent Home/history, WebSocket and audit
behavior remains. A running work container is not automatically restarted by a
source release; deferred host activation must be reported explicitly.
