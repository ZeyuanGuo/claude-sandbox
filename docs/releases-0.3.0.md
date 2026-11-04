# 0.3.0 — consistent fleet shells and local persistent state

Restore interactive Bash aliases and completion, support a common container Home
with legacy path aliases, and allow explicit local environment copies on NFS
hosts. Preserve the audited remote SOCKS gateway SSH route used by existing
fleet hosts. A reproducible portable base retains the verified OS and tools while
excluding user data and historical temporary files from image distribution.

All 0.2.x strict-exit, dynamic SSH, persistent Home/history, WebSocket and audit
behavior remains. A running work container is not automatically restarted by a
source release; deferred host activation must be reported explicitly.

Web and DNS use separate bounded egress pools, preventing ordinary connection
load from exhausting DNS capacity. Both still require the same exact configured
exit and fresh lease. An active documented connection-preserving hotfix prevents
automatic lifecycle admission until its operator-approved retirement.

Hosts that already share an OAuth refresh session can set
`claude_credentials_path` to a child of an explicitly writable shared mount.
Only the small credential directory and native refresh/write locks are shared;
transcripts, temporary work and other application state stay local. This uses
`CLAUDE_SECURESTORAGE_CONFIG_DIR`, verified in the pinned Claude 2.1.308 binary;
recheck support before changing the native version. Do not clone an independently
rotating refresh credential into several local stores, or mount just the JSON
file: native writes use atomic replacement and require shared sibling locks.
Independent hosts keep independent authentication; this option is opt-in.
