#!/usr/bin/env python3
"""Credential-free daily-work acceptance for a running degraded target.

Complements ``rootless_e2e.py`` by checking ordinary file work, Python
training, the recovered ML environment, and offline CLI startup inside the
actual target container.  No login, prompt, or user request is made.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
from typing import Any


def _target_script(*, require_ml: bool, require_gpu: bool) -> str:
    """Return a POSIX shell probe executed inside the target."""
    ml_mode = "required" if require_ml else "optional"
    gpu_mode = "required" if require_gpu else "optional"
    return f'''set -eu
tmp="$HOME/.cdm-rootless-smoke-$$"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/nested/.hidden"
printf 'rootless-smoke\\n' > "$tmp/nested/.hidden/value"
ln -s nested/.hidden/value "$tmp/value-link"
test "$(cat "$tmp/value-link")" = 'rootless-smoke'
chmod 600 "$tmp/nested/.hidden/value"
test "$(stat -c %a "$tmp/nested/.hidden/value")" = 600
mv "$tmp/nested/.hidden/value" "$tmp/nested/.hidden/value.renamed"
test -f "$tmp/nested/.hidden/value.renamed"
command -v python >/dev/null
python --version >/dev/null
python - "$tmp" <<'PY'
import hashlib
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
payload = b"rootless-python-file-operation"
target = root / "python.bin"
target.write_bytes(payload)
assert target.read_bytes() == payload
assert hashlib.sha256(target.read_bytes()).hexdigest()
PY
python - <<'PY'
# Deterministic, dependency-free training smoke: y = 2x + 1.
weights, bias = 0.0, 0.0
for _ in range(400):
    grad_w = grad_b = 0.0
    for x, y in ((0.0, 1.0), (1.0, 3.0), (2.0, 5.0)):
        error = weights * x + bias - y
        grad_w += error * x
        grad_b += error
    weights -= 0.05 * grad_w / 3
    bias -= 0.05 * grad_b / 3
assert abs(weights - 2.0) < 0.01 and abs(bias - 1.0) < 0.01
print("python-training=pass")
PY
test "${{HOME}}" = /home/gzy
test "${{CLAUDE_CONFIG_DIR}}" = /home/gzy/.claude
test -n "${{LANG}}" && test -n "${{LC_ALL}}" && test -n "${{TZ}}"
git --version >/dev/null
git_tmp="$tmp/git-project"
mkdir -p "$git_tmp"
git -C "$git_tmp" init -q
printf 'tracked\n' > "$git_tmp/README.md"
git -C "$git_tmp" add README.md
git -C "$git_tmp" -c user.name=rootless-smoke -c user.email=rootless-smoke@example.invalid commit -qm initial
test "$(git -C "$git_tmp" status --porcelain)" = ""
node --version >/dev/null
npm --version >/dev/null
node -e 'if (1 + 1 !== 2) process.exit(1)'
command -v claude >/dev/null
command -v codex >/dev/null
claude --version >/dev/null
claude --help >/dev/null
codex --version >/dev/null
codex --help >/dev/null
test -d /home/gzy/.claude
test -r /home/gzy/.claude
test -d /home/gzy/newdfm || test -d /home/gzy/dfm
route=$(awk 'NR > 1 && $2 == "00000000" {{ print; exit }}' /proc/net/route)
test -z "$route"
if [ -x /home/gzy/miniconda3/envs/pthgnn/bin/python ]; then
  /home/gzy/miniconda3/envs/pthgnn/bin/python - <<'PY'
import numpy
import torch
x = torch.tensor([[1.0, 2.0], [3.0, 4.0]])
y = x @ x.T
assert tuple(y.shape) == (2, 2)
model = torch.nn.Linear(1, 1)
optimizer = torch.optim.SGD(model.parameters(), lr=0.1)
features = torch.tensor([[0.0], [1.0], [2.0]])
target = torch.tensor([[1.0], [3.0], [5.0]])
for _ in range(100):
    optimizer.zero_grad()
    loss = torch.nn.functional.mse_loss(model(features), target)
    loss.backward()
    optimizer.step()
assert float(torch.abs(model(torch.tensor([[3.0]])) - 7.0)) < 0.2
print("numpy=%s torch=%s cuda=%s" % (numpy.__version__, torch.__version__, torch.cuda.is_available()))
PY
  cuda=$(/home/gzy/miniconda3/envs/pthgnn/bin/python -c 'import torch; print(str(torch.cuda.is_available()).lower())')
  if [ "{gpu_mode}" = required ] && [ "$cuda" != true ]; then
    echo 'required CUDA is unavailable' >&2
    exit 42
  fi
else
  if [ "{ml_mode}" = required ]; then
    echo 'required pthgnn Python is unavailable' >&2
    exit 43
  fi
  echo 'ml=unavailable (optional)'
fi
'''


def _run_target(compose_file: Path, script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "exec", "-T", "target", "sh", "-lc", script],
        check=False,
        capture_output=True,
        text=True,
    )


def run_probe(compose_file: Path, *, require_ml: bool = False,
              require_gpu: bool = False) -> dict[str, Any]:
    """Run the target probe and return a safe machine-readable report."""
    result = _run_target(compose_file, _target_script(require_ml=require_ml, require_gpu=require_gpu))
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    safe_lines = [line for line in lines if line.startswith(("python-training=", "numpy=", "ml="))]
    return {
        "compose_file": str(compose_file),
        "target": "target",
        "passed": result.returncode == 0,
        "returncode": result.returncode,
        "markers": safe_lines,
        "stderr_present": bool(result.stderr.strip()),
        "requirements": {"ml": require_ml, "gpu": require_gpu},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-file", type=Path, required=True)
    parser.add_argument("--require-ml", action="store_true",
                        help="fail unless recovered pthgnn NumPy/Torch passes")
    parser.add_argument("--require-gpu", action="store_true",
                        help="fail unless pthgnn Torch reports CUDA")
    args = parser.parse_args(argv)
    if not args.compose_file.is_file():
        parser.error(f"compose file does not exist: {args.compose_file}")
    report = run_probe(args.compose_file, require_ml=args.require_ml, require_gpu=args.require_gpu)
    print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
