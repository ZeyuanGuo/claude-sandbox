"""Map host-owned bind data to real gzy identity in Docker's mount namespace."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid


UID = GID = 1010
NAME = "cdm-degraded-uid-view"


def _atomic(path: Path, value: str) -> None:
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    temporary.chmod(0o600)
    temporary.replace(path)


def _namespace(name: str, pid: int | str = "self") -> str:
    return os.readlink(f"/proc/{pid}/ns/{name}")


def verify_namespace(daemon_pid: int) -> None:
    if os.getuid() != 0 or Path(f"/proc/{daemon_pid}/comm").read_text().strip() != "dockerd":
        raise RuntimeError("mapper must run as namespace root beside the rootless dockerd")
    for name in ("mnt", "user"):
        if _namespace(name) != _namespace(name, daemon_pid):
            raise RuntimeError(f"wrong Docker {name} namespace")
    rows = Path("/proc/self/uid_map").read_text().splitlines()
    first = [int(part) for part in rows[0].split()]
    if first[0] != 0 or first[1] == 0 or first[2] != 1:
        raise RuntimeError("this mapper only accepts a rootless Docker UID map")


def _unescape(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def mount_record(view: Path, text: str | None = None) -> dict[str, str] | None:
    if text is None:
        text = Path("/proc/self/mountinfo").read_text()
    for line in text.splitlines():
        fields = line.split()
        separator = fields.index("-")
        if _unescape(fields[4]) == str(view):
            return {"fstype": fields[separator + 1],
                    "source": _unescape(fields[separator + 2])}
    return None


def _paths(source: Path, view: Path, state: Path) -> None:
    for path in (source, view, state):
        if not path.is_absolute() or any(char in str(path) for char in ("\n", "\0", ",")):
            raise RuntimeError("absolute, unambiguous paths are required")
    if not source.is_dir() or source.is_symlink() or source == view:
        raise RuntimeError("source must be a real directory distinct from the view")
    if not view.is_relative_to(state) or view == source:
        raise RuntimeError("view must be inside separate control state, outside source")
    metadata = source.stat()
    if (metadata.st_uid, metadata.st_gid) != (0, 0):
        raise RuntimeError("source is not owned by the rootless Docker host user")


def _probe_mapping(source: Path, view: Path, state: Path, token: str) -> None:
    mounted = mount_record(view)
    if mounted != {"fstype": "fuse.cdm_uid_view", "source": str(source)}:
        raise RuntimeError("UID view is not the expected active FUSE mount")
    original, translated = source.stat(), view.stat()
    if ((original.st_uid, original.st_gid) != (0, 0)
            or (translated.st_uid, translated.st_gid) != (UID, GID)
            or stat.S_IMODE(original.st_mode) != stat.S_IMODE(translated.st_mode)):
        raise RuntimeError("source root does not prove the live translated UID/GID view")


def _ssh_record(source: Path, shadow: Path, expected: dict | None = None) -> dict:
    source_info, shadow_info = source.lstat(), shadow.lstat()
    if (not stat.S_ISDIR(source_info.st_mode) or source_info.st_uid != 0
            or source_info.st_mode & 0o022 or not stat.S_ISDIR(shadow_info.st_mode)
            or (shadow_info.st_uid, shadow_info.st_gid, stat.S_IMODE(shadow_info.st_mode)) != (UID, GID, 0o700)):
        raise RuntimeError("SSH shadow/source ownership or permissions drift")
    sockets = {}
    for path in sorted(source.iterdir()):
        if not path.name.endswith(".sock"):
            continue
        original, translated = path.lstat(), (shadow / path.name).lstat()
        if (not stat.S_ISSOCK(original.st_mode) or original.st_uid != 0 or original.st_mode & 0o022
                or not stat.S_ISSOCK(translated.st_mode)
                or (translated.st_uid, translated.st_gid) != (UID, GID)
                or stat.S_IMODE(original.st_mode) != stat.S_IMODE(translated.st_mode)):
            raise RuntimeError("SSH fixed socket ownership or permissions drift")
        sockets[path.name] = {"source_identity": [original.st_dev, original.st_ino],
                              "shadow_identity": [translated.st_dev, translated.st_ino],
                              "mode": stat.S_IMODE(original.st_mode)}
    if not sockets:
        raise RuntimeError("SSH shadow has no frozen sockets")
    files = {}
    for name in ("ssh_config", "known_hosts", "id_ed25519_fleet"):
        original, translated = (source / name).lstat(), (shadow / name).lstat()
        if (not stat.S_ISREG(original.st_mode) or original.st_uid != 0 or original.st_mode & 0o022
                or not stat.S_ISREG(translated.st_mode)
                or (translated.st_uid, translated.st_gid) != (UID, GID)
                or stat.S_IMODE(original.st_mode) != stat.S_IMODE(translated.st_mode)
                or (source / name).read_bytes() != (shadow / name).read_bytes()):
            raise RuntimeError("SSH shadow configuration drift")
        files[name] = {"source_identity": [original.st_dev, original.st_ino],
                        "shadow_identity": [translated.st_dev, translated.st_ino],
                        "size": original.st_size, "mtime_ns": original.st_mtime_ns,
                        "mode": stat.S_IMODE(original.st_mode)}
    record = {"source": str(source), "shadow": str(shadow), "sockets": sockets, "files": files,
              "source_identity": [source_info.st_dev, source_info.st_ino],
              "shadow_identity": [shadow_info.st_dev, shadow_info.st_ino]}
    if expected is not None and record != expected:
        raise RuntimeError("SSH frozen socket or configuration identity drift")
    return record


def ready_record(source: Path, view: Path, state: Path, daemon_pid: int,
                 ssh_source: Path | None = None, ssh_shadow: Path | None = None) -> dict:
    verify_namespace(daemon_pid)
    _paths(source, view, state)
    ready = json.loads((state / "ready.json").read_text())
    if (not isinstance(ready, dict) or not isinstance(ready.get("token"), str)
            or re.fullmatch(r"[a-f0-9]{32}", ready["token"]) is None
            or not isinstance(ready.get("mapper_pid"), int) or ready["mapper_pid"] <= 0):
        raise RuntimeError("malformed UID view readiness record")
    expected = {"source": str(source), "view": str(view), "uid": UID, "gid": GID,
                "daemon_pid": daemon_pid, "mount_namespace": _namespace("mnt"),
                "user_namespace": _namespace("user")}
    if any(ready.get(key) != value for key, value in expected.items()):
        raise RuntimeError("UID view readiness configuration or namespace drift")
    _probe_mapping(source, view, state, ready["token"])
    if bool(ssh_source) != bool(ssh_shadow) or bool(ready.get("ssh")) != bool(ssh_source):
        raise RuntimeError("SSH shadow readiness configuration drift")
    if ssh_source and ssh_shadow:
        _ssh_record(ssh_source, ssh_shadow, ready["ssh"])
    os.kill(int(ready["mapper_pid"]), 0)
    return ready


def _unmount(source: Path, view: Path) -> None:
    mounted = mount_record(view)
    if mounted is None:
        return
    if mounted != {"fstype": "fuse.cdm_uid_view", "source": str(source)}:
        raise RuntimeError("refusing to unmount an unrelated filesystem")
    subprocess.run(["umount", "--", str(view)], check=True)


def mapper(source: Path, view: Path, state: Path, tools: Path, daemon_pid: int,
           ssh_source: Path | None = None, ssh_shadow: Path | None = None) -> int:
    verify_namespace(daemon_pid)
    _paths(source, view, state)
    if bool(ssh_source) != bool(ssh_shadow):
        raise RuntimeError("SSH source and shadow must be configured together")
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (state / "mapper.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another UID mapper holds the control lock") from exc
        ready = state / "ready.json"
        ready.unlink(missing_ok=True)
        _unmount(source, view)
        view.mkdir(mode=0o700, parents=True, exist_ok=True)
        executable = tools / "usr/bin/bindfs"
        metadata = executable.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise RuntimeError("bindfs must be owned by the host user and not writable by others")
        token = uuid.uuid4().hex
        environment = os.environ.copy()
        environment["LD_LIBRARY_PATH"] = str(tools / "lib/x86_64-linux-gnu")
        command = [str(executable), "-f", "-o",
                   "allow_other,default_permissions,subtype=cdm_uid_view",
                   f"--map=0/{UID}:@0/@{GID}", "--create-for-user=0", "--create-for-group=0",
                   str(source), str(view)]
        child = subprocess.Popen(command, env=environment)
        stopping = False
        bridge = worker = None
        bridge_stop = threading.Event()
        bridge_errors = []

        def stop(_number, _frame):
            nonlocal stopping
            stopping = True

        previous = {number: signal.signal(number, stop) for number in (signal.SIGTERM, signal.SIGINT)}
        try:
            deadline = time.monotonic() + 20
            while mount_record(view) is None:
                if stopping or child.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("FUSE mapper failed before readiness")
                time.sleep(0.1)
            record = {"source": str(source), "view": str(view), "uid": UID, "gid": GID,
                      "daemon_pid": daemon_pid, "mapper_pid": os.getpid(), "token": token,
                      "mount_namespace": _namespace("mnt"), "user_namespace": _namespace("user")}
            if ssh_source and ssh_shadow:
                from controlled_dev_machine.rootless_uid_ssh import SSHShadow
                bridge = SSHShadow(ssh_source, ssh_shadow, uid=UID, gid=GID)
                bridge.prepare()
                record["ssh"] = _ssh_record(ssh_source, ssh_shadow)

                def serve():
                    try:
                        bridge.serve(bridge_stop)
                    except BaseException as exc:
                        bridge_errors.append(exc)

                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
            _probe_mapping(source, view, state, token)
            _atomic(ready, json.dumps(record) + "\n")
            ready_record(source, view, state, daemon_pid, ssh_source, ssh_shadow)
            print(json.dumps(record), flush=True)
            while not stopping and child.poll() is None:
                if worker and (not worker.is_alive() or bridge_errors):
                    raise RuntimeError("SSH shadow relay exited unexpectedly")
                time.sleep(0.5)
            if not stopping:
                raise RuntimeError("FUSE mapper exited unexpectedly")
            return 0
        finally:
            ready.unlink(missing_ok=True)
            bridge_stop.set()
            if worker:
                worker.join(timeout=6)
            if bridge:
                bridge.close()
            _unmount(source, view)
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            for number, handler in previous.items():
                signal.signal(number, handler)


def helper_command(action: str, *, source: Path, view: Path, state: Path, tools: Path,
                   daemon_pid: int, image: str, module: Path | None = None,
                   name: str = NAME, ssh_source: Path | None = None,
                   ssh_shadow: Path | None = None) -> list[str]:
    if action not in ("mapper", "check", "cleanup"):
        raise ValueError("invalid privileged mapper action")
    if bool(ssh_source) != bool(ssh_shadow):
        raise ValueError("SSH source and shadow must be configured together")
    if action == "check":
        # Reuse the verified mapper namespace: creating a container on every
        # health tick consumes session keyrings and can exhaust the host UID quota.
        command = ["docker", "exec", "--user=0:0", name, "nsenter"]
    else:
        command = ["docker", "run", "--rm", "--pull=never", "--network=none", "--pid=host",
                   "--user=0:0", "--read-only", "--cap-drop=ALL", "--cap-add=SYS_ADMIN",
                   "--cap-add=SYS_PTRACE", "--cap-add=SYS_CHROOT", "--cap-add=DAC_OVERRIDE",
                   "--cap-add=CHOWN", "--cap-add=FOWNER", "--security-opt=no-new-privileges:true", "--device=/dev/fuse",
                   "--entrypoint=nsenter"]
    if action == "mapper":
        command.extend(["--name", name])
    script = module or Path(__file__).absolute()
    if action != "check":
        command.append(image)
    command.extend(["-t", str(daemon_pid), "-m", "--", "/usr/bin/python3", "-I", "-c",
                    "import runpy,sys; sys.path.insert(0,sys.argv[1]); sys.argv=sys.argv[2:]; "
                    "runpy.run_path(sys.argv[0],run_name='__main__')", str(script.parent.parent), str(script), action,
                    "--source", str(source), "--view", str(view), "--state", str(state),
                    "--tools", str(tools), "--daemon-pid", str(daemon_pid),
                    "--uid", str(UID), "--gid", str(GID)])
    if ssh_source and ssh_shadow:
        command.extend(["--ssh-source", str(ssh_source), "--ssh-shadow", str(ssh_shadow)])
    return command


def main(argv: list[str] | None = None) -> int:
    global UID, GID
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "status", "stop", "mapper", "check", "cleanup"))
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--view", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--tools", required=True, type=Path)
    parser.add_argument("--daemon-pid", type=int)
    parser.add_argument("--image", default="cdm-degraded-target:5090-rootfs")
    parser.add_argument("--name", default=NAME)
    parser.add_argument("--ssh-source", type=Path)
    parser.add_argument("--ssh-shadow", type=Path)
    parser.add_argument("--uid", type=int, default=1010)
    parser.add_argument("--gid", type=int, default=1010)
    args = parser.parse_args(argv)
    if args.uid <= 0 or args.gid <= 0:
        parser.error("target UID/GID must be positive")
    UID, GID = args.uid, args.gid
    try:
        pid = args.daemon_pid
        if pid is None:
            matches = subprocess.check_output(["pgrep", "-u", str(os.getuid()), "-x", "dockerd"], text=True).split()
            if len(matches) != 1:
                raise RuntimeError("exactly one rootless dockerd must be selected")
            pid = int(matches[0])
        if args.action in ("start", "status", "stop"):
            action = {"start": "mapper", "status": "check", "stop": "cleanup"}[args.action]
            if args.action == "stop":
                subprocess.run(["docker", "stop", "--timeout=10", args.name], check=False)
            return subprocess.run(helper_command(action, source=args.source, view=args.view,
                                  state=args.state, tools=args.tools, daemon_pid=pid,
                                  image=args.image, name=args.name, ssh_source=args.ssh_source,
                                  ssh_shadow=args.ssh_shadow)).returncode
        if args.action == "mapper":
            return mapper(args.source, args.view, args.state, args.tools, pid,
                          args.ssh_source, args.ssh_shadow)
        if args.action == "check":
            print(json.dumps(ready_record(args.source, args.view, args.state, pid,
                                         args.ssh_source, args.ssh_shadow)))
            return 0
        verify_namespace(pid)
        _paths(args.source, args.view, args.state)
        _unmount(args.source, args.view)
        (args.state / "ready.json").unlink(missing_ok=True)
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ready": False, "error": str(exc)}), flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
