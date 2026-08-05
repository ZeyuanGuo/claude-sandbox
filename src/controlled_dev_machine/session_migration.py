from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from controlled_dev_machine.errors import SessionMigrationError


@dataclass(frozen=True)
class SessionImportResult:
    new_session_id: str
    project_key: str
    main_path: Path
    manifest_path: Path
    files: int
    bytes: int
    imported_tmp: bool
    archived_file_history: bool
    secret_redactions: int
    remapped_identifiers: int

    def as_json(self) -> dict[str, object]:
        return {
            "new_session_id": self.new_session_id,
            "project_key": self.project_key,
            "resume_from": f"~/.claude/projects/{self.project_key}/{self.new_session_id}.jsonl",
            "manifest": str(self.manifest_path),
            "files": self.files,
            "bytes": self.bytes,
            "imported_tmp": self.imported_tmp,
            "archived_file_history": self.archived_file_history,
            "session_env_imported": False,
            "secret_redactions": self.secret_redactions,
            "remapped_identifiers": self.remapped_identifiers,
        }


_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{19,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
    ),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
        r"password|passwd|client[_-]?secret)\s*[:=]\s*[\"']?[^\s\"';,]{8,}[\"']?"
    ),
    re.compile(r"\bTOKEN\s*[:=]\s*[\"']?[^\s\"';,]{8,}[\"']?"),
    re.compile(
        r"(?im)^[ \t]*(?:authorization|proxy-authorization|cookie|set-cookie)"
        r"\s*:\s*[^\r\n]+$"
    ),
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
)
_SECRET_REPLACEMENT = "<redacted-imported-secret>"
_CREDENTIAL_KEYS = frozenset(
    {
        "access_token",
        "accesstoken",
        "api_key",
        "apikey",
        "auth_token",
        "authorization",
        "authtoken",
        "client_secret",
        "clientsecret",
        "cookie",
        "credentials",
        "id_token",
        "idtoken",
        "oauth_token",
        "oauthtoken",
        "passwd",
        "password",
        "private_key",
        "privatekey",
        "proxy_authorization",
        "proxyauthorization",
        "refresh_token",
        "refreshtoken",
        "session_token",
        "sessiontoken",
        "set_cookie",
        "setcookie",
        "token",
    }
)
_TOP_LEVEL_IDENTIFIER_KEYS = frozenset(
    {
        "agentId",
        "agent_id",
        "leafUuid",
        "messageId",
        "parentUuid",
        "promptId",
        "requestId",
        "runId",
        "snapshotMessageId",
        "sourceToolAssistantUUID",
        "taskId",
        "toolUseId",
        "tool_use_id",
        "uuid",
    }
)
_PREFIXED_IDENTIFIER = re.compile(r"^(?:msg_|req_|toolu_|wf_)[A-Za-z0-9_-]+$")
_AGENT_IDENTIFIER = re.compile(r"^a[0-9a-f]{16}$")
_PATH_IDENTIFIER = re.compile(
    r"(?:msg_|req_|toolu_)[A-Za-z0-9_-]+|wf_[0-9a-f]+-[0-9a-f]+|a[0-9a-f]{16}"
)
_OPAQUE_FILE_IDENTIFIER = re.compile(r"^[a-z0-9]{8,32}$")
_AGENT_RECORD_FILE = re.compile(r"^agent-a[0-9a-f]{16}\.jsonl$")
_AGENT_META_FILE = re.compile(r"^agent-a[0-9a-f]{16}\.meta\.json$")
_WORKFLOW_FILE = re.compile(r"^wf_[0-9a-f]+-[0-9a-f]+\.json$")
_IDENTIFIER_CANDIDATE_PATTERN = (
    r"(?:msg_|req_|toolu_)[A-Za-z0-9_-]+"
    r"|wf_[0-9a-f]+-[0-9a-f]+"
    r"|(?<![A-Za-z0-9])a[0-9a-f]{16}(?![A-Za-z0-9])"
    r"|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    r"|(?<![A-Za-z0-9])[A-Za-z0-9]{6,64}(?![A-Za-z0-9])"
)
_IDENTIFIER_CANDIDATE_TEXT = re.compile(_IDENTIFIER_CANDIDATE_PATTERN)
_IDENTIFIER_CANDIDATE_BYTES = re.compile(_IDENTIFIER_CANDIDATE_PATTERN.encode())


@dataclass
class _Sanitizer:
    replacements: tuple[tuple[str, str], ...]
    identifier_map: dict[str, str]
    secret_redactions: int = 0

    def credential(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {self.text(str(key)): self.credential(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.credential(item) for item in value]
        if isinstance(value, str):
            self.secret_redactions += 1
            return _SECRET_REPLACEMENT
        return value

    def text(self, value: str) -> str:
        for old, new in self.replacements:
            value = value.replace(old, new)
        value = _IDENTIFIER_CANDIDATE_TEXT.sub(
            lambda match: self.identifier_map.get(match.group(0), match.group(0)),
            value,
        )
        for pattern in _SECRET_PATTERNS:
            value, count = pattern.subn(_SECRET_REPLACEMENT, value)
            self.secret_redactions += count
        return value

    def data(self, value: bytes) -> bytes:
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            for old, new in self.replacements:
                value = value.replace(old.encode(), new.encode())
            value = _IDENTIFIER_CANDIDATE_BYTES.sub(
                lambda match: self.identifier_map.get(
                    match.group(0).decode(), match.group(0).decode()
                ).encode(),
                value,
            )
            for pattern in _SECRET_PATTERNS:
                if pattern.flags & re.DOTALL:
                    continue
                byte_pattern = re.compile(
                    pattern.pattern.encode(), pattern.flags & ~re.UNICODE
                )
                value, count = byte_pattern.subn(_SECRET_REPLACEMENT.encode(), value)
                self.secret_redactions += count
            return value
        return self.text(text).encode("utf-8")


def import_claude_session(
    *,
    source_home: Path,
    persistent_home: Path,
    target_home: Path,
    target_uid: int,
    target_gid: int,
    source_session_id: str,
    new_session_id: str | None = None,
    source_tmp_root: Path | None = None,
) -> SessionImportResult:
    """Import one Claude session under a new ID and redact recognized credentials."""
    source_id = _canonical_uuid(source_session_id, "源会话编号")
    destination_id = _canonical_uuid(new_session_id or str(uuid.uuid4()), "新会话编号")
    if source_id == destination_id:
        raise SessionMigrationError("新会话编号不能与源会话编号相同")
    if os.geteuid() not in {0, target_uid}:
        raise SessionMigrationError("必须由目标用户或 root 执行会话迁移")

    source_claude = source_home / ".claude"
    source_projects = source_claude / "projects"
    destination_claude = persistent_home / ".claude"
    destination_projects = destination_claude / "projects"

    if not persistent_home.is_dir() or persistent_home.is_symlink():
        raise SessionMigrationError("沙箱持久 Home 尚未初始化或不是普通目录")
    if source_projects.is_symlink():
        raise SessionMigrationError("宿主 Claude projects 不能是符号链接")

    main_candidates = sorted(source_projects.glob(f"*/{source_id}.jsonl"))
    if len(main_candidates) != 1:
        raise SessionMigrationError(
            f"应找到一个主会话文件，实际找到 {len(main_candidates)} 个"
        )
    source_main = main_candidates[0]
    _require_regular_file(source_main)
    if source_main.parent.is_symlink():
        raise SessionMigrationError("主会话项目目录不能是符号链接")
    project_key = source_main.parent.name

    companion_sources = sorted(source_projects.glob(f"*/{source_id}"))
    for path in companion_sources:
        if path.is_symlink() or path.parent.is_symlink() or not path.is_dir():
            raise SessionMigrationError(f"会话附属路径不是普通目录: {path}")
    source_history = source_claude / "file-history" / source_id
    tmp_root = source_tmp_root or Path(f"/tmp/claude-{target_uid}")
    source_tmp = tmp_root / project_key / source_id

    final_main = destination_projects / project_key / f"{destination_id}.jsonl"
    final_companions = {
        source.parent.name: destination_projects / source.parent.name / destination_id
        for source in companion_sources
    }
    if (
        (source_tmp.is_dir() or source_history.is_dir())
        and project_key not in final_companions
    ):
        final_companions[project_key] = destination_projects / project_key / destination_id
    final_manifest = destination_claude / "session-imports" / f"{destination_id}.json"
    old_tmp = str(tmp_root / project_key / source_id)
    stable_tmp = str(
        target_home
        / ".claude"
        / "projects"
        / project_key
        / destination_id
        / "imported-tmp"
    )
    source_roots = [source_main, *companion_sources]
    if source_history.is_dir():
        source_roots.append(source_history)
    if source_tmp.is_dir():
        source_roots.append(source_tmp)
    source_fingerprint = _fingerprint_paths(source_roots)
    identifier_map = _build_identifier_map(source_roots, source_id, destination_id)
    replacements = ((old_tmp, stable_tmp), (source_id, destination_id))
    sanitizer = _Sanitizer(replacements, identifier_map)
    allowed_link_targets = (source_main, *companion_sources)

    stage = destination_claude / f".session-import-{destination_id}.tmp"
    created_directories: list[Path] = []
    committed: list[Path] = []
    reservations: list[Path] = []
    lock_descriptor: int | None = None
    try:
        _ensure_private_directory(
            destination_claude, target_uid, target_gid, created_directories
        )
        lock_descriptor = _acquire_import_lock(destination_claude)
        _ensure_private_directory(
            destination_projects, target_uid, target_gid, created_directories
        )
        if stage.exists() or stage.is_symlink():
            raise SessionMigrationError(f"迁移暂存目录已存在: {stage}")
        stage.mkdir(mode=0o700)

        staged_main = stage / "projects" / project_key / f"{destination_id}.jsonl"
        _copy_file(source_main, staged_main, sanitizer, allowed_link_targets)

        for source in companion_sources:
            staged = stage / "projects" / source.parent.name / destination_id
            _copy_tree(source, staged, sanitizer, allowed_link_targets)

        imported_tmp = source_tmp.is_dir() and not source_tmp.is_symlink()
        if imported_tmp:
            staged_tmp = stage / "projects" / project_key / destination_id / "imported-tmp"
            if staged_tmp.exists():
                raise SessionMigrationError("会话附属目录已包含 imported-tmp，不能覆盖")
            _copy_tree(source_tmp, staged_tmp, sanitizer, allowed_link_targets)

        archived_history = source_history.is_dir() and not source_history.is_symlink()
        if archived_history:
            _copy_tree(
                source_history,
                stage
                / "projects"
                / project_key
                / destination_id
                / "imported-file-history",
                sanitizer,
                allowed_link_targets,
            )

        if _fingerprint_paths(source_roots) != source_fingerprint:
            raise SessionMigrationError("源会话在迁移过程中发生变化，请停止源会话后重试")

        payload_files, payload_bytes = _tree_totals(stage)
        manifest = {
            "schema_version": 1,
            "new_session_id": destination_id,
            "project_key": project_key,
            "payload_files": payload_files,
            "payload_bytes": payload_bytes,
            "imported_tmp": imported_tmp,
            "file_history_mode": "archived" if archived_history else "absent",
            "session_env_imported": False,
            "secret_redactions": sanitizer.secret_redactions,
            "remapped_identifiers": len(identifier_map),
        }
        staged_manifest = stage / "session-imports" / f"{destination_id}.json"
        _write_json(staged_manifest, manifest)
        _assert_no_source_id(stage, source_id)
        _assert_no_identifiers(stage, identifier_map)
        _assert_no_recognized_secrets(stage)
        _validate_main_session(staged_main, destination_id)

        staged_targets = [
            (staged_main, final_main),
            *(
                (stage / "projects" / key / destination_id, final)
                for key, final in sorted(final_companions.items())
            ),
        ]
        staged_targets.append((staged_manifest, final_manifest))

        for staged_path, final_path in staged_targets:
            _ensure_private_directory(
                final_path.parent, target_uid, target_gid, created_directories
            )
            _reserve_path(final_path, directory=staged_path.is_dir())
            reservations.append(final_path)

        for staged_path, final_path in staged_targets:
            os.replace(staged_path, final_path)
            reservations.remove(final_path)
            committed.append(final_path)
            if os.geteuid() == 0:
                _chown_path(final_path, target_uid, target_gid)

        _assert_no_source_id_paths(committed, source_id)
        final_files, final_bytes = _paths_totals(committed)
        return SessionImportResult(
            new_session_id=destination_id,
            project_key=project_key,
            main_path=final_main,
            manifest_path=final_manifest,
            files=final_files,
            bytes=final_bytes,
            imported_tmp=imported_tmp,
            archived_file_history=archived_history,
            secret_redactions=sanitizer.secret_redactions,
            remapped_identifiers=len(identifier_map),
        )
    except Exception as exc:
        for path in reversed(committed):
            _remove_path(path)
        for path in reversed(reservations):
            _remove_path(path)
        if isinstance(exc, SessionMigrationError):
            raise
        raise SessionMigrationError(f"会话迁移失败: {exc}") from exc
    finally:
        _remove_path(stage)
        if lock_descriptor is not None:
            os.close(lock_descriptor)
        for path in reversed(created_directories):
            with suppress(OSError):
                path.rmdir()


def _canonical_uuid(value: str, label: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise SessionMigrationError(f"{label}不是有效 UUID") from exc
    canonical = str(parsed)
    if canonical != value:
        raise SessionMigrationError(f"{label}必须使用小写标准 UUID 格式")
    return canonical


def _require_regular_file(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise SessionMigrationError(f"会话文件不存在: {path}") from exc
    if not stat.S_ISREG(mode):
        raise SessionMigrationError(f"会话文件不是普通文件: {path}")


def _copy_tree(
    source: Path,
    destination: Path,
    sanitizer: _Sanitizer,
    allowed_link_targets: tuple[Path, ...],
) -> None:
    if source.is_symlink():
        raise SessionMigrationError(f"不迁移符号链接目录: {source}")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    for root, dirs, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        for name in dirs:
            child = root_path / name
            if child.is_symlink():
                raise SessionMigrationError(f"不迁移符号链接: {child}")
            relative = _mapped_relative(child.relative_to(source), sanitizer)
            (destination / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
        for name in files:
            child = root_path / name
            copy_source = child
            if child.is_symlink():
                try:
                    copy_source = child.resolve(strict=True)
                except FileNotFoundError as exc:
                    raise SessionMigrationError(f"符号链接目标不存在: {child}") from exc
                if not _is_allowed_link_target(copy_source, allowed_link_targets):
                    raise SessionMigrationError(f"符号链接超出本次会话目录: {child}")
            _require_regular_file(copy_source)
            relative = _mapped_relative(child.relative_to(source), sanitizer)
            _copy_file(
                copy_source, destination / relative, sanitizer, allowed_link_targets
            )


def _mapped_relative(path: Path, sanitizer: _Sanitizer) -> Path:
    parts = []
    for part in path.parts:
        mapped = sanitizer.text(part)
        if mapped in {"", ".", ".."} or "/" in mapped:
            raise SessionMigrationError(f"迁移后出现非法路径分量: {mapped!r}")
        parts.append(mapped)
    return Path(*parts)


def _copy_file(
    source: Path,
    destination: Path,
    sanitizer: _Sanitizer,
    allowed_link_targets: tuple[Path, ...],
) -> None:
    if source.is_symlink():
        source = source.resolve(strict=True)
        if not _is_allowed_link_target(source, allowed_link_targets):
            raise SessionMigrationError(f"符号链接超出本次会话目录: {source}")
    _require_regular_file(source)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    suffix = source.suffix.lower()
    if suffix == ".jsonl":
        _copy_jsonl(source, destination, sanitizer)
    elif suffix == ".json":
        try:
            value = json.loads(source.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SessionMigrationError(f"JSON 文件无效: {source}") from exc
        _write_json(destination, _replace_json(value, sanitizer))
    else:
        data = sanitizer.data(source.read_bytes())
        destination.write_bytes(data)
        os.chmod(destination, 0o700 if source.stat().st_mode & stat.S_IXUSR else 0o600)


def _copy_jsonl(source: Path, destination: Path, sanitizer: _Sanitizer) -> None:
    with source.open("r", encoding="utf-8") as reader, destination.open(
        "w", encoding="utf-8"
    ) as writer:
        for line_number, line in enumerate(reader, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SessionMigrationError(
                    f"JSONL 文件无效: {source}:{line_number}"
                ) from exc
            writer.write(
                json.dumps(
                    _replace_json(value, sanitizer),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )
    os.chmod(destination, 0o600)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o600)


def _replace_json(value: Any, sanitizer: _Sanitizer) -> Any:
    if isinstance(value, str):
        return sanitizer.text(value)
    if isinstance(value, list):
        return [_replace_json(item, sanitizer) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            mapped_key = sanitizer.text(key)
            normalized_key = re.sub(r"[-\s]", "_", key).lower()
            if normalized_key in _CREDENTIAL_KEYS:
                result[mapped_key] = sanitizer.credential(item)
            else:
                result[mapped_key] = _replace_json(item, sanitizer)
        return result
    return value


def _validate_main_session(path: Path, session_id: str) -> None:
    rows = 0
    matching = 0
    uuids: set[str] = set()
    parents: set[str] = set()
    references: set[str] = set()
    tool_uses: set[str] = set()
    tool_results: set[str] = set()
    with path.open("r", encoding="utf-8") as reader:
        for line in reader:
            if not line.strip():
                continue
            row = json.loads(line)
            rows += 1
            if "sessionId" in row and row["sessionId"] != session_id:
                raise SessionMigrationError("迁移后的主记录含有其他 sessionId")
            if "session_id" in row and row["session_id"] != session_id:
                raise SessionMigrationError("迁移后的主记录含有其他 session_id")
            if row.get("sessionId") == session_id or row.get("session_id") == session_id:
                matching += 1
            if isinstance(row.get("uuid"), str):
                uuids.add(row["uuid"])
            if isinstance(row.get("parentUuid"), str):
                parents.add(row["parentUuid"])
            for key in ("leafUuid", "sourceToolAssistantUUID"):
                if isinstance(row.get(key), str):
                    references.add(row[key])
            message = row.get("message")
            if not isinstance(message, dict) or not isinstance(message.get("content"), list):
                continue
            for item in message["content"]:
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "tool_use" and isinstance(item.get("id"), str):
                    tool_uses.add(item["id"])
                if item.get("type") == "tool_result" and isinstance(
                    item.get("tool_use_id"), str
                ):
                    tool_results.add(item["tool_use_id"])
    if rows == 0 or matching == 0:
        raise SessionMigrationError("迁移后的主记录没有有效 sessionId")
    missing = (parents | references) - uuids
    if missing:
        raise SessionMigrationError("迁移后的主消息引用存在悬空")
    if tool_results - tool_uses:
        raise SessionMigrationError("迁移后的 tool_result 引用存在悬空")


def _assert_no_source_id(root: Path, source_id: str) -> None:
    _assert_no_source_id_paths([root], source_id)


def _assert_no_source_id_paths(paths: list[Path], source_id: str) -> None:
    marker = source_id.encode()
    for root in paths:
        if source_id in root.name:
            raise SessionMigrationError(f"迁移目标路径仍含源会话编号: {root}")
        candidates = [root] if root.is_file() else root.rglob("*")
        for path in candidates:
            if source_id in path.name:
                raise SessionMigrationError(f"迁移目标路径仍含源会话编号: {path}")
            if path.is_file() and marker in path.read_bytes():
                raise SessionMigrationError(f"迁移目标内容仍含源会话编号: {path}")


def _assert_no_identifiers(root: Path, identifier_map: dict[str, str]) -> None:
    if not identifier_map:
        return
    old_values = {value.encode() for value in identifier_map}
    for path in root.rglob("*"):
        if any(
            match.group(0) in old_values
            for match in _IDENTIFIER_CANDIDATE_BYTES.finditer(path.name.encode())
        ):
            raise SessionMigrationError(f"迁移目标路径仍含源内部标识: {path}")
        if path.is_file():
            for match in _IDENTIFIER_CANDIDATE_BYTES.finditer(path.read_bytes()):
                if match.group(0) in old_values:
                    raise SessionMigrationError(f"迁移目标内容仍含源内部标识: {path}")


def _assert_no_recognized_secrets(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if any(pattern.search(text) for pattern in _SECRET_PATTERNS):
            raise SessionMigrationError(f"迁移目标仍含可识别的凭据形态: {path}")


def _tree_totals(root: Path) -> tuple[int, int]:
    return _paths_totals([root])


def _paths_totals(paths: list[Path]) -> tuple[int, int]:
    files = 0
    size = 0
    for root in paths:
        candidates = [root] if root.is_file() else root.rglob("*")
        for path in candidates:
            if path.is_file():
                files += 1
                size += path.stat().st_size
    return files, size


def _fingerprint_paths(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for root_index, root in enumerate(paths):
        candidates = [root] if root.is_file() else [root, *sorted(root.rglob("*"))]
        for path in candidates:
            relative = Path(str(root_index)) / path.relative_to(root)
            metadata = path.lstat()
            digest.update(str(relative).encode())
            digest.update(b"\0")
            digest.update(str(stat.S_IFMT(metadata.st_mode)).encode())
            digest.update(b"\0")
            if path.is_symlink():
                digest.update(os.readlink(path).encode())
            elif path.is_file():
                with path.open("rb") as reader:
                    for block in iter(lambda: reader.read(1024 * 1024), b""):
                        digest.update(block)
            digest.update(b"\0")
    return digest.hexdigest()


def _build_identifier_map(
    roots: list[Path], source_session_id: str, destination_session_id: str
) -> dict[str, str]:
    identifiers: set[str] = set()
    for root in roots:
        candidates = [root] if root.is_file() else root.rglob("*")
        for path in candidates:
            for match in _PATH_IDENTIFIER.finditer(path.name):
                identifiers.add(match.group(0))
            if (
                path.is_file()
                and path.parent.name == "tasks"
                and _OPAQUE_FILE_IDENTIFIER.fullmatch(path.stem)
            ):
                identifiers.add(path.stem)
            if path.is_symlink() or not path.is_file():
                continue
            if path.suffix.lower() == ".jsonl":
                context = _identifier_context(path, source_session_id)
                with path.open("r", encoding="utf-8") as reader:
                    for line_number, line in enumerate(reader, start=1):
                        if not line.strip():
                            continue
                        try:
                            value = json.loads(line)
                        except json.JSONDecodeError as exc:
                            raise SessionMigrationError(
                                f"JSONL 文件无效: {path}:{line_number}"
                            ) from exc
                        _collect_json_identifiers(value, identifiers, context=context)
            elif path.suffix.lower() == ".json":
                try:
                    value = json.loads(path.read_text(encoding="utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise SessionMigrationError(f"JSON 文件无效: {path}") from exc
                _collect_json_identifiers(
                    value,
                    identifiers,
                    context=_identifier_context(path, source_session_id),
                )

    identifiers.discard(source_session_id)
    identifiers.discard("")
    reserved = identifiers | {source_session_id, destination_session_id}
    result: dict[str, str] = {}
    for identifier in sorted(identifiers):
        replacement = _new_identifier(identifier)
        while replacement in reserved:
            replacement = _new_identifier(identifier)
        result[identifier] = replacement
        reserved.add(replacement)
    return result


def _collect_json_identifiers(
    value: Any,
    identifiers: set[str],
    *,
    context: str,
    path: tuple[str, ...] = (),
) -> None:
    if context == "none":
        return
    if isinstance(value, list):
        for item in value:
            _collect_json_identifiers(
                item, identifiers, context=context, path=(*path, "[]")
            )
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        known_id_field = path == () and (
            (context == "record" and key in _TOP_LEVEL_IDENTIFIER_KEYS)
            or (context == "agent-meta" and key == "toolUseId")
            or (context == "workflow" and key in {"runId", "taskId"})
        )
        known_id_path = context == "record" and (
            (path == ("message",) and key == "id")
            or (
                path == ("message", "content", "[]")
                and value.get("type") == "tool_use"
                and key == "id"
            )
            or (
                path == ("message", "content", "[]")
                and value.get("type") == "tool_result"
                and key == "tool_use_id"
            )
            or (path == ("snapshot",) and key == "messageId")
        )
        known_workflow_path = context == "workflow" and (
                path == ("workflowProgress", "[]")
                and value.get("type") == "workflow_agent"
                and key == "agentId"
        )
        if (
            isinstance(item, str)
            and (known_id_field or known_id_path or known_workflow_path)
            and _looks_like_session_identifier(item)
        ):
            identifiers.add(item)
        _collect_json_identifiers(
            item, identifiers, context=context, path=(*path, key)
        )


def _identifier_context(path: Path, source_session_id: str) -> str:
    if path.name == f"{source_session_id}.jsonl":
        return "record"
    if _AGENT_RECORD_FILE.fullmatch(path.name) or path.name == "journal.jsonl":
        return "record"
    if _AGENT_META_FILE.fullmatch(path.name):
        return "agent-meta"
    if path.parent.name == "workflows" and _WORKFLOW_FILE.fullmatch(path.name):
        return "workflow"
    return "none"


def _looks_like_session_identifier(value: str) -> bool:
    if _PREFIXED_IDENTIFIER.fullmatch(value) or _AGENT_IDENTIFIER.fullmatch(value):
        return True
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _new_identifier(value: str) -> str:
    try:
        if str(uuid.UUID(value)) == value:
            return str(uuid.uuid4())
    except ValueError:
        pass
    if value.startswith(("msg_", "req_", "toolu_")):
        prefix, suffix = value.split("_", 1)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return prefix + "_" + "".join(secrets.choice(alphabet) for _ in suffix)
    if value.startswith("wf_"):
        return "wf_" + "".join(
            char if char == "-" else secrets.choice("0123456789abcdef")
            for char in value[3:]
        )
    if _AGENT_IDENTIFIER.fullmatch(value):
        return "a" + secrets.token_hex(8)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in value)


def _is_allowed_link_target(path: Path, allowed_targets: tuple[Path, ...]) -> bool:
    for target in allowed_targets:
        resolved_target = target.resolve()
        if resolved_target.is_file() and path == resolved_target:
            return True
        if resolved_target.is_dir() and path.is_relative_to(resolved_target):
            return True
    return False


def _chown_path(path: Path, uid: int, gid: int) -> None:
    candidates = [path] if path.is_file() else [path, *path.rglob("*")]
    for candidate in candidates:
        os.chown(candidate, uid, gid, follow_symlinks=False)


def _ensure_private_directory(
    path: Path, uid: int, gid: int, created: list[Path]
) -> None:
    if path in created:
        return
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
            raise SessionMigrationError(f"目标路径不是普通目录: {path}")
        if metadata.st_uid != uid or metadata.st_gid != gid:
            raise SessionMigrationError(f"目标目录不属于沙箱用户: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise SessionMigrationError(f"目标目录权限不是私有: {path}")
        return
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise SessionMigrationError(f"目标父目录不存在或不安全: {path.parent}")
    path.mkdir(mode=0o700)
    if os.geteuid() == 0:
        os.chown(path, uid, gid)
    created.append(path)


def _acquire_import_lock(path: Path) -> int:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(descriptor)
        raise SessionMigrationError("另一个会话迁移正在写入目标 Home") from exc
    return descriptor


def _reserve_path(path: Path, *, directory: bool) -> None:
    try:
        if directory:
            path.mkdir(mode=0o700)
        else:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
    except FileExistsError as exc:
        raise SessionMigrationError(f"目标会话已存在: {path}") from exc


def _remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()
