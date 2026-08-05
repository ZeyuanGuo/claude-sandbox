import fcntl
import json
import os
import stat
from pathlib import Path

import pytest

import controlled_dev_machine.session_migration as session_migration
from controlled_dev_machine.errors import SessionMigrationError
from controlled_dev_machine.session_migration import import_claude_session

SOURCE_ID = "11111111-1111-4111-8111-111111111111"
NEW_ID = "22222222-2222-4222-8222-222222222222"
BUSINESS_ID = "33333333-3333-4333-8333-333333333333"


def _source(tmp_path: Path) -> tuple[Path, Path]:
    source_home = tmp_path / "source-home"
    persistent_home = tmp_path / "persistent-home"
    persistent_home.mkdir()
    projects = source_home / ".claude" / "projects"
    main_dir = projects / "-home-alice"
    main_dir.mkdir(parents=True)
    source_tmp = tmp_path / "claude-tmp" / "-home-alice" / SOURCE_ID
    rows = [
        {
            "type": "user",
            "sessionId": SOURCE_ID,
            "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "message": {
                "id": "msg_01FixtureMessageIdentifier",
                "content": f"read {source_tmp}/scratchpad/note.md"
            },
            "toolUseResult": {"customer": {"id": BUSINESS_ID}},
            "businessPayload": {
                "uuid": BUSINESS_ID,
                "requestId": BUSINESS_ID,
                "taskId": BUSINESS_ID,
            },
        },
        {
            "type": "assistant",
            "sessionId": SOURCE_ID,
            "session_id": SOURCE_ID,
            "parentUuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        },
    ]
    (main_dir / f"{SOURCE_ID}.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    companion = main_dir / SOURCE_ID
    (companion / "subagents").mkdir(parents=True)
    (companion / "subagents" / "agent.jsonl").write_text(
        json.dumps(
            {
                "sessionId": SOURCE_ID,
                "token": "sk-this-is-a-realistic-secret-token-value",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    other = projects / "-home-alice-project" / SOURCE_ID / "workflows" / "scripts"
    other.mkdir(parents=True)
    (other / "workflow.js").write_text(f"const session = '{SOURCE_ID}';\n", encoding="utf-8")
    tool_result = main_dir / SOURCE_ID / "tool-results" / "artifact.json"
    tool_result.parent.mkdir(parents=True)
    tool_result.write_text(
        json.dumps(
            {
                "uuid": BUSINESS_ID,
                "requestId": BUSINESS_ID,
                "taskId": BUSINESS_ID,
            }
        ),
        encoding="utf-8",
    )

    history = source_home / ".claude" / "file-history" / SOURCE_ID
    history.mkdir(parents=True)
    (history / "version@v1").write_text("source snapshot", encoding="utf-8")
    session_env = source_home / ".claude" / "session-env" / SOURCE_ID
    session_env.mkdir(parents=True)
    (session_env / "secret").write_text("must-not-copy", encoding="utf-8")

    source_tmp.mkdir(parents=True, exist_ok=True)
    (source_tmp / "scratchpad").mkdir()
    (source_tmp / "scratchpad" / "note.md").write_text(
        f"temporary record for {SOURCE_ID}", encoding="utf-8"
    )
    (source_tmp / "tasks").mkdir()
    (source_tmp / "tasks" / "b1yeyza2b.output").symlink_to(
        companion / "subagents" / "agent.jsonl"
    )
    return source_home, persistent_home


def _import(tmp_path: Path):
    source_home, persistent_home = _source(tmp_path)
    result = import_claude_session(
        source_home=source_home,
        persistent_home=persistent_home,
        target_home=Path("/home/alice"),
        target_uid=os.geteuid(),
        target_gid=os.getegid(),
        source_session_id=SOURCE_ID,
        new_session_id=NEW_ID,
        source_tmp_root=tmp_path / "claude-tmp",
    )
    return result, persistent_home


def _tree_snapshot(root: Path) -> dict[str, tuple[str, int, bytes | None]]:
    snapshot = {}
    for path in [root, *sorted(root.rglob("*"))]:
        relative = str(path.relative_to(root))
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_file():
            snapshot[relative] = ("file", mode, path.read_bytes())
        else:
            snapshot[relative] = ("directory", mode, None)
    return snapshot


def test_import_rekeys_complete_session_and_persists_tmp(tmp_path: Path) -> None:
    result, persistent_home = _import(tmp_path)

    assert result.new_session_id == NEW_ID
    assert result.secret_redactions == 2
    assert result.remapped_identifiers == 3
    main = persistent_home / ".claude" / "projects" / "-home-alice" / f"{NEW_ID}.jsonl"
    rows = [json.loads(line) for line in main.read_text(encoding="utf-8").splitlines()]
    assert {row["sessionId"] for row in rows} == {NEW_ID}
    assert rows[1]["session_id"] == NEW_ID
    assert rows[0]["uuid"] != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert rows[0]["message"]["id"] != "msg_01FixtureMessageIdentifier"
    assert rows[1]["parentUuid"] == rows[0]["uuid"]
    assert rows[0]["toolUseResult"]["customer"]["id"] == BUSINESS_ID
    assert rows[0]["businessPayload"] == {
        "uuid": BUSINESS_ID,
        "requestId": BUSINESS_ID,
        "taskId": BUSINESS_ID,
    }
    assert (
        rows[0]["message"]["content"]
        == f"read /home/alice/.claude/projects/-home-alice/{NEW_ID}/imported-tmp/scratchpad/note.md"
    )

    imported_tmp = main.with_suffix("") / "imported-tmp" / "scratchpad" / "note.md"
    assert imported_tmp.read_text(encoding="utf-8") == f"temporary record for {NEW_ID}"
    imported_outputs = list(
        (main.with_suffix("") / "imported-tmp" / "tasks").glob("*.output")
    )
    assert len(imported_outputs) == 1
    imported_link = imported_outputs[0]
    assert imported_link.is_file() and not imported_link.is_symlink()
    assert "<redacted-imported-secret>" in imported_link.read_text(encoding="utf-8")
    assert (
        persistent_home
        / ".claude"
        / "projects"
        / "-home-alice-project"
        / NEW_ID
        / "workflows"
        / "scripts"
        / "workflow.js"
    ).exists()
    assert (
        main.with_suffix("") / "imported-file-history" / "version@v1"
    ).exists()
    assert json.loads(
        (main.with_suffix("") / "tool-results" / "artifact.json").read_text(
            encoding="utf-8"
        )
    ) == {
        "uuid": BUSINESS_ID,
        "requestId": BUSINESS_ID,
        "taskId": BUSINESS_ID,
    }
    assert not (persistent_home / ".claude" / "file-history" / NEW_ID).exists()
    assert not (persistent_home / ".claude" / "session-env" / NEW_ID).exists()
    assert stat.S_IMODE(main.stat().st_mode) == 0o600

    for path in (persistent_home / ".claude").rglob("*"):
        assert SOURCE_ID not in path.name
        if path.is_file():
            assert SOURCE_ID.encode() not in path.read_bytes()


def test_import_refuses_collision_without_changing_existing_session(tmp_path: Path) -> None:
    result, persistent_home = _import(tmp_path)
    before = result.main_path.read_bytes()
    source_home = tmp_path / "source-home"

    with pytest.raises(SessionMigrationError, match="目标会话已存在"):
        import_claude_session(
            source_home=source_home,
            persistent_home=persistent_home,
            target_home=Path("/home/alice"),
            target_uid=os.geteuid(),
            target_gid=os.getegid(),
            source_session_id=SOURCE_ID,
            new_session_id=NEW_ID,
            source_tmp_root=tmp_path / "claude-tmp",
        )
    assert result.main_path.read_bytes() == before


def test_import_requires_one_main_session(tmp_path: Path) -> None:
    persistent_home = tmp_path / "persistent"
    persistent_home.mkdir()
    with pytest.raises(SessionMigrationError, match="实际找到 0 个"):
        import_claude_session(
            source_home=tmp_path / "missing",
            persistent_home=persistent_home,
            target_home=Path("/home/alice"),
            target_uid=os.geteuid(),
            target_gid=os.getegid(),
            source_session_id=SOURCE_ID,
            new_session_id=NEW_ID,
            source_tmp_root=tmp_path / "claude-tmp",
        )


def test_import_rejects_dangling_tool_result(tmp_path: Path) -> None:
    source_home, persistent_home = _source(tmp_path)
    main = source_home / ".claude" / "projects" / "-home-alice" / f"{SOURCE_ID}.jsonl"
    rows = [json.loads(line) for line in main.read_text(encoding="utf-8").splitlines()]
    rows[1]["message"] = {
        "content": [
            {
                "type": "tool_result",
                "tool_use_id": "toolu_01DanglingFixtureIdentifier",
            }
        ]
    }
    main.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    with pytest.raises(SessionMigrationError, match="tool_result 引用存在悬空"):
        import_claude_session(
            source_home=source_home,
            persistent_home=persistent_home,
            target_home=Path("/home/alice"),
            target_uid=os.geteuid(),
            target_gid=os.getegid(),
            source_session_id=SOURCE_ID,
            new_session_id=NEW_ID,
            source_tmp_root=tmp_path / "claude-tmp",
        )

    assert not (persistent_home / ".claude").exists()


def test_import_rejects_symlink_to_other_claude_state(tmp_path: Path) -> None:
    source_home, persistent_home = _source(tmp_path)
    credentials = source_home / ".claude" / ".credentials.json"
    credentials.write_text('{"token":"do-not-copy"}', encoding="utf-8")
    unsafe_link = (
        tmp_path
        / "claude-tmp"
        / "-home-alice"
        / SOURCE_ID
        / "tasks"
        / "credentials.output"
    )
    unsafe_link.symlink_to(credentials)

    with pytest.raises(SessionMigrationError, match="超出本次会话目录"):
        import_claude_session(
            source_home=source_home,
            persistent_home=persistent_home,
            target_home=Path("/home/alice"),
            target_uid=os.geteuid(),
            target_gid=os.getegid(),
            source_session_id=SOURCE_ID,
            new_session_id=NEW_ID,
            source_tmp_root=tmp_path / "claude-tmp",
        )
    assert not (persistent_home / ".claude" / "projects" / "-home-alice" / NEW_ID).exists()


def test_root_import_assigns_private_paths_to_target_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_home, persistent_home = _source(tmp_path)
    chowns: list[tuple[Path, int, int]] = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        os,
        "chown",
        lambda path, uid, gid, **_kwargs: chowns.append((Path(path), uid, gid)),
    )

    result = import_claude_session(
        source_home=source_home,
        persistent_home=persistent_home,
        target_home=Path("/home/alice"),
        target_uid=1234,
        target_gid=5678,
        source_session_id=SOURCE_ID,
        new_session_id=NEW_ID,
        source_tmp_root=tmp_path / "claude-tmp",
    )

    assert (persistent_home / ".claude", 1234, 5678) in chowns
    assert (result.main_path, 1234, 5678) in chowns
    assert (result.manifest_path.parent, 1234, 5678) in chowns


def test_file_history_without_companion_is_archived(tmp_path: Path) -> None:
    source_home = tmp_path / "source-home"
    persistent_home = tmp_path / "persistent-home"
    persistent_home.mkdir()
    project = source_home / ".claude" / "projects" / "-home-alice"
    project.mkdir(parents=True)
    (project / f"{SOURCE_ID}.jsonl").write_text(
        json.dumps({"type": "user", "sessionId": SOURCE_ID, "uuid": BUSINESS_ID})
        + "\n",
        encoding="utf-8",
    )
    history = source_home / ".claude" / "file-history" / SOURCE_ID
    history.mkdir(parents=True)
    (history / "version@v1").write_text("snapshot", encoding="utf-8")

    result = import_claude_session(
        source_home=source_home,
        persistent_home=persistent_home,
        target_home=Path("/home/alice"),
        target_uid=os.geteuid(),
        target_gid=os.getegid(),
        source_session_id=SOURCE_ID,
        new_session_id=NEW_ID,
        source_tmp_root=tmp_path / "claude-tmp",
    )

    assert result.archived_file_history is True
    assert (
        persistent_home
        / ".claude"
        / "projects"
        / "-home-alice"
        / NEW_ID
        / "imported-file-history"
        / "version@v1"
    ).read_text(encoding="utf-8") == "snapshot"


def test_import_redacts_recognized_credentials(tmp_path: Path) -> None:
    source_home, persistent_home = _source(tmp_path)
    main = source_home / ".claude" / "projects" / "-home-alice" / f"{SOURCE_ID}.jsonl"
    rows = [json.loads(line) for line in main.read_text(encoding="utf-8").splitlines()]
    rows[0]["headers"] = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.signaturevalue"
    }
    rows[0]["payload"] = {"password": "fixture-password-value"}
    rows[0]["credentialResult"] = {"token": "fixture-opaque-token-value"}
    rows[0]["notes"] = (
        "ACCESS_TOKEN=fixture-access-token-value\n"
        "Cookie: session=fixture-cookie-value\n"
        "TOKEN=fixture-generic-token-value"
    )
    main.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    result = import_claude_session(
        source_home=source_home,
        persistent_home=persistent_home,
        target_home=Path("/home/alice"),
        target_uid=os.geteuid(),
        target_gid=os.getegid(),
        source_session_id=SOURCE_ID,
        new_session_id=NEW_ID,
        source_tmp_root=tmp_path / "claude-tmp",
    )

    content = result.main_path.read_text(encoding="utf-8")
    assert result.secret_redactions == 8
    assert "fixture-password-value" not in content
    assert "fixture-access-token-value" not in content
    assert "fixture-cookie-value" not in content
    assert "fixture-generic-token-value" not in content
    assert "fixture-opaque-token-value" not in content
    assert "eyJhbGciOiJIUzI1NiJ9" not in content
    assert content.count("<redacted-imported-secret>") == 6


def test_import_rolls_back_every_target_when_commit_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_home, persistent_home = _source(tmp_path)
    before = _tree_snapshot(persistent_home)
    real_replace = os.replace
    calls = 0

    def fail_second_replace(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected commit failure")
        real_replace(source, destination)

    monkeypatch.setattr(session_migration.os, "replace", fail_second_replace)

    with pytest.raises(SessionMigrationError, match="会话迁移失败"):
        import_claude_session(
            source_home=source_home,
            persistent_home=persistent_home,
            target_home=Path("/home/alice"),
            target_uid=os.geteuid(),
            target_gid=os.getegid(),
            source_session_id=SOURCE_ID,
            new_session_id=NEW_ID,
            source_tmp_root=tmp_path / "claude-tmp",
        )

    assert _tree_snapshot(persistent_home) == before


def test_import_refuses_concurrent_writer(tmp_path: Path) -> None:
    source_home, persistent_home = _source(tmp_path)
    claude_home = persistent_home / ".claude"
    claude_home.mkdir(mode=0o700)
    descriptor = os.open(claude_home, os.O_RDONLY | os.O_DIRECTORY)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(SessionMigrationError, match="另一个会话迁移"):
            import_claude_session(
                source_home=source_home,
                persistent_home=persistent_home,
                target_home=Path("/home/alice"),
                target_uid=os.geteuid(),
                target_gid=os.getegid(),
                source_session_id=SOURCE_ID,
                new_session_id=NEW_ID,
                source_tmp_root=tmp_path / "claude-tmp",
            )
    finally:
        os.close(descriptor)

    assert not (claude_home / "projects").exists()
