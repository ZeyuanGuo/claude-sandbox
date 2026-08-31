from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from controlled_dev_machine.automation import install_automation
from controlled_dev_machine.config import (
    create_host_config,
    default_config_path,
    ensure_invoking_target,
    load_host_config,
)
from controlled_dev_machine.doctor import overall_level, run_doctor
from controlled_dev_machine.errors import ControlledDevMachineError
from controlled_dev_machine.policy import load_policy
from controlled_dev_machine.review import RequestStore, ReviewRecord
from controlled_dev_machine.runtime import (
    audit_status,
    compose_build,
    compose_shell,
    compose_start_closed,
    compose_status,
    compose_stop,
    prepare_parent_guard,
    prepare_runtime,
)
from controlled_dev_machine.session_migration import import_claude_session
from controlled_dev_machine.storage import build_storage_report, rotate_audit
from controlled_dev_machine.traffic_analysis import analyze_review_payload
from controlled_dev_machine.verification import run_closed_gate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sandboxctl")
    parser.add_argument(
        "--config", type=Path, default=None, help="主机配置；默认使用调用者 Home 下的配置"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    config_parser = subparsers.add_parser("config", help="主机配置操作")
    config_sub = config_parser.add_subparsers(dest="config_command", required=True)
    config_sub.add_parser("init", help="按当前宿主账号生成不覆盖已有文件的配置")
    config_sub.add_parser("validate", help="验证主机配置")

    init_parser = subparsers.add_parser("init", help="生成当前主机的受控运行环境")
    init_parser.add_argument(
        "--policy",
        type=Path,
        default=Path("policies/strict/0001-bootstrap.yaml"),
        help="要部署的 strict 或 daily 策略快照",
    )
    subparsers.add_parser("build", help="构建固定版本的目标和网关镜像")
    subparsers.add_parser("guard", help="在启动父代理前安装仅回环可访问的宿主门禁")
    subparsers.add_parser("start", help="启动当前受控环境")
    subparsers.add_parser("stop", help="停止本实例，不删除持久状态")
    subparsers.add_parser("status", help="显示本实例容器状态")
    subparsers.add_parser("shell", help="以普通用户进入目标容器")
    subparsers.add_parser("root-shell", help="从宿主以 root 进入目标容器")
    subparsers.add_parser("verify-closed", help="运行无公网出口的封闭门禁检查")

    automation_parser = subparsers.add_parser("automation", help="安装自动启动与审计轮转")
    automation_sub = automation_parser.add_subparsers(
        dest="automation_command", required=True
    )
    automation_sub.add_parser("install", help="写入并启用本实例的 systemd 自动化 unit")

    doctor_parser = subparsers.add_parser("doctor", help="只读检查当前主机")
    doctor_parser.add_argument("--json", action="store_true", help="输出 JSON")

    storage_parser = subparsers.add_parser("storage", help="只读存储检查")
    storage_sub = storage_parser.add_subparsers(dest="storage_command", required=True)
    storage_sub.add_parser("plan", help="生成占用与清理候选报告，不执行删除")
    storage_sub.add_parser("rotate", help="删除已结束且超过保留期的本项目审计数据")

    audit_parser = subparsers.add_parser("audit", help="审计状态")
    audit_sub = audit_parser.add_subparsers(dest="audit_command", required=True)
    audit_sub.add_parser("status", help="显示当前 PCAP/eBPF 审计进程")

    session_parser = subparsers.add_parser("session", help="Claude 会话操作")
    session_sub = session_parser.add_subparsers(dest="session_command", required=True)
    session_import = session_sub.add_parser("import", help="脱敏迁入一个宿主 Claude 会话")
    session_import.add_argument("source_session_id")
    session_import.add_argument("--new-id", default=None, help=argparse.SUPPRESS)

    policy_parser = subparsers.add_parser("policy", help="策略快照操作")
    policy_sub = policy_parser.add_subparsers(dest="policy_command", required=True)
    for name in ("validate", "digest"):
        item = policy_sub.add_parser(name)
        item.add_argument("path", type=Path)

    review_parser = subparsers.add_parser("review", help="请求审核队列")
    review_sub = review_parser.add_subparsers(dest="review_command", required=True)
    review_sub.add_parser("list")

    show_parser = review_sub.add_parser("show")
    show_parser.add_argument("request_id")
    show_parser.add_argument("--raw", action="store_true")

    analyze_parser = review_sub.add_parser("analyze")
    analyze_parser.add_argument("request_id")

    enqueue_parser = review_sub.add_parser("enqueue")
    enqueue_parser.add_argument("--policy-digest", required=True)
    enqueue_parser.add_argument("--scheme", choices=("http", "https"), required=True)
    enqueue_parser.add_argument("--host", required=True)
    enqueue_parser.add_argument("--port", type=int, required=True)
    enqueue_parser.add_argument("--method", required=True)
    enqueue_parser.add_argument("--path", required=True)
    enqueue_parser.add_argument("--header", action="append", default=[])
    enqueue_parser.add_argument("--body-file", type=Path)

    approve_parser = review_sub.add_parser("approve-once")
    approve_parser.add_argument("request_id")
    approve_parser.add_argument("--ttl", type=int, default=60)
    approve_parser.add_argument("--reason", required=True)

    reject_parser = review_sub.add_parser("reject")
    reject_parser.add_argument("request_id")
    reject_parser.add_argument("--reason", required=True)

    consume_parser = review_sub.add_parser("consume")
    consume_parser.add_argument("request_id")
    consume_parser.add_argument("--request-sha256", required=True)
    consume_parser.add_argument("--policy-digest", required=True)

    review_sub.add_parser("expire")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except ControlledDevMachineError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2


def _run(args: argparse.Namespace) -> int:
    if args.command == "policy":
        policy = load_policy(args.path)
        if args.policy_command == "validate":
            print(f"有效: {policy.policy_id} revision={policy.revision} digest={policy.digest()}")
        else:
            print(policy.digest())
        return 0

    config_path = (args.config or default_config_path()).expanduser()
    if args.command == "config" and args.config_command == "init":
        create_host_config(config_path)
        print(f"已生成主机配置: {config_path}")
        return 0
    config = load_host_config(config_path)
    ensure_invoking_target(config)

    if args.command == "config":
        print(
            f"有效: instance={config.instance} target={config.target.name} "
            f"resource_prefix={config.resource_prefix}"
        )
        return 0

    if args.command == "init":
        manifest = prepare_runtime(config, args.policy)
        print(
            f"已初始化受控环境: {manifest.resource_prefix}\n"
            f"策略: {manifest.policy_digest}\n"
            f"Compose: {manifest.compose_path}"
        )
        return 0

    if args.command == "build":
        compose_build(config)
        print("目标镜像和策略网关镜像构建完成")
        return 0

    if args.command == "guard":
        prepare_parent_guard(config)
        print("父代理门禁已安装；当前只允许宿主回环访问")
        return 0

    if args.command == "start":
        compose_start_closed(config)
        if config.upstream.kind == "unset":
            print("受控环境已启动；当前没有公网上游")
        else:
            print("受控环境已启动；外部请求必须经本机上游代理")
        return 0

    if args.command == "stop":
        compose_stop(config)
        print("本实例已停止；持久 Home、策略、证据和证书均保留")
        return 0

    if args.command == "automation" and args.automation_command == "install":
        paths = install_automation(config)
        print("已安装并启用自动化 unit:")
        for path in paths:
            print(path)
        print("当前运行实例未重启；自动启动和轮转从下次 systemd 启动/计时器触发时生效")
        return 0

    if args.command == "status":
        print(compose_status(config), end="")
        return 0

    if args.command == "verify-closed":
        print(json.dumps(run_closed_gate(config), indent=2, sort_keys=True, ensure_ascii=False))
        return 0

    if args.command in {"shell", "root-shell"}:
        return compose_shell(config, root=args.command == "root-shell")

    if args.command == "doctor":
        checks = run_doctor(config)
        if args.json:
            print(
                json.dumps(
                    {
                        "overall": overall_level(checks).name.lower(),
                        "checks": [check.as_json() for check in checks],
                    },
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                )
            )
        else:
            for check in checks:
                print(f"{check.level.name:<7} {check.name}: {check.message}")
        return 0 if overall_level(checks).value < 2 else 1

    if args.command == "storage":
        if args.storage_command == "plan":
            report = build_storage_report(config)
            print(json.dumps(report.as_json(), indent=2, sort_keys=True, ensure_ascii=False))
        else:
            result = rotate_audit(config)
            print(json.dumps(result.as_json(), indent=2, sort_keys=True, ensure_ascii=False))
        return 0

    if args.command == "audit" and args.audit_command == "status":
        print(json.dumps(audit_status(config), indent=2, sort_keys=True, ensure_ascii=False))
        return 0

    if args.command == "session" and args.session_command == "import":
        result = import_claude_session(
            source_home=config.target.home,
            persistent_home=config.paths.persistent_home,
            target_home=config.target.home,
            target_uid=config.target.uid,
            target_gid=config.target.gid,
            source_session_id=args.source_session_id,
            new_session_id=args.new_id,
        )
        print(json.dumps(result.as_json(), indent=2, sort_keys=True, ensure_ascii=False))
        return 0

    store = RequestStore(config.paths.review)
    if args.review_command == "list":
        for record in store.list_records():
            print(
                f"{record.request_id} {record.state:<13} {record.method} "
                f"{record.scheme}://{record.host}:{record.port}{_redacted_path(record.path)}"
            )
        return 0
    if args.review_command == "show":
        record = store.get(args.request_id)
        result: dict[str, object] = {
            "record": asdict(record) if args.raw else _safe_record(record)
        }
        if args.raw:
            headers, body = store.raw(args.request_id)
            result["headers"] = list(headers)
            result["body_utf8"] = body.decode("utf-8", errors="replace")
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    if args.review_command == "analyze":
        record = store.get(args.request_id)
        headers, body = store.raw(args.request_id)
        result = {
            "record": _safe_record(record),
            "analysis": analyze_review_payload(
                headers,
                body,
                target_home=str(config.target.home),
                target_name=config.target.name,
            ),
        }
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    if args.review_command == "enqueue":
        headers = _headers(args.header)
        body = args.body_file.read_bytes() if args.body_file else b""
        record = store.enqueue(
            policy_digest=args.policy_digest,
            scheme=args.scheme,
            host=args.host,
            port=args.port,
            method=args.method,
            path=args.path,
            headers=headers,
            body=body,
        )
        print(json.dumps(_safe_record(record), indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    if args.review_command == "approve-once":
        record = store.approve_once(
            args.request_id, ttl_seconds=args.ttl, reason=args.reason
        )
    elif args.review_command == "reject":
        record = store.reject(args.request_id, reason=args.reason)
    elif args.review_command == "consume":
        record = store.consume_approval(
            args.request_id,
            request_sha256=args.request_sha256,
            policy_digest=args.policy_digest,
        )
    else:
        expired = store.expire_due()
        print(json.dumps({"expired": expired}, indent=2, ensure_ascii=False))
        return 0
    print(json.dumps(_safe_record(record), indent=2, sort_keys=True, ensure_ascii=False))
    return 0


def _headers(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values:
        if ":" not in item:
            raise ControlledDevMachineError("--header 必须使用 Name:Value 格式")
        name, value = item.split(":", 1)
        if not name.strip():
            raise ControlledDevMachineError("请求头名称不能为空")
        result[name.strip()] = value.lstrip()
    return result


def _safe_record(record: ReviewRecord) -> dict[str, object]:
    result = asdict(record)
    result.pop("request_sha256")
    result["path"] = _redacted_path(record.path)
    if record.content_type is not None:
        result["content_type"] = record.content_type.split(";", 1)[0].strip()
    return result


def _redacted_path(value: str) -> str:
    parsed = urlsplit(value)
    if not parsed.query:
        return parsed.path
    count = len(parse_qsl(parsed.query, keep_blank_values=True))
    return f"{parsed.path}?<redacted:{count}>"
