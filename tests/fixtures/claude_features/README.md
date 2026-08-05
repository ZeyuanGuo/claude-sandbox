# Claude Code 扩展功能 fixture

这组文件用于在一次性项目中复测 Claude Code 的 MCP、hook、Skill 和自定义 agent。它没有凭据，不应装入真实项目。

## 安装到测试项目

在控制仓库根目录执行。`CDM_TEST_PROJECT` 指向宿主持久 Home 中的测试项目，其他主机只需改这个值：

```bash
CDM_FIXTURE_ROOT="$PWD/tests/fixtures/claude_features"
CDM_TEST_PROJECT="$HOME/.local/share/controlled-dev-machine/home/claude-api-key-test"

install -d -m 700 \
  "$CDM_TEST_PROJECT/.claude/fixtures" \
  "$CDM_TEST_PROJECT/.claude/skills/sandbox-fixture" \
  "$CDM_TEST_PROJECT/.claude/agents"
install -m 600 "$CDM_FIXTURE_ROOT/mcp_server.py" \
  "$CDM_TEST_PROJECT/.claude/fixtures/mcp_server.py"
install -m 600 "$CDM_FIXTURE_ROOT/hook_logger.py" \
  "$CDM_TEST_PROJECT/.claude/fixtures/hook_logger.py"
install -m 600 "$CDM_FIXTURE_ROOT/settings.local.json" \
  "$CDM_TEST_PROJECT/.claude/settings.local.json"
install -m 600 "$CDM_FIXTURE_ROOT/skills/sandbox-fixture/SKILL.md" \
  "$CDM_TEST_PROJECT/.claude/skills/sandbox-fixture/SKILL.md"
install -m 600 "$CDM_FIXTURE_ROOT/agents/fixture-reviewer.md" \
  "$CDM_TEST_PROJECT/.claude/agents/fixture-reviewer.md"
install -m 600 "$CDM_FIXTURE_ROOT/mcp.project.json" \
  "$CDM_TEST_PROJECT/.mcp.json"
```

`.mcp.json` 使用项目相对路径。MCP 子进程从受控开发机继承代理和 CA，不需要写入主机专用路径。

fixture 的事件文件是本地审计证据，不应提交到测试项目。安装后把下面两行加入该项目的 `.git/info/exclude`，不修改共享 `.gitignore`：

```text
.claude/hook-events.jsonl
.claude/mcp-events.jsonl
```

hook 只保存 session ID 的 SHA-256，不保存原始关联标识。

## 验收

进入测试项目后直接运行 `claude`，依次确认：

1. `/mcp` 显示 `sandbox-fixture` 已连接；
2. MCP echo 返回 `MCP_CANARY`，Python 文档请求成功，元数据域名请求被 403 阻断；
3. MCP resource 和 `/mcp__sandbox-fixture__review-sandbox-change` 可用；
4. `/sandbox-fixture` 返回 `SKILL_CANARY:controlled`；
5. `fixture-reviewer` 子 agent 返回 `SUBAGENT_CANARY:controlled`；
6. `.claude/hook-events.jsonl` 和 `.claude/mcp-events.jsonl` 记录了对应事件。

外层同时检查 mitmproxy 明文、目标 `connect.log` 和双侧 PCAP。fixture 通过只说明扩展机制及审计路径正常，不代表其他第三方扩展已经获得信任。

报告已提取并归档所需证据后，可以只删除这两个事件文件。MCP、Skill、agent 和 hook 配置是否保留由测试项目用途决定，不要用递归删除清理整个 `.claude`。
