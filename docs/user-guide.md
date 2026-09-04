# 用户使用指南

这份文档只写日常需要的操作。部署、策略设计和完整检测证据不在这里展开。

## 进入和退出

在宿主进入沙箱：

```bash
cd "$HOME/claude-sandbox"
sudo bin/sandboxctl shell
```

进入后就是普通开发 shell：

```bash
cd "$HOME/project"        # 或其他已挂载项目
claude
# 或
codex
```

容器 Home 固定映射到宿主配置的 `paths.persistent_home`，不是临时卷。Claude 的会话、历史、memory、账号状态和其他持久文件因此长期保存；容器内的 `~/.claude` 位于这棵持久 Home 中。不要把宿主原生 `~/.claude` 整棵目录覆盖进去，两套 Claude 账号/会话状态应保持隔离。Codex 则相反：整棵宿主 `~/.codex` 读写挂载到容器同路径，容器和宿主共用 Codex 配置、登录状态、会话和 skills。

默认配置生成器会创建宿主 `~/claude_code_config`，把 Claude 的提示词、设置、规则、skills 和 agents 分项读写挂载到容器 `~/.claude`，但不共享凭据、会话、历史和插件状态。宿主默认 `~/.claude` 不作为挂载源，直接运行 Claude Code 时不会自动读取共享目录。生成器也会自动创建并读写挂载宿主的 `~/.codex`，并在这些路径实际存在时同路径接入 `~/.agents/skills`、`~/.config/git` 和 `.condarc`；`.ssh` 仍只读以保护关键私钥。

文件、Git、Python、GPU、Skill、子 agent、MCP 和 Web 等开发流程已在 API-key 基线中验证。当前账号模式尚未完成整套验收；遇到阻断时按下文处理。退出 Claude 或 shell 不会停止沙箱，也不会删除会话。

首次使用前先按 [凭据与风险](credentials.md#claude-的三种接入方式) 选择账号登录、标准 API key 或私有 Base URL。发布策略不包含私有模型端点；不要为了登录或 API 调用在容器内设置代理或修改 DNS。

容器普通用户可以直接使用 `sudo`，密码与当前宿主账号一致。宿主密码变更后，执行 `stop -> init -> build -> start -> verify-closed`。若容器内 sudo 本身损坏，再从宿主执行 `sudo bin/sandboxctl root-shell` 修复。

## 恢复迁入的会话

迁入会话必须从导入结果记录的原工作目录恢复。例如当前用户 Home：

```bash
cd "$HOME"
claude --resume NEW_SESSION_ID
```

`NEW_SESSION_ID` 是 `sandboxctl session import` 输出的新编号，不是宿主原编号。迁入的旧文件历史只作为归档保存，不进入 Claude 的活动 rewind 目录；不要对迁入会话使用 `--rewind-files`。

迁移命令、脱敏范围和恢复边界见 [会话迁移](conversation-migration.md)。导入报告可能包含本机路径和运行编号，只保存在本机，不提交到 Git。

## 什么时候检查

沙箱持续运行且功能正常时，日常进入不需要逐条审核。下面情况再检查：

| 情况 | 要做的事 |
|---|---|
| 环境刚启动或切换过策略 | 检查服务、审计探针和出口 |
| 连续使用一段时间后 | 按本次时间窗复查目标、正文和非 Web 尝试 |
| 登录、请求或网页访问被阻断 | 先看状态和审核队列，不在容器内绕过 |
| 新增 MCP、插件、hook、LSP、浏览器或认证方式 | 切回严格策略，单独测试新增流量 |
| 功能正常但出现无法解释的后台请求 | 保留现场，停止扩大使用范围 |

状态检查都在宿主执行：

```bash
cd "$HOME/claude-sandbox"
sudo bin/sandboxctl doctor
sudo bin/sandboxctl status
sudo bin/sandboxctl audit status
```

重启或断网后的第一条命令始终是 `sudo bin/sandboxctl doctor`。如果它报告基础审计失活而四个容器仍在运行，执行 `sudo bin/sandboxctl audit restart`；如果容器缺失，执行 `sudo bin/sandboxctl recover`。这些恢复命令不会扩大到其他用户的容器或进程。

正常状态应满足：四个服务运行，DNS、网关和 canary 为 `healthy`；`audit status` 的 `active` 为 `true`；五个探针/监督进程和三个 `namespaces` 项均为 `alive: true`；出口落在 `host.yaml` 的 `upstream.expected_exit_cidr` 内。

## 请求被阻断

先记下失败时间、项目目录、正在使用的功能和错误信息，然后在宿主执行：

```bash
sudo bin/sandboxctl review list
sudo bin/sandboxctl review analyze REQUEST_ID
```

`analyze` 隐藏凭据值，报告正文结构、哈希和机器特征。只有确实需要逐字检查时才使用：

```bash
sudo bin/sandboxctl review show REQUEST_ID --raw
```

原始内容可能包含 API key、Cookie、源码和完整对话，不能贴进普通报告。严格模式下确认请求合理后，可一次性放行当前请求：

```bash
sudo bin/sandboxctl review approve-once REQUEST_ID --ttl 60 --reason '当前功能需要'
# 或拒绝
sudo bin/sandboxctl review reject REQUEST_ID --reason '目标或正文无法解释'
```

如果审核队列为空但终端提示域名解析失败，先记录失败时间并检查 `runtime/dns/queries.jsonl`。普通公网域名默认可解析；私网、保留地址、异常查询类型或上游解析失败会在 DNS 层失败。不要在容器内改 DNS。

日常模式不会为普通公网 Web 请求创建逐条审核记录。此时访问失败应先检查网关、DNS、审计状态和明确阻断规则；未经规则允许的直接 IP、SSH、UDP、外部 DNS 和非 Web 协议失败属于预期边界。容器内不设置 `HTTP_PROXY`、`HTTPS_PROXY` 或自定义 DNS。

## 使用一段时间后分析流量

先记录使用的起止时间、项目、主要任务和 `audit status` 中的 `run_id`。按下面顺序检查本次窗口：

1. 从 `runtime/dns/queries.jsonl` 汇总域名、解析结果、DNS 租约和 DoH 出口标记。
2. 从 `plaintext/flows.mitm` 汇总新增域名、方法、路径类型、状态码和请求量，区分健康检查与业务请求。
3. 从 `structured/RUN_ID/connect.log` 检查发起进程、失败直连、DNS、UDP 和非 Web 尝试。
4. 在解密后的请求正文中检查任务外文件、凭据、主机特征、异常大上传和无法解释的编码或二次加密。响应正文默认不保存。
5. 用 `pcap/RUN_ID/target.pcap*`、`dns.pcap*` 和 `gateway.pcap*` 确认解析与 Web 流量都走受控路径；这些文件会按主机配置循环覆盖，无法对应的流量保持阻断或切回严格策略复现。

这些原始文件只能从宿主提权读取。详细字段解释、证据边界和报告要求见 [默认审计](audit.md)；Claude 已知业务流量和机器信息结论见 [Claude Code 使用与审计手册](targets/claude-code.md)。

如果不想自己读取原始证据，只需保留起止时间、`run_id`、项目、主要任务和异常现象，再让维护者按这个窗口分析。

## 切换策略

新认证方式或新增联网组件先切回严格策略；完成解释和回归后再恢复日常策略。具体命令见 [部署与操作](operations.md#严格与日常策略)。策略切换会重建容器和网络，但保留项目、持久 Home、会话和审计记录。
