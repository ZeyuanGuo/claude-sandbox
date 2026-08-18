# Claude Code 使用与审计手册

这份文档保存 Claude Code 的完整操作和审计边界。只想进入 shell、恢复会话或判断何时检查流量时，先看 [用户使用指南](../user-guide.md)。底层部署命令见 [部署与操作](../operations.md)，已完成测试和结论边界见 [公开验收摘要](../validation.md)。

## 当前状态

| 项目 | 当前结论 |
|---|---|
| Claude Code | `2.1.220`，`linux-x64`，SHA-256 `674f61f2...a89c863` |
| 认证与模型 | API-key 已验证一个固定模型基线；私有模型别名不发布；账号登录需单独验收 |
| 可用策略 | 严格账号发现策略 `strict/0002`；公共 Web 日常策略 `daily/0001`；实际活动策略看运行清单 |
| 使用方式 | 从容器 Bash 直接运行 `claude`；无需代理参数 |
| 默认开发环境 | 由每台主机的 `profile.default_conda_env` 和同路径挂载决定 |
| 已覆盖 | 对话、文件读写、测试、Git、curl、WebSearch、WebFetch、会话恢复、Skill、子 agent、MCP 工具/资源/prompt、hook |
| 当前未覆盖 | 完整账号授权及后续任务，以及本机未启用的第三方插件、LSP、Chrome、遥测和远程控制 |

历史 API-key 基线使用的私有模型端点和规则不进入仓库；需要私有端点时，应在本机创建新的策略版本并重新验收。发布日常策略不会放行未登记的直接 IP。

已测基线用本地 fixture 验证了常见扩展机制；这不表示任意未来扩展已经获准。认证方式、版本或联网组件改变后，要建立新的检测基线。

2026-07-29 已完成从显式代理到透明网络的迁移。封闭门禁、受控 DoH、DNS 租约、系统/Conda CA、curl、Python、Node 和审计失效闭锁均已实测。完整 Claude 功能正面证据仍来自 API-key 基线；账号模式要在真实授权后重新测试，不能用基础网络通过代替功能通过。

## 宿主配置与工具同步

容器的整个目标用户 Home 使用宿主固定目录 `~/.local/share/controlled-dev-machine/home` 的读写 bind mount；不使用 Docker anonymous volume 或临时存储。因此容器内 `~/.claude`、会话数据库、history、memory、插件状态和账号状态都能直接在宿主对应目录中备份、迁移或重新挂载。全局 `CLAUDE.md` 由仓库配置和宿主提示词生成初始内容，但现在以读写方式挂入容器；`.bashrc`、`.profile`、`.gitconfig` 和 `.tmux.conf` 仍是只读受控副本。

`host.yaml` 在每次 `init` 时同步下面的行为配置：

- 宿主 `~/.claude/CLAUDE.md` 与仓库中的沙箱网络约束合并，作为容器可编辑的全局提示词初始内容；
- 宿主 `.bashrc`、`.profile`、`.gitconfig` 和 `.tmux.conf` 生成受控副本；
- `~/.claude/skills`、`~/.claude/agents` 和 `~/.agents/skills` 读写同路径挂载，便于容器内安装或更新技能与 agent；
- 目标镜像固定安装 Codex CLI；整棵宿主 `~/.codex` 以同路径读写挂载，因此 Codex 的配置、登录状态、会话和 skills 与宿主共用；
- Git 直接使用宿主 `~/.config/git` 读写目录，Conda 配置直接使用宿主 `.condarc` 读写；SSH 仍使用宿主 `.ssh` 只读目录，避免改写关键私钥；
- 主机选择的 Conda 根目录以相同绝对路径读写挂载，默认环境由 `profile.default_conda_env` 指定。

本机同时用 `profile.conda_root` 声明 `~/miniconda3`。其他服务器可以使用不同 Conda 根目录；未声明时只采用该服务器 `.bashrc` 已初始化的环境，不猜测安装位置。

生成器保留宿主 alias、Conda、NVM 等 shell 行为，但会在最后清除大小写代理变量、Git 代理和专用 CA 路径。网关根证书合入系统、Conda OpenSSL 和 certifi 的标准信任文件，Node 使用系统 CA。profile 源必须位于用户 Home、由该用户拥有且不是符号链接。宿主 profile 变化后必须重新执行 `init`；运行清单保存宿主源摘要和不可编辑 profile 文件摘要，容器内编辑 `CLAUDE.md` 不会被误判为运行文件损坏，并会保留到下一次 `init`。

容器内可以直接编辑 `~/.claude/CLAUDE.md`。它是提示词和工作约定，不是网络强制边界；网络控制仍由网关、DNS、nftables 和审计链路执行。重新执行 `init` 会用仓库配置和宿主 `~/.claude/CLAUDE.md` 重新生成初始版本，因此要把稳定的通用修改纳入发布时，应审阅后更新仓库的 `config/claude/CLAUDE.md` 并提交，而不要把运行时生成目录直接提交。

没有同步整个宿主 `.claude`。沙箱单独保存 Claude 的提供方、账号状态、设备标识和会话历史。此前 API-key 基线使用一个固定模型；私有别名不进入发布仓库，旧结果只作为历史基线。

Codex CLI `0.147.0` 在目标镜像中固定；首次使用仍需在容器中完成自己的登录。登录凭据不进入镜像或仓库，而是写入宿主 `~/.codex`，并通过整棵目录挂载到容器。Codex 的本地命令沙箱配置也随该目录共享；外部网络仍由本项目透明网关控制。

每台主机的 Python、PyTorch、CUDA、GPU、Git、tmux 和 Node 环境都可能不同。迁移后必须检查容器内实际可执行文件、关键 import 和 GPU 计算，不能继承源主机结论。失效的 Skill 或 agent 链接也不会因为挂载自动变成可用能力。

## 开始一次日常使用

沙箱持续运行时，在宿主直接执行 `sudo bin/sandboxctl shell`。环境刚启动或切换过策略、准备长时间使用、请求被阻断或新增联网组件时，再完整检查：

```bash
cd "$HOME/claude-sandbox"
sudo bin/sandboxctl status
sudo bin/sandboxctl audit status
sudo bin/sandboxctl shell
```

开始前检查：

1. `target`、`dns`、`gateway` 和 `canary` 正常运行，带健康检查的服务为 `healthy`。
2. `audit status` 的 `active` 是 `true`，五个探针/监督进程都是 `alive: true`。
3. `observed_upstream_ip` 落在本机 `upstream.expected_exit_cidr` 内。
4. 记下 `run_id` 和开始时间，便于使用后只分析本次窗口。

进入容器后，像普通开发机一样使用：

```bash
cd "$HOME/project"              # 或其他已挂载项目
echo "$CONDA_PREFIX"
command -v python
python -c 'import torch; print(torch.__version__, torch.cuda.is_available())'
claude
# 或
codex
```

不需要附加 `--tools`、测试参数或特殊启动器。当前持久配置已经保存默认模型。退出 Claude 或容器 shell 不会停止沙箱和审计；需要停止整套环境时回到宿主执行 `sudo bin/sandboxctl stop`。

`command -v python` 必须指向本机配置的环境目录。如果 `CONDA_DEFAULT_ENV` 显示目标环境，但可执行文件仍指向 base，环境没有正确激活，不能继续用“环境名正确”代替包和 GPU 验证。

需要维护容器系统文件时，从宿主执行：

```bash
sudo bin/sandboxctl root-shell
```

容器普通用户可以使用 `sudo`，密码与当前宿主账号一致；不要把密码、API key 或账号令牌写进仓库、策略或普通报告。宿主密码变更后执行 `stop -> init -> build -> start -> verify-closed`。

## 公共 Web 日常网络行为

公开仓库中的日常策略处理方式如下：

| 请求 | 处理 |
|---|---|
| 普通公网域名 HTTP/80、HTTPS/443 | 外层透明接管；目标 IP 匹配 DNS 租约后放行并保存明文 |
| 外部 DNS、UDP/QUIC、SSH 和其他非 Web 协议 | 阻断 |
| 直接 IP、特殊主机名、已登记 DoH | 默认阻断；发布策略没有模型直连例外 |
| 原始 TCP、HTTP Upgrade、应用层 `CONNECT`、上游 `101` | 阻断 |
| TLS 无法解密或策略/审核存储异常 | 本地失败，不改为密文直通 |

WebSearch 的搜索主要在模型服务端执行。WebFetch 会先访问 Anthropic 的域名检查接口，再读取目标网页。curl、Git HTTPS 和联网 MCP 子进程按普通服务器方式联网，由外层透明接管；它们不继承代理变量或专用 CA 路径。工具在本地读取的文件、输出和差异可能在下一轮模型请求中发送。

## 请求被阻断时

先不要修改容器代理、CA、DNS 或网络。记录失败时间、项目目录、正在执行的功能、预期目标和错误信息，然后在宿主检查：

```bash
cd "$HOME/claude-sandbox"
sudo bin/sandboxctl status
sudo bin/sandboxctl audit status
sudo bin/sandboxctl review list
```

根据情况处理：

| 现象 | 操作 |
|---|---|
| 严格策略产生 `pending` 请求 | 保持原命令运行，先脱敏分析，再一次性批准或拒绝 |
| 日常策略中的普通公网网页失败 | 检查网关健康、TLS、目标是否为公网域名，以及是否命中明确阻断规则 |
| 直接 IP、SSH、UDP、外部 DNS 或非 Web 协议失败 | 这是预期边界；不要为了让功能运行而在容器内绕过 |
| 新插件、MCP 或后台组件需要联网 | 切回严格策略，用可公开项目单独复现和解释流量 |
| 审计探针死亡、出口变化或记录无法关联 | 停止扩大使用，保留当前运行和日志，先修复审计条件 |

严格策略中的待审核请求这样处理：

```bash
sudo bin/sandboxctl review analyze REQUEST_ID
sudo bin/sandboxctl review show REQUEST_ID --raw
sudo bin/sandboxctl review approve-once REQUEST_ID --ttl 60 --reason '当前测试用例需要'
# 或
sudo bin/sandboxctl review reject REQUEST_ID --reason '目标或正文无法解释'
```

先使用 `analyze`。它隐藏凭据值，只报告正文结构、哈希和机器特征。`show --raw` 包含完整认证头、源码和对话，只在必须逐字核对时使用，输出不能进入普通报告。

一次批准只绑定当前请求正文哈希、当前策略和短有效期，不是永久白名单。`authorized` 只表示网关已经消费批准；收到上游响应后才是 `completed`。如果客户端已经断开，该请求会进入 `client_disconnected`，不能拿旧批准放行重试产生的新请求。

## 切换严格与日常策略

出现新认证方式、Claude 版本、联网插件、MCP、hook、LSP、Chrome、遥测或无法解释的后台目标时，先切回严格策略：

```bash
cd "$HOME/claude-sandbox"
sudo bin/sandboxctl stop
sudo bin/sandboxctl init --policy policies/strict/0002-claude-account.yaml
sudo bin/sandboxctl build
sudo bin/sandboxctl start
sudo bin/sandboxctl verify-closed
```

完成流量解释、真实任务和门禁回归后，才能切换到公共 Web 日常策略：

```bash
sudo bin/sandboxctl stop
sudo bin/sandboxctl init --policy policies/daily/0001-public-web.yaml
sudo bin/sandboxctl build
sudo bin/sandboxctl start
sudo bin/sandboxctl verify-closed
```

切换会重建容器和网络，但保留持久 Home、项目与历史审计。只有控制源码或镜像内容改变时才需要重新 `build`。私有 API 端点不在发布策略中；需要时必须在本机新增策略并单独测试。

## 调整长期策略

严格模式中的 `approve-once` 只用于发现，不应当成为日常操作负担。确认一类流量确实必要后，按下面过程形成新策略：

1. 在允许公开的一次性项目中重现请求，记录软件版本、功能、进程、目标、正文类型和审核编号。
2. 说明为什么该请求属于正常功能，并确认没有任务外目标、不合理机器信息、异常上传或二次加密。
3. 复制最近的策略到新的递增文件；不要修改已经使用过的策略文件。
4. 用旧策略的完整 SHA-256 填写新文件的 `parent_digest`，更新 `policy_id`、`revision`、`created_at`、规则和 `evidence`。
5. 校验并记录新摘要：

```bash
bin/sandboxctl policy digest policies/daily/0001-public-web.yaml
bin/sandboxctl policy validate policies/daily/NEW_POLICY.yaml
bin/sandboxctl policy digest policies/daily/NEW_POLICY.yaml
```

6. 使用 `stop -> init --policy -> build -> start -> verify-closed` 部署新策略，再重跑产生该流量的真实任务和相邻阻断测试。
7. 把策略文件、变更原因、测试结论和回滚目标一起提交。出现泄露或回归时，重新部署上一份策略快照，而不是反向修改历史文件。

当前控制器没有自动生成或编辑策略的命令；策略变更需要人工审查 YAML。日常策略已经默认允许受审计的普通公网 Web，因此增加普通网页通常不需要新增域名规则。直接 IP、非标准端口和非 Web 协议仍需要更高证据，不能靠一条宽泛规则放开。

## 增加 MCP、插件或其他扩展

项目自己的 `.mcp.json`、`.claude/settings.local.json`、`.claude/skills/` 和 `.claude/agents/` 随项目持久化。配置应使用项目相对路径，不引用宿主审计目录或控制器内部路径。

新增扩展时：

1. 切回严格策略，并使用不含秘密的一次性项目。
2. 固定扩展版本、启动命令、权限、环境变量和预期目标。
3. 分别测试启动、正常调用、失败重试、空闲后台行为和退出。
4. 对每个新请求关联发起进程、DNS 记录、代理明文和三处 PCAP。
5. 确认功能输出后，再决定恢复原日常策略、创建新策略或继续阻断。

可迁移的 MCP、hook、Skill 和子 agent 验收夹具位于 `tests/fixtures/claude_features/`。它用于证明机制可运行和可审计，不代表第三方扩展自动可信。

## 使用后怎样审查

先记录结束时间，再检查运行仍然完整：

```bash
sudo bin/sandboxctl audit status
sudo bin/sandboxctl status
```

宿主审计目录包含：

| 证据 | 用途 |
|---|---|
| `plaintext/flows.mitm` | HTTP/HTTPS 请求正文、双向头字段、响应状态和传输结果；不缓存响应正文 |
| `pcap/RUN_ID/target.pcap` | 目标容器实际产生的数据包 |
| `pcap/RUN_ID/dns.pcap` | 受控 DNS 到目标和父代理的数据包 |
| `pcap/RUN_ID/gateway.pcap` | 网关到父代理方向的数据包 |
| `structured/RUN_ID/connect.log` | 目标 cgroup 中的进程执行和连接结果 |
| `runtime/dns/queries.jsonl` | DNS 原文、解析地址、租约和 DoH 出口标记 |

按使用时间窗检查新增目标、请求量、非 Web 尝试、机器信息和无法解释的正文。正常结论至少要能对应“哪个进程、连接到哪里、PCAP 是否存在、网关看到了什么正文、功能产生了什么结果”。失败连接可能在发包前返回，此时有 eBPF 记录而没有 PCAP 是正常现象。

原始证据只能从宿主提权读取。报告保留目标、类型、长度、哈希和结论，不复制 API key、Cookie、认证头、完整源码或长对话。审计原理、文件权限和未覆盖条件见 [默认审计](../audit.md)。

## 当前已知结果

API-key 完整功能基线中，已观察的业务流量只有模型接口、Anthropic 域名检查、Python 文档和 GitHub；没有发现任务外公网目标或非 Web 外连。Claude 正常请求会发送：

- 沙箱内核版本、平台、架构和当前日期；
- 当前项目绝对路径、Claude memory 路径和 Git 快照；
- 客户端版本、设备/会话标识；
- 对话、工具定义、参数、输出、读取文件和差异。

当前测试没有看到实际时区值、CPU/GPU、内存、MAC、容器或宿主 IP、代理变量和 CA 路径。正文中出现 `timezone` 等单词可能来自测试提示或工具说明，不能把关键词命中直接写成泄露。

第一轮独立审查发现的原始 TCP、HTTP Upgrade、上游 `101`、旧式数字 IPv4 和特殊域名顶点问题已经修复。透明迁移又补上了受控 DoH、DNS-IP 租约和审计失效自动闭锁。当前结论是“API-key 基线可用，透明网络基础能力通过，账号模式待真实授权”，不是对所有未来版本、插件和高负载协议的永久安全证明。

## 下一阶段：账号登录

账号登录由用户提供账号并在自己的浏览器完成授权。开始前必须切回严格策略，然后像平时一样运行：

```bash
claude
```

当前严格策略会自动放行已经实测无正文的 `/api/hello`、`/v1/oauth/hello` 和固定官方 changelog，阻断但记录事件上报；真正的代码交换、令牌刷新和其他新请求仍进入一次性审核。沙箱不开放浏览器或 Web 端口。授权 URL、代码交换、令牌刷新、退出和错误重试要分别审核；报告只保存字段类型、长度和哈希，不保存 OAuth 代码、令牌、Cookie 或认证头。账号登录流程仍需在部署主机用实际账号完成独立验收。

账号登录尚未完成，预期步骤和未完成边界见 [公开验收摘要](../validation.md)。

登录后重新测试对话、文件修改、测试、Git、WebSearch、WebFetch、curl、子 agent、会话恢复、Skill、MCP、hook 和空闲观察。完成实际使用窗口并解释所有新增流量后，才能建立账号模式自己的日常策略。

## 必须停止扩大的情况

- 任一审计探针不再存活，网关不健康或出口变化；
- 出现未登记的直接连接、DNS、UDP、非 Web 流量或后台目标；
- TLS 无法解密、正文再次加密或连接、PCAP、明文无法关联；
- 请求发送了任务不需要的机器信息、凭据或项目内容；
- 新版本或扩展的行为与当前基线不一致。

任一登记 tcpdump 或 eBPF 探针死亡后，watchdog 停止续期，网络放行项在 5 秒内过期。仍应主动检查 `audit status`，因为进程存活不能证明没有丢包、丢事件或磁盘问题。发现上述情况时保留现场，切回严格策略或停止环境，不在容器内临时放宽网络。
