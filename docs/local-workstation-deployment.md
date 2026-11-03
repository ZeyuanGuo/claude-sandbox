# 本机透明工作站部署记录

## 原始目标

在受控开发机基础上部署长期 Claude 开发容器。容器固定 Ubuntu 版本、英文区域设置、中性容器身份和受控出口；保留 PID、网络与系统文件隔离，不暴露宿主实际主机名或把配置时区声明成物理位置。宿主 Home 与 `/data` 在容器内同路径读写，用户级工具链和工作文件即时共享。容器只通过 `25600-25700/tcp` 向宿主提供服务，并持续保存 Claude API/Web 流量证据。

## 计划

1. 扩展配置模型，支持共享宿主 Home 与显式服务端口段。
2. 调整 Compose 和目标 nftables，使端口发布与入站策略一致。
3. 补齐 Python、Rust、Go 和无头浏览器所需的镜像工具链。
4. 生成本机配置，构建并启动严格策略环境。
5. 验证身份隔离、目录读写、工具链、GPU、端口回环与审计闭锁。
6. 切换日常策略，运行 Claude CLI/API 任务并分析 DNS、明文流和 PCAP。

## 当前状态

- 2026-08-06：参考仓库已克隆到 `/home/gzy/claude-sandbox`，基线为 `main@96f3891`。
- 2026-08-06：共享 Home、端口段、shell 提示、工具链依赖和回归测试已实现；本机 `host.yaml` 已生成并通过配置校验。
- 2026-08-06：宿主控制器统一使用仓库 Python 3.12 venv；配置和运行时定向测试通过。
- 2026-08-06：发现宿主 jammy `skopeo 1.4` 与 Docker Engine 29 API 不兼容，已加入 Docker CLI digest pull 回退路径。
- 2026-08-06：发现共享 Home 下会话迁入仍写入未使用的持久 Home，已改为写入实际活动 Home，并补充回归覆盖。
- 2026-08-06：首次目标/网关镜像构建成功；镜像内 Claude Code 2.1.220、Python 3.12.3、Rust 1.75、Go、Xvfb、字体和 locale 已核对。
- 2026-08-06：完整测试、Ruff 和 `git diff --check` 通过；`25600-25700` 当前没有宿主监听冲突。
- 2026-08-06：修正 shell 提示的时区渲染和新 shell 重复显示语义。启动阶段因宿主 sudo 票据失效暂停，未声称完成运行态验收。
- 2026-08-06：配置解析器已强制共享 Home 模式下 `paths.state` 与 `paths.audit` 位于 Home 之外；本机配置满足该边界。
- 2026-08-06：独立容器探针确认共享 Home 与 `/data` 双向写入；`/data` 的既有 ext4、ZFS、NTFS 子挂载递归可见，NVM、Playwright 缓存和 Claude 状态可见。
- 2026-08-06：CDI 探针确认 4 张 NVIDIA GPU 均可见，计算模式保持 `Default`。
- 2026-08-06：发现 Docker 对 isolated internal bridge 只保存 `PortBindings` 而不创建宿主监听；改为宿主 socket 建立后进入目标 netns 的受控同号 relay。`25642` HTTP 真实链路通过，短时探针已停止并清理。
- 2026-08-06：strict 运行 `20260807T000800.485817Z-dd43b475` 完成 `verify-closed`；直接 IP、外部 DNS、UDP、原始 TCP、协议升级和审计故障路径均保持关闭，目标、DNS、网关 PCAP、eBPF、明文和 watchdog 在线。
- 2026-08-06：实际目标 shell 核对 `devbox`、PDT、Python 3.12.3、Node 24.18.0、npm 11.16.0、Rust/Cargo 1.75、Go 1.26.5、Claude Code 2.1.220；Docker socket 未暴露，PID 1 为容器 init。
- 2026-08-06：profile 生成器会在未声明 Conda 时跳过宿主无效的 Conda 初始化/自动激活，并跳过目标不存在的绝对 `source` 文件；本机生成结果不再触发 `conda: command not found` 或缺失 `.deno/env` 报错。
- 2026-08-06：最新源码全量测试、Ruff 和 `git diff --check` 再次通过。旧 strict 实例仍运行；包含 profile 清理的最终重建在 `stop` 阶段等待宿主刷新 `sudo` 凭据。
- 2026-08-07：最终 strict 运行 `20260807T012901.983479Z-0c322ffb` 通过完整 `verify-closed`；共享路径、端口 relay、4 张 GPU、CUDA Driver API 实算、工具链、无噪声 shell 和全部闭锁/审计路径均已现场核对。
- 2026-08-07：已停止 strict 并初始化 daily 策略。首次 daily 构建暴露 BuildKit 默认 provenance attestation 造成同一源码摘要对应不同 manifest/image ID；Compose v5.3.1 的 bake 转换会丢弃值为 false 的声明字段，因此控制器同时在实际 `compose build` 命令上强制 `--provenance=false --sbom=false`，并把该构建语义纳入目标镜像摘要。
- 2026-08-07：修正后的 target `1cd71b87...` 和 gateway `8c8211b1...` 连续两次构建得到相同 image ID，第二次构建通过既有 pin 检查；导出日志不再包含 attestation manifest。
- 2026-08-07：daily 运行 `20260807T020840.084583Z-ccef00f3` 通过完整 `verify-closed`，证据位于 `/var/log/controlled-dev-machine/gzy/audit/structured/20260807T020840.084583Z-ccef00f3/verify-closed.json`；PCAP、eBPF、明文、watchdog 和 service relay 全部在线。
- 2026-08-07：该 daily run 的 27 条 DNS 记录仅涉及门禁使用的 `api.anthropic.com`、`api.ipify.org`、`canary.test` 和 `example.com`；114 条明文 flow 中 102 条为健康检查，其余均为门禁请求。connect 记录和 target/gateway/dns PCAP 均与这些测试对应，没有额外域名、模型请求或未知上传。
- 2026-08-07：从宿主既有 Claude 设置生成 root-only 私有策略 `0001-claude-api.yaml`，策略摘要为 `c4d3e58be4aa659c49ec2511a14c3d481a31bb0a5bc631213986c8db1ccee93a`。该策略只增加一个精确 API 地址、一个 HTTP 端口、`POST /v1/messages*`、JSON 和 8 MiB 请求上限；真实地址、API key 和敏感请求头不进入仓库。
- 2026-08-07：私有 daily 运行 `20260807T022835.702684Z-3410ee06` 通过完整 `verify-closed`，证据位于 `/var/log/controlled-dev-machine/gzy/audit/structured/20260807T022835.702684Z-3410ee06/verify-closed.json`；私有策略没有放宽其他闭锁项。
- 2026-08-07：在仓库外 `/home/gzy/claude-sandbox-smoke` 建立 6 项端口段解析 fixture。headless Claude 在 7 个 turn 内实现 `normalize_port_range` 并运行测试；外层再次执行 `python3 -m unittest -v`，6 项全部通过，结果为 `success`，没有权限拒绝或 API 错误。
- 2026-08-07：smoke 时间窗为 `02:33:20.410-02:34:08.289 UTC`。明文审计记录同一 API 端点上的 1 次 `HEAD` 探测（策略拒绝为 403）和 5 次 `POST /v1/messages`（全部 200），无重试、额外域名、遥测端点或其他上传路径；5 个 JSON 请求正文为 4,199-11,074 字节，随工具上下文正常递增。
- 2026-08-07：该时间窗没有新增 DNS 记录，因为私有端点使用精确地址。目标 cgroup 新增 53 行审计事件，包括 2 次到 API 角色的非阻塞 TCP `connect`、6 次复用已连接 socket 的发送和任务所需的本地进程执行；另外 4 次失败连接均为本地 Unix socket 探测，没有 DNS、其他 Web 地址或异常端口连接。
- 2026-08-07：三处 PCAP 都可完整读取；时间窗内 target、gateway、dns 分别记录 1,295、1,572、143 个 IPv4/TCP 包。target 只有目标与 API 角色之间的两条连接；gateway 还记录其到宿主父代理的受控转发；dns 只有本地健康检查，没有 UDP 或新增解析流量。请求正文扫描未发现宿主实际主机名、控制/审计路径、Base URL 或 API key，只包含透明共享所需的 `/home/gzy` 工作路径；API key 仅存在于 root-only 明文证据的敏感请求头中。
- 2026-08-07：最终源码回归为 171 项测试通过，Ruff 和 `git diff --check` 通过。新交互 shell 再次显示中性身份、共享路径、`25600-25700` 服务范围和受控出口说明；canary、dns、gateway、target 四个服务保持运行，6 个审计/监督进程和 3 个网络命名空间全部存活，`audit active: true`。
- 2026-08-07：逐项目标完成审计重新读取当前运行态，而不是沿用前述结论。目标仍为非特权 `1001:1001`、Ubuntu 24.04.4、`devbox`、`America/Los_Angeles` 和 `en_US.UTF-8`；宿主实际 hostname、宿主 `/etc` 与 Docker socket 不可见。活动 target、gateway、profile 源摘要、镜像 tag 和镜像构建 label 全部匹配当前 manifest。
- 2026-08-07：`/home/gzy` 完成宿主到容器、容器到宿主双向写入。`/data` 根目录本身沿用宿主 POSIX 权限，不为容器额外放宽；其下 22 个既有 ext4、ZFS 和 fuseblk 子挂载全部可见，并在三类文件系统各选一个原本可写位置完成双向写入，探针文件均已清理。
- 2026-08-07：交互 shell 实测 Node 24.18.0、npm 11.16.0、Python 3.12.3、Go 1.26.5 和 Claude Code 2.1.220；Rust/Cargo、Git、ripgrep、tmux 等基础工具同时可用，宿主代理和自定义 CA 环境变量未泄漏。共享 Playwright 缓存中的 `chrome-headless-shell` 成功启动并渲染已知 DOM；4 张 GPU 分别完成 CUDA Driver API kernel 计算，结果全部正确。
- 2026-08-07：宿主 `/proc/net/tcp` 恰有 `25600-25700` 共 101 个 `0.0.0.0/tcp` 监听，逐端口握手全部成功。唯一 relay 已降权为 `65534:65534`，持有全部 101 个监听 socket inode，当前 netns 与 target 相同；在 25600、25650、25700 启动的临时容器回显服务均通过宿主同号访问，随后自动退出。
- 2026-08-07：完成审计再次确认私有策略与活动 manifest 摘要一致，20 项 `verify-closed` 检查全部通过。向三处在线 tcpdump 请求中间统计后，target、gateway、dns 的内核丢包计数均为 0；bpftrace 错误日志为空且无丢事件标记，审计继续 active。smoke 的唯一非业务观察是 API 客户端先发出一次被策略 403 的同端点 `HEAD` 探测，以及无 stdin 时的一行 CLI 警告；文件修改、5 次消息请求和测试均成功，因此没有扩大策略。流式响应正文不保存在 `.mitm` flow 中，响应状态、请求正文、传输字节和双侧 PCAP 仍完整保留，这是现有审计边界而非本次新增异常。
- 2026-08-07：完成审计后的最终门禁再次通过 171 项 pytest、Ruff、`git diff --check`、shell 语法、主机配置和活动 Compose 配置校验；`doctor --json` 的 24 项主机检查全部为 pass，没有 warning 或 blocked。私有 daily 环境继续在线，临时 root shell 和全部完成审计探针文件已清理。
- 2026-08-07：按部署任务范围追加一次只读日常工作复测，不再修改实现或创建提交。容器内 Claude 在 4 个 turn 中读取实现与测试、执行 `python3 -m unittest -v` 并给出结论；结果为 success，无 API 错误、权限拒绝或 stderr，外层哈希确认工作文件未变化，6 项测试再次通过。该窗口只有同一 API 角色的 2 次 `POST /v1/messages`（200）和 1 次 `HEAD` 探测（403），无额外业务主机、flow 错误或新增 DNS；四个服务连续运行约 6 小时并保持健康。
- 2026-08-08：拉取远端 `c95ed7f` 并与本机工作站配置合并，当前本地合并提交为 `9d47afa`，没有推送。共享 Home 模式继续使用宿主 `/home/gzy`，`.claude` 与 `.codex` 改由 `paths.persistent_home/.controlled-mounts` 中的独立读写存储覆盖，`/data` 保持 `rslave` 读写挂载，服务 relay 继续发布 `25600-25700/tcp`。
- 2026-08-08：受控目录禁止被同路径或祖先 `mounts` 覆盖，但允许显式普通挂载指向其严格子路径；Compose 固定按共享 Home、受控目录、普通子挂载、只读 profile 的顺序渲染。这样可以隔离 Claude 的账号、settings、会话和历史，同时让明确列出的非凭据目录继续与宿主共用。
- 2026-08-08：检查并恢复另一台受控容器导出的 `.claude` tar。归档只有一个 `.claude/` 顶层、2200 个安全路径条目，没有绝对路径、父目录跳转、链接或特殊文件；1852 个普通文件恢复到 `paths.persistent_home/.controlled-mounts/.claude`，没有解压到宿主活动 `~/.claude`。恢复后的 `.credentials.json` 和 `settings.json` 权限为 `0600`，Claude 账号状态与真实 headless API 请求均成功。
- 2026-08-08：宿主 `~/.claude/skills`、`agents`、`commands` 作为独立读写子挂载进入沙箱，双向写入探针通过；宿主 Claude 继续读取宿主自己的 `~/.claude`，未读取沙箱账号。临时 smoke 目录、恢复前旧状态和原始 tar 已清理。最终全量 pytest、Ruff、配置校验、24 项 doctor 检查和完整 `verify-closed` 均通过；门禁证据位于 `/var/log/controlled-dev-machine/gzy/audit/structured/20260808T181656.009006Z-ec24a800/verify-closed.json`，审计与 101 端口 relay 保持在线。
- 2026-08-08：容器内 Codex CLI 0.147.0 加载受控 `.codex` 中的 API-key 认证和配置，`codex doctor` 确认安装、配置、认证、状态数据库与活动提供方连通性正常。真实 `codex exec --ephemeral` 请求成功；随后 Codex 在仓库外共享目录实现 `slugify` 并运行 4 项测试，宿主复跑同样通过，临时夹具已清理。Doctor 仅报告一个既有可选 MCP 命令路径缺失，不影响核心 Codex 请求、文件编辑和命令执行。
- 2026-08-08：宿主 Ubuntu 22.04 的 tmux 从 APT `3.2a` 更新为官方 release `3.7b`，发布包 SHA-256 校验通过，源码安装到 `/usr/local/bin/tmux`，保留 `/usr/bin/tmux` 作为系统包回退。宿主 `.tmux.conf` 改用 `tmux-256color` 和 `terminal-features` RGB，移除会干扰全屏 TUI 重绘的 `smcup/rmcup` override；独立 socket 的配置与版本探针通过。现有两个会话仍由旧 server 承载，等待操作者从 tmux 外部重启 server 后切换。

## 当前本机约束

- 共享读写路径：`/home/gzy`、`/data`。
- Claude 私有状态：沙箱使用独立可写 `.claude`，不导入宿主旧认证；有效非认证功能可以单独共享。提示词、规则和设置保留为可写普通文件，可引用共同主规则，不使用只读单文件覆盖。
- 日常配置：shell、Git、tmux、SSH 配置和用户凭据可在容器内正常编辑、原子保存并持久化；`init` 仅为缺失文件提供种子，不覆盖已有修改。Codex 共用宿主配置和登录状态。
- 控制状态与审计：位于共享 Home 之外，只由宿主管理。
- 容器身份：`devbox`、`America/Los_Angeles`、`en_US.UTF-8`。
- 服务入口：宿主与容器同号 `25600-25700/tcp`。
- 公网路径：目标容器没有直接公网路由，Web 请求经受控 DNS、透明网关和宿主父代理。
- Docker socket、宿主 `/etc`、宿主 PID/网络命名空间和审计目录不进入目标容器。

## 下一步

日常使用和恢复以当前安装的开发沙盒入口及 [开发沙盒配置](development-sandbox.md) 为准；上面的带日期记录保留为历史证据。日常用户配置修改不需要重建。后续新增网络能力、策略或控制组件时，按对应变更重新执行闭锁门禁和增量审计归因。
