# 开发沙盒配置

开发沙盒沿用 Docker 开发环境，不使用另一个用户名或另一套项目路径。它与宿主共用真实用户名、UID/GID、Home 及用户工具链；基础系统仍来自容器镜像，不把宿主 `/usr` 整体覆盖进去。

## 日常使用

已安装入口的宿主上：

```sh
sbc                    # 进入开发 shell，尽量保留当前目录
sbc claude             # 干净且独立的 Claude
sbc codex              # 使用宿主同一份 Codex 配置和认证
sbc exec python script.py
sbc status
sbc audit status       # 宿主管理操作需要相应权限
sbc recover            # 仅恢复本用户的沙盒，不重启整机或 Docker
```

宿主的 `claude` 可以转发到 `sbc claude`；容器内的 `claude` 必须解析到真实 CLI，而不是再次进入宿主 wrapper。修改 login profile 时同时检查非交互、嵌套 login 和交互 shell，不能只在会被 `return` 跳过的 `.bashrc` 末尾调整 PATH。

## 文件与应用状态

开发配置使用 `workspace.share_host_home: true`。除明确的受控覆盖外，容器中的文件变更就是宿主变更。数据盘和 Home 外工具链只补实际必要的同路径挂载。

- Codex：直接共享宿主整棵 `.codex`，不再叠加独立目录。
- Claude：`/home/gzy/.claude` 是宿主 `~/.local/share/controlled-dev-machine/claude` 的普通 bind 挂载（`mounts`，不是 `controlled_mounts`），随共享 Home 在所有 gamma 主机一致。目录里只放全局提示词与工具配置：`CLAUDE.md`（@ 引用 `~/claude_code_config/CLAUDE.md`）、`settings.json`，以及 `rules/`、`skills/`、`agents/`（由 `~/claude_code_config` 子挂载提供）；不导入宿主历史、会话和认证。沙盒内 `/login` 后 `.credentials.json`、`.claude.json` 落在该目录，所有挂同一 Home 的服务器一致可见。
- 独立账号不等于丢弃通用指令和功能配置：`profile.claude_instructions` 保持主指令来源，仅为缺失文件提供首次种子；有效的 rules、skills、agents 和非认证设置单独继承，不复制账号、历史或缓存。私有主指令可引用共同基线并追加简短说明，不用新增几句话替代整份规则，也不在恢复时覆盖用户修改。
- Claude 的持久 `CLAUDE.md` 应要求重要计划执行前、初步结果后、阶段结论和后续规划前调用 Codex 独立评审，并综合原始证据判断，不把调用失败冒充通过。
- 评审使用当前实际可用的 Codex CLI。已被当前版本移除的 `codex mcp-server` 不应作为 MCP 服务继续配置；MCP 可用性要用真实握手核对，不能只检查配置项存在。
- 控制代码、策略、管理材料、出口租约和审计放在共享 Home 外。宿主入口执行冻结的安装副本，不直接执行目标用户可修改的项目源码。
- Home 外只保留控制面与审计：`/etc/controlled-dev-machine`、`/opt` 与 `/local/controlled-dev-machine/releases`、每台主机的 `/local/controlled-dev-machine/<host>/{runtime,audit,managed-home}`。用户可写、需要跨机一致的沙盒状态一律放 Home 内。

`controlled_mounts` 的 `seed: never` 表示干净初始化；重建容器仍保留该受控目录已有的新状态。`.claude` 是唯一例外：它必须落在共享 Home 内并在多台服务器间一致，所以用普通 `mounts` 指向 `~/.local/share/controlled-dev-machine/claude`，不再直接共享宿主 `~/.claude` 本体（避免把宿主历史与认证带进沙盒）。除 `.claude` 外，不要新增指向宿主 `~/.claude` 或其认证、settings 的穿透挂载。

shell、Git、tmux、SSH 配置及 SSH 凭据属于日常用户状态，允许容器用户正常编辑并持久化。共享 Home 中直接使用原文件，Home 外的 SSH Include 依赖以同路径可写目录接入；不要叠加只读或读写的单文件 bind，以免编辑器的临时文件加原子 rename 保存失败。首次 `init` 只为缺失文件提供种子，之后重建不覆盖修改，日常编辑不受不可变 profile 摘要约束。开放共享前先移除旧 shell 代理副作用并确认 Claude wrapper 不会回到 `sbc`；CA、machine-id、解析器、审计和网络控制组件仍保持只读。

## 容器身份

`target.hostname` 默认保留通用配置的 `devbox`，部署时可指定独立值。可选的 `target.mac_address` 必须是小写冒号格式、locally-admin、unicast，例如 `02:ab:cd:12:34:56`；它只设置目标网络的 MAC，不影响目标镜像构建摘要。部署时初始化并保存 hostname、machine-id 和 MAC，不能每次启动都更换。

容器仍共享真实内核与 GPU。软件状态独立不等于硬件标识全部变化，也不能承诺外部服务无法关联旧设备。SSH 是用户授权的宿主外访问能力，不应把它与上述应用状态覆盖误述为强制信息隔离。

## 网络与恢复边界

沿用既有 DNS、HTTP/S 网关、异常协议阻断和审计。专属出口传输只负责固定父代理和短租约，不重复实现网关的域名/协议策略。实际出口不匹配或租约无效时拒绝新连接，并撤销已有传输；最长租约为 15 秒，检查间隔包含探针耗时，不是逐请求直接观察公网 IP。

用户工具链也必须实际读取系统 CA。当前 Node 22.18 使用 `NODE_OPTIONS=--use-system-ca`，不能用该版本尚不识别的 `NODE_USE_SYSTEM_CA` 环境变量冒充已启用。uv 等工具按实际版本配置系统证书信任；验收同时检查可信 HTTPS 成功和未受信任证书仍被拒绝，不关闭 TLS 校验来修复下载。

Python 的 `SSL_CERT_FILE` 和 `REQUESTS_CA_BUNDLE` 默认指向系统 CA 包 `/etc/ssl/certs/ca-certificates.crt`。只读保护系统 CA，不再把 Conda 或 certifi 的包内证书文件作为单文件挂载；包目录保持可写，避免更新器在原子替换文件时遇到挂载点错误。

本机 rootful 部署使用原 nftables、PCAP、eBPF 和网络 watchdog；已有 rootless 部署保留其原设备映射和 UID 映射机制，不宣称与 rootful 拥有完全相同的宿主审计权限。生命周期操作只影响本任务登记的资源，不能重启共享 dockerd 或其他用户作业。

验收至少覆盖：正式入口与真实工具调用、双向文件共享、Claude 独立状态、Codex 共享认证、逐卡 CUDA 实算、SSH 宿主对照、出口偏差闭锁、原网络门禁、重建后身份/数据持久和审计存活。全局零包门禁应在无并行业务的受控窗口执行；若有失败，保留原 PCAP 并先分型，不能放宽判据来获得通过。
