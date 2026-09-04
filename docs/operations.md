# 部署与操作

一名用户在一台服务器上只运行一套受控开发机。新增项目只增加挂载，不再创建第二套长期环境。项目、环境和凭据留在本机；控制代码、策略和文档由 Git 固定版本。

主机配置中的 `instance` 固定为 `main`，生命周期锁保存在 root-only 的 `/run/controlled-dev-machine-locks` 并按目标 UID 在宿主全局生效。不要通过另一份状态目录或实例名创建第二套环境。

## 新主机从零部署

### 1. 准备宿主

当前实现只支持满足下列条件的 Linux amd64 主机：

- Ubuntu 24.04 或经过单独验证的兼容系统，使用 systemd、cgroup v2 和 AppArmor；
- Python 3.11+ 和 PyYAML；
- Docker Engine 28+、Docker Compose v2 插件；
- NVIDIA 驱动、NVIDIA Container Toolkit 和 CDI，`nvidia-ctk cdi list` 包含 `nvidia.com/gpu=all`；
- 目标账号有未锁定的本地密码；`init` 需要从 `/etc/shadow` 读取该账号密码哈希，以保持容器内 `sudo` 密码一致；
- `nft`、`nsenter`、`ip`、`tcpdump`、`bpftrace`、`skopeo`、`curl`、`openssl` 和 `systemctl`。

当前只实现 HTTP 父代理；`upstream.kind: tun` 会在 `doctor` 中明确阻断，不能作为已支持的部署方式。

Ubuntu 上先安装系统工具；Docker 和 NVIDIA 组件按各自官方安装方式完成：

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-yaml nftables iproute2 util-linux \
  tcpdump bpftrace skopeo curl openssl
```

### 2. 取得固定代码

从发布仓库克隆后切到明确的 release tag 或 commit，不使用会移动的分支名作为部署依据：

```bash
git clone https://github.com/ZeyuanGuo/claude-sandbox.git "$HOME/claude-sandbox"
cd "$HOME/claude-sandbox"
release_ref=REPLACE_WITH_RELEASE_TAG_OR_COMMIT
git checkout "$release_ref"
git status --short
```

发布方需记录 commit、策略摘要以及构建后两个镜像的内容摘要。

### 3. 配置固定出口父代理

父代理是本项目的外部前置条件，不由 `sandboxctl` 安装。部署者应先让一个支持 HTTPS `CONNECT` 的 HTTP 代理监听宿主 `11450`，并确认它使用期望的公网出口。DNS 和网关从 Docker 内部桥访问宿主，因此父代理必须监听该桥可达的地址；示例使用 `0.0.0.0`。安全边界由 `sandboxctl` 安装的宿主 nftables 提供：运行时只允许回环及本实例 DNS/网关的固定源地址，停止时只允许回环，其他容器、LAN 和外部来源均被拒绝。代理可以由 Mihomo、Clash 或其他实现提供；父代理必须全局使用指定出口，出口失效时直接失败，不能回退到其他代理或直连。

仓库提供了脱敏的 [`examples/mihomo-11450.example.yaml`](../examples/mihomo-11450.example.yaml)：`11450` 的唯一规则指向固定出口节点，该节点再通过 `dialer-proxy` 使用商业 VPN 作为第一跳。把模板复制到宿主私有目录、填入两级节点参数并设为 `0600`；不要把真实服务器、账号或密码提交到 Git。模板中的 `allow-lan: true` 只用于让 Docker 内部桥可达，不能代替上述 nftables 门禁。使用其他父代理实现时也必须保持“唯一最终出口、失败即失败”的结构。

下面是仓库验收过的 amd64 参考部署。Mihomo 固定为 `v1.18.3`，解压后程序的 SHA-256 是 `6a31325951db7ed8bb42f484fa4c5c4dc02d06488a4cb25f810e8ecb0245163d`：

```bash
mihomo_root="$HOME/.local/share/claude-sandbox/mihomo"
mihomo_config="$HOME/.config/claude-sandbox/mihomo-11450.yaml"
install -d -m 700 "$mihomo_root" "$(dirname "$mihomo_config")"
curl -fsSL \
  https://github.com/MetaCubeX/mihomo/releases/download/v1.18.3/mihomo-linux-amd64-compatible-v1.18.3.gz \
  | gzip -dc > "$mihomo_root/mihomo"
chmod 700 "$mihomo_root/mihomo"
printf '%s  %s\n' \
  6a31325951db7ed8bb42f484fa4c5c4dc02d06488a4cb25f810e8ecb0245163d \
  "$mihomo_root/mihomo" | sha256sum --check --strict
install -m 600 examples/mihomo-11450.example.yaml "$mihomo_config"
```

填好私有配置后先检查并安装用户服务，但先不要启动：

```bash
"$mihomo_root/mihomo" -t -d "$mihomo_root" -f "$mihomo_config"
install -Dm644 examples/mihomo-11450.service \
  "$HOME/.config/systemd/user/claude-sandbox-mihomo.service"
systemctl --user daemon-reload
```

不要在 `sandboxctl guard` 之前启动这个服务。父代理配置、程序和运行数据都位于用户目录；迁移时只需重新下载已校验程序并放入该主机自己的私有配置，不复制凭据到仓库。
示例服务每次启动前都会确认当前用户 `main` 实例的系统级门禁已经 active；门禁安装失败或开机恢复失败时，父代理保持启动失败，不会绑定 `11450`。

### 4. 生成本机配置

普通用户执行：

```bash
cd "$HOME/claude-sandbox"
bin/sandboxctl config init
```

`config init` 从实际系统账号填写用户名、UID、GID 和 Home，拒绝覆盖已有文件。它创建宿主 `~/claude_code_config`，以仓库中的 `config/claude/CLAUDE.md` 初始化全局提示词，并创建设置、规则、skills 和 agents 的独立入口；这些项目分别读写挂载到容器 `~/.claude` 下。它不会创建或挂载宿主 `~/.claude`，Claude 的账号、会话、历史、插件和设备状态只保留在沙箱持久 Home。

生成器还会自动创建 `~/.codex`（不存在时）并以读写方式挂载整棵目录；Codex CLI 首次登录后的状态直接保存在宿主该目录。它在源文件安全且实际存在时接入常用 shell、Git、tmux、`~/.agents/skills`、`~/.config/git`、`~/.ssh` 和 `~/.condarc`。Git、skills、agents 和 Conda 配置读写；只有 SSH 关键凭据保持只读。生成器不知道这台服务器的真实出口，因此 `expected_exit_cidr` 初始留空，填写前配置不会通过校验。

默认通用挂载由仓库中的 `config init` 固定生成；只有源路径实际存在时才加入：

| 宿主路径 | 容器路径 | 权限 | 用途 |
|---|---|---|---|
| `~/claude_code_config/CLAUDE.md` | `~/.claude/CLAUDE.md` | 读写 | Claude 全局提示词 |
| `~/claude_code_config/settings.json`、`rules`、`skills`、`agents` | `~/.claude` 下对应路径 | 读写 | Claude 的共享行为配置 |
| `~/.codex` | 同路径 | 读写 | Codex 配置、登录状态、会话和 skills |
| `~/.agents/skills` | 同路径 | 读写 | Codex 可见的通用 skills |
| `~/.config/git` | 同路径 | 读写 | Git 凭据存储和配置数据库 |
| `~/.ssh` | 同路径 | 只读 | 日常 SSH 配置和密钥 |
| `~/.condarc` | 同路径 | 读写 | Conda 配置 |

`CLAUDE.md` 和上表中的 Claude 行为配置直接读写同步；`.bashrc`、`.profile`、`.gitconfig` 和 `.tmux.conf` 仍由 `init` 生成受控只读副本。宿主不设置 `CLAUDE_CONFIG_DIR`，默认 `~/.claude` 也不作为挂载源，所以宿主直接运行 Claude Code 时不会自动读取容器配置。Claude 凭据、会话数据库和其他运行状态留在持久 Home。项目目录、Conda 根目录和其他大型数据目录属于主机特定配置，由操作者在 `host.yaml` 中追加。

然后编辑 `~/.config/controlled-dev-machine/host.yaml`：

- 给每个项目增加同路径 `rw` 挂载；
- 按出口环境填写 `profile.timezone`；公开默认 `UTC`，使用 IANA 时区名称；
- 按本机情况填写 `profile.conda_root`、`profile.default_conda_env`，并把大型环境目录同路径挂载；
- 删除不希望交给目标软件的凭据挂载；
- 确认持久 Home、状态、审计目录和存储保留线；
- 确认父代理端口与 `expected_exit_cidr`。

编辑完成后再校验：

```bash
bin/sandboxctl config validate
```

Python 环境是主机自己的配置，不由框架检查或下载。每台服务器可以选择不同环境。完整字段和挂载示例见 [`examples/host.example.yaml`](../examples/host.example.yaml)。

默认配置始终取调用者账号的 `~/.config/controlled-dev-machine/host.yaml`，即使用 `sudo` 也不会改读 root 的 Home。预检临时配置或恢复配置时必须显式传入路径，而且 `--config` 位于子命令之前：

```bash
bin/sandboxctl --config /absolute/path/host.yaml config init
# 编辑该文件并填写 expected_exit_cidr
bin/sandboxctl --config /absolute/path/host.yaml config validate
```

后续每条命令也必须携带同一个参数，不能只在 `validate` 时使用：

```bash
sudo bin/sandboxctl --config /absolute/path/host.yaml doctor --json
sudo bin/sandboxctl --config /absolute/path/host.yaml storage plan
sudo bin/sandboxctl --config /absolute/path/host.yaml init \
  --policy policies/strict/0002-claude-account.yaml
sudo bin/sandboxctl --config /absolute/path/host.yaml guard
# 先按本机情况设置 HTTP_PROXY/HTTPS_PROXY/NO_PROXY
sudo -E bin/sandboxctl --config /absolute/path/host.yaml build
sudo bin/sandboxctl --config /absolute/path/host.yaml start
sudo bin/sandboxctl --config /absolute/path/host.yaml verify-closed
```

这套显式路径主要用于迁移预检或故障恢复。正常部署仍使用下节的默认路径；同一用户不要同时启动两个实例。

### 5. 预检、构建和启动

首次部署从严格策略开始：

```bash
sudo bin/sandboxctl init --policy policies/strict/0002-claude-account.yaml
sudo bin/sandboxctl guard
systemctl --user start claude-sandbox-mihomo.service
curl --fail --silent --show-error \
  --proxy http://127.0.0.1:11450 https://api.ipify.org
sudo bin/sandboxctl doctor --json
sudo bin/sandboxctl storage plan
HOST_BUILD_PROXY=http://127.0.0.1:11400  # 按本机实际构建代理修改
export HTTP_PROXY="$HOST_BUILD_PROXY"
export HTTPS_PROXY="$HTTP_PROXY"
export NO_PROXY=127.0.0.1,localhost
sudo -E bin/sandboxctl build
unset HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy
sudo bin/sandboxctl start
sudo bin/sandboxctl verify-closed
systemctl --user enable claude-sandbox-mihomo.service
sudo bin/sandboxctl automation install
```

`guard` 在父代理启动前安装并启用持久 nftables 门禁，此时 `11450` 只允许宿主回环访问；正式 `start` 才原子加入本实例 DNS 和网关的固定来源。这样首次部署也不会在两条命令之间向 LAN、外部或其他容器暴露代理。出口探测结果必须落在 `upstream.expected_exit_cidr` 内；固定出口填写精确 `/32`。`doctor` 任一 `blocked` 都要先修复。`init`、`guard`、`build`、`start` 和 `stop` 对同一实例互斥；运行中执行这些命令会直接拒绝，避免活动容器、门禁、`current` 清单和镜像标签分叉。

基础镜像固定上游 digest，并由 `skopeo` 导入本机 Docker。目标和网关镜像名称包含各自构建输入摘要，镜像内也保存同一摘要。`build` 还把实际 Docker image ID 写入 root-only 的 `paths.state/images/`；同一构建摘要如果已有不同 image ID，构建会拒绝覆盖记录。`start` 同时核对源码、清单、策略、profile、镜像标签和 image ID。同一标签被重新构建成不同内容时会拒绝启动。构建阶段使用宿主网络；`sudo -E` 会把当前命令已有的标准代理变量临时交给 BuildKit，因此 `127.0.0.1` 上的宿主代理可直接使用。代理值不写入生成的 Compose、镜像或目标运行环境。容器启动后仍没有代理变量，运行流量只走 `11450`。

`start` 会再次核对父代理门禁，再创建没有直接公网路由的目标、DNS、网关和 canary。目标容器不发布端口，不挂 Docker socket；全部 GPU 可见但不设置独占模式。canary CA 和服务端证书有效期为 30 天；每次 `start` 在证书剩余有效期不足 7 天时先原子更新，再启动容器。

### 重启后快速诊断

重启、断网或 Claude 窗口仍在但请求失败时，先只运行这一条命令：

```bash
sudo bin/sandboxctl doctor
```

它在只读模式下检查宿主前置条件、运行清单与代码摘要、镜像内容、四个容器、systemd 自动化、父代理、基础审计、三处 PCAP、目标容器内的 `ping0.cc` 与 `api.anthropic.com` DNS/HTTPS，以及 Claude 版本和登录状态。每个非通过项会同时显示事实和下一条建议命令；机器或后续工具读取结构化结果时使用 `sudo bin/sandboxctl doctor --json`。该命令不会重启、重建、清理或修改正在运行的容器。

优先按诊断项执行最小修复：

```bash
# 容器仍在运行，只是基础审计失活或目标网络被 watchdog 收回
sudo bin/sandboxctl audit restart

# 不确定容器是否被 Docker 保留；由 recover 自动选择启动或只恢复审计
sudo bin/sandboxctl recover

# 父代理用户服务未 active
systemctl --user restart claude-sandbox-mihomo.service

# 自动启动或审计轮转 unit 未启用
sudo bin/sandboxctl automation install
```

`audit restart` 只作用于当前实例：它不停止或重建容器，不接触其他用户的进程；只有四个服务都已运行且 DNS、网关、canary healthy 时才会执行。源码、策略或镜像摘要不一致时，doctor 会把它标为“下次启动前需重建”；届时在确认当前任务可以中断后再执行 `stop -> init -> build -> start`。完整网络门禁验收仍需显式运行 `sudo bin/sandboxctl verify-closed`，doctor 不会自动运行这项可能耗时较长的检查。

只有首次 `verify-closed` 和实际开发环境检查均通过后才运行 `automation install`。该命令写入并启用本实例的 systemd 自动启动单元和审计轮转定时器，但不会立即启动或重启任何服务。下次开机时，系统级单元先恢复用户服务、检查父代理，再调用 `recover`：容器已被 Docker 保留时只恢复审计和目标网络，容器不存在时才走完整 `start`；任一前置检查失败都会停止启动。轮转定时器每 15 分钟调用一次 `storage rotate`。安装后可只读检查配置，不要在生产中的实例上手动启动这些单元：

```bash
systemctl is-enabled cdm-u$(id -u)-main.service \
  cdm-u$(id -u)-main-audit-rotate.timer
systemctl status cdm-u$(id -u)-main.service \
  cdm-u$(id -u)-main-audit-rotate.timer --no-pager
```

### 更换父代理或固定出口

父代理地址、端口和期望出口只属于运行配置，不属于目标或网关镜像。先保留旧配置并停止当前沙箱和旧父代理；确认两者都已停止后，再修改父代理私有配置与 `host.yaml`：

```bash
sudo bin/sandboxctl stop
systemctl --user stop claude-sandbox-mihomo.service
# 现在修改父代理私有配置和 host.yaml
bin/sandboxctl config validate
current_policy=policies/daily/0001-public-web.yaml  # 按当前策略修改
sudo bin/sandboxctl init --policy "$current_policy"
sudo bin/sandboxctl guard
systemctl --user start claude-sandbox-mihomo.service
curl --fail --silent --show-error \
  --proxy http://127.0.0.1:11450 https://api.ipify.org
sudo bin/sandboxctl start
sudo bin/sandboxctl verify-closed
```

不要为这类改动执行 `build`。只有 `start` 明确报告目标或网关镜像缺失、构建输入变化或内容摘要不符时，才在停止状态运行 `sudo -E bin/sandboxctl build`，然后重新启动。固定出口填精确 `/32`；启动时控制器会通过父代理查询公网地址，不匹配即拒绝启动。

`verify-closed` 证明网络门禁和审计路径，不等于项目环境、Claude 登录或真实开发任务已经可用。新主机还要进入 shell 检查实际路径：

```bash
sudo bin/sandboxctl shell
command -v python
python -c 'import torch; print(torch.cuda.is_available(), torch.cuda.device_count())'
git config --get user.name
claude --version
codex --version
```

再在一个允许公开的测试项目中完成读写文件、运行测试、Git HTTPS，以及各执行一项正常 Claude 和 Codex 任务。环境名本身不算通过，必须检查实际 Python、关键 import 和 GPU 计算。

## 日常进入与提权

```bash
cd "$HOME/claude-sandbox"
sudo bin/sandboxctl shell
```

退出 shell 不会停止沙箱。普通容器用户属于 `sudo` 组，密码与本机同名宿主账号一致。密码哈希只在 `init` 时从宿主读取并保存到 root-only 运行文件；明文不进入仓库、镜像、配置或日志。宿主密码变化时按 `stop -> init -> build -> start -> verify-closed` 更新。

容器内 sudo 损坏时，从宿主进入 root shell：

```bash
sudo bin/sandboxctl root-shell
```

`shell` 和 `root-shell` 会自动把调用端非空的 `TERM` 和 `COLORTERM` 传入容器，使交互 shell、彩色提示符和全屏 TUI 使用当前终端的能力。用户不需要另外导出终端变量；非交互探针仍使用独立的无 TTY 执行路径。

停止整套环境：

```bash
sudo bin/sandboxctl stop
```

停止会结束本实例审计进程并删除本实例容器和网络，但保留持久 Home、项目、策略和审计证据。它不管理其他用户进程；操作其他用户进程必须另行取得明确确认。

## 严格与日常策略

新认证方式、未知 MCP/插件/hook 或软件升级先使用严格策略。普通公网 DNS 在严格和日常模式都可以解析；DNS 只拒绝危险地址、异常查询类型和解析失败。严格模式的未知 HTTP/HTTPS 在解密后、连接上游前进入审核：

```bash
sudo bin/sandboxctl review list
sudo bin/sandboxctl review analyze REQUEST_ID
sudo bin/sandboxctl review show REQUEST_ID --raw
sudo bin/sandboxctl review approve-once REQUEST_ID --ttl 60 --reason '明确的测试用途'
sudo bin/sandboxctl review reject REQUEST_ID --reason '用途不明确'
```

先看 `analyze`；`show --raw` 含认证头、源码和对话，只在必须逐字确认时使用。一次批准只绑定当前请求摘要、策略和短有效期。

切换策略必须完整执行：

```bash
sudo bin/sandboxctl stop
sudo bin/sandboxctl init --policy policies/daily/0001-public-web.yaml
sudo bin/sandboxctl build
sudo bin/sandboxctl start
sudo bin/sandboxctl verify-closed
```

仅策略变化且目标/网关构建输入未变化时，`build` 会复用内容摘要相同的镜像；保留这一步能让操作顺序统一。策略文件不原地修改：复制上一版本、填写父摘要和变更原因，再执行 `policy validate`、`policy digest`、部署和真实任务回归。

公开发布从一条新的策略谱系开始：`strict/0001-bootstrap.yaml` 是公开根快照，`strict/0002-claude-account.yaml` 是账号发现快照，`daily/0001-public-web.yaml` 从账号快照分支。未发布的主机私有历史策略不是公开父链。首次发布提交之后，这三份文件也不可原地修改；任何变化都新增文件、父摘要和回归证据。

## 审计与故障

```bash
sudo bin/sandboxctl status
sudo bin/sandboxctl audit status
sudo bin/sandboxctl storage plan
```

每次启动有独立运行编号。`flows.mitm` 保存请求正文、双向头、响应状态和传输结果；响应正文收到响应头后直接流式转发，不缓存。目标、DNS、网关三处 PCAP 与目标 cgroup eBPF 记录保存在同一运行编号下。原始证据可能包含令牌、源码和完整对话，只能提权读取，不能提交到 Git。

出现探针死亡、网关不健康、磁盘不足、出口超出 `expected_exit_cidr`、无法解释的直连/非 Web 流量或证据无法对应时，停止扩大使用并保留现场。watchdog 只核对登记进程和命名空间是否仍匹配，不证明磁盘没有写坏，也不证明 PCAP/eBPF 没有丢事件。

## 升级与回滚

先记录当前 commit、策略摘要、运行编号和 `paths.state/images/` 中的两个镜像 ID，然后停止环境。切换到目标 commit 后按 `config validate -> doctor -> init -> build -> start -> verify-closed -> 真实任务` 执行。不要在运行中修改 `current` 清单或重建同一实例镜像。

回滚时停止环境，切回上一固定 commit 和上一策略快照，再执行同一完整序列。项目挂载与持久 Home 不因回滚删除；若新版本已经修改了其中的数据，代码回滚不会自动撤销这些数据变化，应使用项目 Git 或事前备份恢复。

## 迁移到另一台服务器

目标机先按“新主机从零部署”完成依赖、父代理和固定代码。迁移内容分开处理：

- 控制代码和策略从私有 Git 的固定 commit 获取；
- 项目由各自 Git 或存储方案迁移，并在新机 `host.yaml` 中同路径挂载；
- Python/Conda 环境在新机本地准备，名称和目录可以不同；
- Skills、agents、shell、Git、tmux 和凭据从新机实际 Home 接入，不打包进发布物；
- 需要延续 Claude 会话和账号状态时，在源环境停止写入后备份 `paths.persistent_home`，按新机 UID/GID 恢复；账号令牌若失效则在新机重新登录；
- 审计日志可独立归档，但不复制活动 runtime、CA 私钥、nftables 状态或 systemd 运行文件。

目标机重新执行 `doctor -> init -> build -> start -> verify-closed`，再验证 Python/GPU/Git/Claude 真实任务。只有这些新证据通过，才能说该服务器复现成功；源服务器的运行编号和测试结论不能直接继承。
