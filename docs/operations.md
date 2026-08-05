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

父代理是本项目的外部前置条件，不由 `sandboxctl` 安装。部署者应先让一个支持 HTTPS `CONNECT` 的 HTTP 代理只监听宿主 `127.0.0.1:11440`，并确认它使用期望的公网出口。代理可以由 Clash 或其他实现提供；本项目只连接端口，不解析代理自己的 YAML，也不把代理地址暴露给目标容器。

```bash
curl --fail --silent --show-error \
  --proxy http://127.0.0.1:11440 https://api.ipify.org
```

输出必须落在随后配置的 `upstream.expected_exit_cidr` 内。只有一个固定出口时，把实际输出追加 `/32`；只有 VPN 服务明确保证一段地址池时才填写较大的 CIDR。真实出口属于主机私有配置，不能写入仓库。若父代理需要本地配置文件，可把路径写入 `upstream.config_path` 作为存在性检查；控制器不会用它启动父代理。

### 2. 取得固定代码

从发布仓库克隆后切到明确的 release tag 或 commit，不使用会移动的分支名作为部署依据：

```bash
git clone https://github.com/ZeyuanGuo/claude-sandbox.git "$HOME/claude-sandbox"
cd "$HOME/claude-sandbox"
git checkout <RELEASE_TAG_OR_COMMIT>
git status --short
```

当前仓库若尚未配置私有 remote，只能完成本机构建，不能声称已经发布。发布方需记录 commit、策略摘要以及构建后两个镜像的内容摘要。

### 3. 生成本机配置

普通用户执行：

```bash
cd "$HOME/claude-sandbox"
bin/sandboxctl config init
```

`config init` 从实际系统账号填写用户名、UID、GID 和 Home，拒绝覆盖已有文件。它会在源文件安全且实际存在时接入常用 shell/Git/tmux/Claude 文本配置，并同路径挂载现有 Skills、agents、`~/.config/git`、`~/.ssh` 和 `~/.condarc`。Git 配置目录可读写，以支持 credential store 的锁文件和原子更新；SSH 与 Conda 配置只读。它不会挂载整棵宿主 `~/.claude`，Claude 的账号、会话和设备状态保留在沙箱持久 Home。生成器不知道这台服务器的真实出口，因此 `expected_exit_cidr` 初始留空，填写前配置不会通过校验。

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
sudo -E bin/sandboxctl --config /absolute/path/host.yaml build
sudo bin/sandboxctl --config /absolute/path/host.yaml start
sudo bin/sandboxctl --config /absolute/path/host.yaml verify-closed
```

这套显式路径主要用于迁移预检或故障恢复。正常部署仍使用下节的默认路径；同一用户不要同时启动两个实例。

### 4. 预检、构建和启动

首次部署从严格策略开始：

```bash
sudo bin/sandboxctl doctor --json
sudo bin/sandboxctl storage plan
sudo bin/sandboxctl init --policy policies/strict/0002-claude-account.yaml
sudo -E bin/sandboxctl build
sudo bin/sandboxctl start
sudo bin/sandboxctl verify-closed
```

`doctor` 任一 `blocked` 都要先修复。`init`、`build`、`start` 和 `stop` 对同一实例互斥；运行中执行 `init` 或 `build` 会直接拒绝，避免活动容器、`current` 清单和镜像标签分叉。

基础镜像固定上游 digest，并由 `skopeo` 导入本机 Docker。目标和网关镜像名称包含各自构建输入摘要，镜像内也保存同一摘要。`build` 还把实际 Docker image ID 写入 root-only 的 `paths.state/images/`；同一构建摘要如果已有不同 image ID，构建会拒绝覆盖记录。`start` 同时核对源码、清单、策略、profile、镜像标签和 image ID。同一标签被重新构建成不同内容时会拒绝启动。构建时如需代理，只给当前构建命令设置 `HTTP_PROXY`/`HTTPS_PROXY`，这些变量不会写入目标运行环境。

`start` 安装本实例的宿主 nftables 父代理门禁和 systemd 恢复单元，再创建没有直接公网路由的目标、DNS、网关和 canary。目标容器不发布端口，不挂 Docker socket；全部 GPU 可见但不设置独占模式。

`verify-closed` 证明网络门禁和审计路径，不等于项目环境、Claude 登录或真实开发任务已经可用。新主机还要进入 shell 检查实际路径：

```bash
sudo bin/sandboxctl shell
command -v python
python -c 'import torch; print(torch.cuda.is_available(), torch.cuda.device_count())'
git config --get user.name
claude --version
```

再在一个允许公开的测试项目中完成读写文件、运行测试、Git HTTPS 和一项正常 Claude 任务。环境名本身不算通过，必须检查实际 Python、关键 import 和 GPU 计算。

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
