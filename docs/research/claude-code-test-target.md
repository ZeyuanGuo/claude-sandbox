# 把 Claude Code 作为第一套检测对象

本文给出第一套可重复的检测方案。目标不是证明 Claude Code 有问题，而是用一个真实、功能完整、联网路径较多的程序，检查沙箱能否做到：

- 只放行已经登记的连接；
- 保存全部网络包；
- 记录每条连接由哪个进程发起；
- 对已经放行的 Claude Code 流量完整保存 TLS 明文；
- 抓包、解密或记录失效时立即阻断，而不是继续联网。

结论只适用于固定的软件版本、配置和测试路径。版本、凭据方式、插件、MCP 或联网工具变化后，都要重新检查。

## 当前检测基线

截至 2026-07-28，官方最新发布是 `2.1.220`。Linux 的常规推荐安装方式是原生安装；npm 安装已经不再推荐。
[官方安装说明](https://code.claude.com/docs/en/setup)、[2.1.220 发布记录](https://github.com/anthropics/claude-code/releases/tag/v2.1.220)

第一轮检测固定使用：

| 项目 | 固定值 |
|---|---|
| Claude Code | `2.1.220` |
| 平台 | `linux-x64` |
| 安装文件 SHA256 | `674f61f20ff306f3100cf9200e4c36c4b70278b5bef2884549819b942a89c863` |
| 更新 | 全部关闭 |
| 模型 | API-key 基线使用一个固定模型；私有别名不进入发布仓库 |
| 配置 | 最小诊断使用独立配置；正常验收使用沙箱持久 Home |
| 网络 | 只能经过外层解密代理；直连保持阻断 |

表中的 SHA256 取自 Anthropic 发布的 [2.1.220 官方 manifest](https://downloads.claude.ai/claude-code-releases/2.1.220/manifest.json)。

这里的版本号是检测基线，不应永远写死在系统逻辑中。升级时新增一个基线记录，重新执行全部测试，通过后再替换日常版本。

### 2026-07-28 现场结果

API-key 核心路径已经实测完成。直接交互界面、完整标准工具、文件修改、测试、本地 Git、WebSearch、WebFetch、Bash/curl、Git HTTPS、子 agent、长会话恢复和宿主指定会话迁移均可用。最终有效运行没有出现任务外目的地或非 Web 外连。

严格发现完成后，本机 API-key 基线已切到日常策略：普通公网 HTTP/HTTPS 默认放行并继续保存明文，直接连接、外部 DNS、UDP、非 Web 端口、特殊主机名和已登记 DoH 保持阻断。自动任务和容器 Bash 中直接运行 `claude` 的人工任务都已回归通过。公开仓库不包含该本机的私有端点规则；新主机必须按自己的认证方式重新建立基线。

Claude Code 会主动发送沙箱内核版本、平台、架构、项目路径、Git 摘要、客户端版本和设备/会话标识。已测人工任务没有发送实际时区、CPU/GPU、内存、MAC、内网 IP、代理或 CA 路径。项目 Skill、MCP、hook 和子 agent 已用本地 fixture 验证；账号登录、未启用的插件和检测环境对照尚未完成。公开结论见 [验收摘要](../validation.md)。

## 安装和校验

官方原生安装命令可以指定版本：

```bash
curl -fsSL https://claude.ai/install.sh | bash -s 2.1.220
```

但检测镜像需要先验证下载文件，再放到固定路径。官方为每个版本发布 `manifest.json`、SHA256 和 GPG 签名。签名从 `2.1.89` 开始提供。[官方完整性校验说明](https://code.claude.com/docs/en/setup#binary-integrity-and-code-signing)

构建时应执行等价于下面的检查：

```bash
set -euo pipefail

CC_VERSION=2.1.220
CC_PLATFORM=linux-x64
CC_REPO=https://downloads.claude.ai/claude-code-releases
CC_EXPECTED_FPR=31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
CC_TMP=$(mktemp -d)
trap 'rm -rf -- "$CC_TMP"' EXIT

chmod 700 "$CC_TMP"
mkdir -m 700 "$CC_TMP/gnupg"
curl -fsSL https://downloads.claude.ai/keys/claude-code.asc \
  -o "$CC_TMP/claude-code.asc"
gpg --homedir "$CC_TMP/gnupg" --import "$CC_TMP/claude-code.asc"
CC_ACTUAL_FPR=$(
  gpg --homedir "$CC_TMP/gnupg" --with-colons \
    --fingerprint security@anthropic.com |
    awk -F: '$1 == "fpr" { print $10; exit }'
)
if [ "$CC_ACTUAL_FPR" != "$CC_EXPECTED_FPR" ]; then
  printf 'unexpected Claude Code signing key: %s\n' "$CC_ACTUAL_FPR" >&2
  exit 1
fi

curl -fsSL "$CC_REPO/$CC_VERSION/manifest.json" \
  -o "$CC_TMP/manifest.json"
curl -fsSL "$CC_REPO/$CC_VERSION/manifest.json.sig" \
  -o "$CC_TMP/manifest.json.sig"
gpg --homedir "$CC_TMP/gnupg" \
  --verify "$CC_TMP/manifest.json.sig" "$CC_TMP/manifest.json"

curl -fsSL "$CC_REPO/$CC_VERSION/$CC_PLATFORM/claude" \
  -o "$CC_TMP/claude"
CC_EXPECTED=$(jq -r ".platforms[\"$CC_PLATFORM\"].checksum" \
  "$CC_TMP/manifest.json")
printf '%s  %s\n' "$CC_EXPECTED" "$CC_TMP/claude" | sha256sum -c -

install -o root -g root -D -m 0755 "$CC_TMP/claude" \
  "/opt/claude-code/$CC_VERSION/claude"
```

上面的检查会在 GPG 指纹不匹配时立即失败。官方指纹为：

```text
31DD DE24 DDFA B679 F42D 7BD2 BAA9 29FF 1A7E CACE
```

不要在容器启动时跟随 `latest` 或 `stable`。固定版本后设置 `DISABLE_UPDATES=1`。
`DISABLE_AUTOUPDATER=1` 不够，因为它仍允许手动更新。[更新设置说明](https://code.claude.com/docs/en/setup#disable-auto-updates)、[环境变量说明](https://code.claude.com/docs/en/env-vars)

每次构建保存版本、平台、二进制 SHA256、签名检查结果和构建时间。保存 manifest 和签名即可，不必把大体积官方二进制提交到控制仓库。二进制必须由 root 所有、被测用户只读；每次测试前重新检查 SHA256，不能只依赖构建时检查。

## Linux 配置和登录

Claude Code 在 Linux 上把登录凭据保存在 `~/.claude/.credentials.json`，文件权限为 `0600`。
设置 `CLAUDE_CONFIG_DIR` 后，凭据和配置会放到指定目录。[官方认证说明](https://code.claude.com/docs/en/authentication#credential-management)

初始化时可以让操作者选择凭据来源：

1. 使用沙箱内已有的 Claude Code 配置和账号；
2. 给检测任务使用单独的 `CLAUDE_CONFIG_DIR`；
3. 使用 `ANTHROPIC_API_KEY`、`CLAUDE_CODE_OAUTH_TOKEN` 或官方支持的凭据脚本。

这些凭据都属于被测程序自身，可以正常提供。自动测试不能把凭据值写入结果摘要或控制仓库。解密日志中会包含认证头，因此只有管理员可以读取。

自动检测必须明确选择下面一种认证基线，两种结果不能混为同一基线：

- API Key 的最小诊断可以使用 `--bare`。`--bare` 不读取 OAuth、系统 keychain 或 `CLAUDE_CODE_OAUTH_TOKEN`；认证只能来自 `ANTHROPIC_API_KEY`，或来自通过 `--settings` 明确传入的 `apiKeyHelper`。
- API Key 的正常验收不使用 `--bare`，而是在沙箱持久 Home 中直接运行 `claude`。这样才能覆盖会话标题、历史、完整工具和真实交互启动流量。
- 账号登录的最小诊断可以使用独立的 `CLAUDE_CONFIG_DIR` 和 `--safe-mode` 来分离认证流量。最终验收必须回到持久 Home 直接运行 `claude`，覆盖正常项目配置、完整工具和交互流程。

这是官方对两个参数的行为定义。[`--bare` 认证限制](https://code.claude.com/docs/en/headless#start-faster-with-bare-mode)、[`--safe-mode` 说明](https://code.claude.com/docs/en/cli-reference#cli-flags)

首次网页登录在 SSH 或容器里可能无法自动回调。官方支持复制登录 URL，在外部浏览器完成登录后把代码粘回终端。
自动测试前用下面的命令确认状态；该命令登录时退出码为 0，未登录时为 1。[官方 CLI 说明](https://code.claude.com/docs/en/cli-reference)

```bash
claude auth status
```

测试记录只保存认证类型和退出码，不保存令牌。

## 代理和自定义 CA

Claude Code 正式支持 `HTTP_PROXY`、`HTTPS_PROXY`、`NO_PROXY` 和自定义 CA，不支持 SOCKS 代理。
原生版默认信任内置 Mozilla CA 和系统 CA；额外根证书可以通过 `NODE_EXTRA_CA_CERTS` 指定。[官方网络配置](https://code.claude.com/docs/en/network-config)

检测配置使用：

```bash
HTTPS_PROXY=http://sandbox-gateway:PORT
HTTP_PROXY=http://sandbox-gateway:PORT
NO_PROXY=localhost,127.0.0.1,::1
NODE_EXTRA_CA_CERTS=/etc/ssl/certs/sandbox-audit-ca.pem
CLAUDE_CODE_CERT_STORE=bundled,system
```

根证书的公开部分可以装入容器的系统证书库，根证书私钥只能留在外层解密代理。外层防火墙仍要阻止直接外连，不能因为程序设置了代理就假定它不会绕过。

这些变量只保证 Claude Code 自身知道代理和 CA。`git`、`curl`、hook、插件、LSP 和 stdio MCP 是独立程序，必须分别检查它们使用的代理和证书库。
需要后台会话时，代理和 CA 应写入用户设置的 `env`，因为后台 supervisor 不一定继承启动终端的环境。[后台会话的网络设置](https://code.claude.com/docs/en/network-config#apply-network-settings-to-background-agents)

## Claude Code 可能访问哪里

官方当前列出的固定主机如下。[官方网络主机表](https://code.claude.com/docs/en/network-config#network-access-requirements)

| 主机 | 用途 | 最小检测时是否应出现 |
|---|---|---|
| `api.anthropic.com` | 模型请求、功能开关、部分遥测、WebFetch 域名检查 | 是，模型任务需要 |
| `claude.ai` | Claude 账号登录 | 只在登录时 |
| `claude.com` | 登录跳转、部分文档读取 | 只在对应功能启用时 |
| `code.claude.com` | 内置指南和预先批准的文档读取 | 最小检测中禁止 |
| `platform.claude.com` | Console 登录、OAuth 交换和刷新 | 取决于认证方式 |
| `mcp-proxy.anthropic.com` | Claude.ai MCP 连接器 | 最小检测中禁止 |
| `downloads.claude.ai` | 安装、更新、插件可执行文件 | 构建时允许，运行时禁止 |
| `storage.googleapis.com` | 插件元数据、安装计数和部分上传 | 最小检测中禁止 |
| `raw.githubusercontent.com` | 发布说明 | 最小检测中禁止 |
| `http-intake.logs.us5.datadoghq.com` | 可选运行指标 | 最小检测中禁止 |
| `browser-intake-us5-datadoghq.com` | 可选错误报告 | 最小检测中禁止 |
| `bridge.claudeusercontent.com` | Chrome 扩展连接 | 最小检测中禁止 |
| `formulae.brew.sh` | Homebrew 安装的更新检查 | 原生安装基线中禁止 |

固定主机表不是完整白名单。下面这些功能会增加动态地址：

- WebFetch 会先把目标主机名发给 `api.anthropic.com` 检查，然后读取目标网站。它可能访问任意获准域名。[WebFetch 说明](https://code.claude.com/docs/en/tools-reference#webfetch-tool-behavior)
- WebSearch 调用 Anthropic 的服务端搜索，不会直接读取搜索结果网页；如需读取结果，还会继续使用 WebFetch。[WebSearch 说明](https://code.claude.com/docs/en/tools-reference#websearch-tool-behavior)
- 远程 MCP 可以连接配置中的任意 HTTP 或 SSE 地址；stdio MCP 是本地子进程，但它自己仍可联网。[MCP 说明](https://code.claude.com/docs/en/mcp)
- 插件可以来自 Git、HTTP 或 npm，并可启动 hook、MCP、LSP 和其他程序。插件与市场都属于可执行代码。[插件市场说明](https://code.claude.com/docs/en/discover-plugins)
- Bash 可以启动 `git`、`curl`、包管理器和任意项目程序。这些连接属于子进程，不一定使用 Claude Code 自身的网络库。
- OpenTelemetry 启用后，可以通过 OTLP 把指标、事件和跟踪发到配置中的任意收集端。[官方监控说明](https://code.claude.com/docs/en/monitoring-usage)
- Amazon Bedrock、Google Cloud、Microsoft Foundry 或自定义 `ANTHROPIC_BASE_URL` 会改变模型和认证流量的目的地，必须建立独立基线。自定义网关启用 fast mode 时，部分可用性检查仍可能访问 `api.anthropic.com`。[第三方提供方和网关说明](https://code.claude.com/docs/en/network-config#network-access-requirements)
- Chrome、Remote Control、后台 agent、云任务和反馈命令都有额外连接，必须按功能单独测试。

`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` 会关闭更新、遥测、错误报告、反馈和发布说明等非必要流量，但不会关闭 WebFetch 域名检查，也不会关闭官方插件市场首次加入。
最小检测还要单独关闭插件市场和 Claude.ai MCP 连接器。[数据和遥测说明](https://code.claude.com/docs/en/data-usage#telemetry-services)、[环境变量说明](https://code.claude.com/docs/en/env-vars)

## 最小诊断配置

每次测试都从下面的共同配置开始：

```bash
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL=1
export ENABLE_CLAUDEAI_MCP_SERVERS=false
export CLAUDE_CODE_DISABLE_AGENT_VIEW=1
export CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1
export CLAUDE_CODE_AUTO_CONNECT_IDE=false
export CLAUDE_CODE_ENABLE_TELEMETRY=0
export DISABLE_UPDATES=1
```

每条命令还要带上：

- `--bare` 或 `--safe-mode`：按上面的认证基线二选一；
- `--no-chrome`：关闭浏览器集成；
- `--strict-mcp-config`：不加载其他位置的 MCP；
- `--no-session-persistence`：测试会话不写入历史；
- `--tools`：只提供当前测试需要的工具；
- `--allowedTools`：只自动批准当前测试明确需要的工具；
- `--permission-mode dontAsk`：未批准的工具调用直接拒绝，不等待交互；
- `--max-turns` 和 `--max-budget-usd`：限制循环和费用；
- `--session-id`：给代理日志和外层流量使用同一个已知 UUID。

`--tools` 只限制工具是否可见，不能代替授权。每个用例必须同时记录 `--tools`、`--allowedTools` 和权限模式。

这些参数都有正式 CLI 支持。[非交互运行说明](https://code.claude.com/docs/en/headless)、[CLI 参数说明](https://code.claude.com/docs/en/cli-reference)

这些参数用于隔离单个现象，不是最终使用方式。核心路径解释清楚后，还要在持久 Home 中直接运行 `claude`，让标准工具、会话标题、历史和正常交互流程全部参与验收。外层网关继续逐请求控制网络，不依赖 `--tools` 充当网络边界。

## 适合自动验收的输出

`claude -p` 是官方非交互入口，任务完成后退出。推荐保存两种输出：

1. 日常自动验收使用 `--output-format json --json-schema`。最终结果在 `structured_output` 中，脚本可以严格比较字段和值。
2. 调查工具调用时使用 `--output-format stream-json --verbose`。每行是一个 JSON 事件，可以看到模型、工具调用、结果和最后状态。

不要依赖自然语言中出现“成功”两个字。验收脚本应同时检查：退出码、JSON 类型、固定字段、生成文件、流量记录和明文内容。[结构化输出说明](https://code.claude.com/docs/en/headless#get-structured-output)

最小 API 任务可以使用：

```bash
CC_BIN=/opt/claude-code/2.1.220/claude
CC_SESSION_ID=550e8400-e29b-41d4-a716-446655440000
CC_RUN_ID=CCNET-EXAMPLE-0001
CC_CLEAN_ARGS=(--safe-mode)  # 账号登录基线；API Key 基线改为 (--bare)
: "${CC_TEST_MODEL:?must set a full model ID}"
CC_SCHEMA=$(jq -cn --arg run_id "$CC_RUN_ID" '{
  type: "object",
  properties: {run_id: {const: $run_id}, answer: {const: 42}},
  required: ["run_id", "answer"],
  additionalProperties: false
}')

printf '%s  %s\n' \
  674f61f20ff306f3100cf9200e4c36c4b70278b5bef2884549819b942a89c863 \
  "$CC_BIN" | sha256sum -c -

"$CC_BIN" -p "${CC_CLEAN_ARGS[@]}" --no-chrome \
  --session-id "$CC_SESSION_ID" \
  --tools "" \
  --permission-mode dontAsk \
  --strict-mcp-config \
  --no-session-persistence \
  --max-turns 2 \
  --max-budget-usd 0.20 \
  --model "$CC_TEST_MODEL" \
  --output-format json \
  --json-schema "$CC_SCHEMA" \
  "Return run_id $CC_RUN_ID and the integer result of 6*7."
```

实际运行时每次生成新的 UUID 和 `CC_RUN_ID`。上面的固定值只用于展示格式。
实际脚本也要像示例一样，根据当次 `RUN_ID` 动态生成 schema，并在执行前检查模型 ID 和二进制 SHA256。
官方从 `2.1.86` 起在 API 请求中发送 `X-Claude-Code-Session-Id`，外层代理可用它关联一次测试的多个 API 请求。[官方网关说明](https://code.claude.com/docs/en/llm-gateway#request-headers)

## 真实任务和检查顺序

不要一次打开全部功能。每项使用独立时间窗和新 `RUN_ID`；只有前一项流量已经解释清楚，才进入下一项。

### 1. 冷启动和空闲

开始前先记录 `claude daemon status` 和沙箱 cgroup 内的进程。若存在该用户以前启动的 supervisor 或 worker，不能把它们混入本次结果；停止现有进程前必须按项目规则取得用户确认。最稳妥的做法是在没有旧进程的新测试容器中运行。

分别运行：

```bash
"$CC_BIN" --version
"$CC_BIN" auth status
"$CC_BIN" doctor
```

然后保持空闲 10 分钟。空闲窗口内只允许测试容器的 init、审计组件和已经列明的 Claude Code 进程存在，进程清单随结果保存。官方只说明这些命令的用途，没有承诺它们完全离线，所以预期连接必须由现场记录确定。三条命令不能合并，否则无法判断是哪一条产生流量。

### 2. 只有模型请求

运行上面的 `6*7` 任务，不提供任何工具。

通过条件：

- JSON 中的 `run_id` 和 `answer` 完全匹配；
- 代理保存的是完整 HTTP 请求体和响应体，不只是命中 `RUN_ID` 的片段；
- API 请求体能解析为完整 JSON，其 session ID、模型、问题和工具配置与测试记录一致；
- 除当前认证方式需要的主机和 `api.anthropic.com` 外，没有其他连接。

明文完整性另用同一类任务执行一次 `--output-format stream-json --verbose --include-partial-messages`。验收程序解析代理保存的 SSE/JSON 和 Claude Code 的 `stream-json`，按顺序比较内容块、消息 ID、`stop_reason`、usage 和最后的 result 事件。缺少开头或结尾事件、JSON 无法解析、事件 ID 重复或乱序、内容或 usage 不一致、代理截断、PCAP 丢包、eBPF 丢事件，任何一项都判定失败。

### 3. 读取和写入文件

在一次性目录中创建 `input.txt`，内容包含新的 `RUN_ID` 和一个简单数字。该用例增加下面的参数，只提供并批准 `Read` 和 `Write`：

```bash
--tools "Read,Write" --allowedTools "Read,Write" --permission-mode dontAsk
```

让 Claude Code 读取文件并写出固定 JSON，例如：

```text
读取 input.txt。把其中的整数乘以 2，将结果写入 result.json。
result.json 只能包含 run_id 和 result 两个字段。
```

通过条件是 `result.json` 精确匹配预期，API 请求明文包含输入文件内容，且没有 Bash、WebFetch、MCP 或未知子进程。

### 4. WebSearch

使用 `--tools "WebSearch" --allowedTools "WebSearch" --permission-mode dontAsk`，要求搜索包含 `RUN_ID` 的固定查询，并把工具返回的标题数量写入结构化结果。

通过条件：

- `stream-json` 中确实出现一次 WebSearch 工具调用；
- 本地只观察到 Anthropic 连接，没有直接连接 Google、Bing 或搜索结果网站；
- 查询文字能在 Anthropic API 明文中找到。

WebSearch 可能在服务端内部细化查询，结果数量也会变化，所以不能把某个标题或数量作为长期固定值。
模型也可能没有调用工具。每个 `RUN_ID` 最多重试三次；`stream-json` 中没有 WebSearch 工具调用时，该次记为“用例未执行”，不能记为网络检测失败。

### 5. WebFetch

准备一个外部受控 HTTPS 测试站点。每个 URL 都包含新的 `RUN_ID`，返回正文也包含同一个值。使用 `--tools "WebFetch" --allowedTools "WebFetch(domain:audit.example)" --permission-mode dontAsk`，其中 `audit.example` 替换为受控站点的真实域名。要求 Claude Code 读取该 URL 并返回标记。

通过条件：

- 目标站点收到预期 URL 和以 `Claude-User` 开头的 User-Agent；
- 外层代理保存目标请求和响应的完整明文；
- 同时记录发往 `api.anthropic.com` 的域名安全检查；
- 没有连接 URL 中未登记的跳转主机。

WebFetch 有 15 分钟缓存，必须使用新的 URL，不能用重复 URL 判断是否漏流量。[WebFetch 缓存和跳转规则](https://code.claude.com/docs/en/tools-reference#webfetch-tool-behavior)

### 6. Bash 子进程的大内容传输

在一次性目录放置固定的 `audit-transfer.sh`。脚本只连接受控 HTTPS 站点，上传和下载各 64 KiB 测试内容。内容由多个带序号的块组成，并记录原始长度和 SHA256。

先用 `realpath` 得到脚本绝对路径，然后使用 `--tools "Bash" --allowedTools "Bash(/绝对路径/audit-transfer.sh)" --permission-mode dontAsk`。提示词要求只运行该绝对路径，不带参数。这样 Claude Code 只能获准执行这一条脚本；外层防火墙仍是最终限制，不能依赖 Bash 命令匹配保护网络。

通过条件：

- 能把连接归属到 Claude Code 启动的 shell 和传输程序；
- 上传与下载的重建字节长度和 SHA256 完全一致；
- 系统证书库或该程序自己的 CA 配置确实经过解密代理；
- 没有丢包、丢事件、截断或密文透传。

这项检查的是 Claude Code 子进程路径，不代表主程序的 TLS 路径。

### 7. Git HTTPS

使用专门的只读测试仓库，让 Claude Code 执行固定绝对路径的脚本读取远程引用和一个已知文件。工具参数与上一项相同，只把批准规则换成 `Bash(/绝对路径/audit-git-read.sh)`。不使用 SSH，不执行 push，不接触正式仓库。

通过条件是远程提交 ID 与预期一致，GitHub HTTPS 明文完整，所有 Git 子进程都有归属。Git 自己的重试、重定向和凭据请求也要逐条解释。

### 8. MCP

分开测试两类 MCP：

- 远程 HTTP MCP：使用 `--mcp-config` 指向受控服务，并带 `--strict-mcp-config`；
- stdio MCP：启动一个固定哈希的本地测试程序，由它连接受控 HTTPS 服务。

每个服务只提供一个返回 `RUN_ID` 的无副作用工具，例如 `mcp__audit__echo`。该用例使用 `--tools "mcp__audit__echo" --allowedTools "mcp__audit__echo" --permission-mode dontAsk`。通过条件是 MCP 工具结果匹配，主程序和 MCP 子进程的连接都能分别归属和解密。

MCP 和插件测试默认使用 API Key 基线：`--bare` 加显式的 `--mcp-config` 或 `--plugin-dir`。若必须测试账号登录，则使用独立 `CLAUDE_CONFIG_DIR`，不加会关闭这些自定义内容的 `--safe-mode`，并把它记录为第三套独立基线。

### 9. 插件

使用本地、固定哈希、无副作用的测试插件。插件只包含一个明确的 hook 或 MCP，访问受控测试站点。不要先测试在线市场安装，否则安装下载和插件运行会混在一起。

通过后再单独测试官方市场加入、插件下载和插件更新。安装、运行和更新是三条不同网络路径，不能用其中一条代替另外两条。

### 10. OpenTelemetry

使用纯测试提示词和受控 OTLP 收集端，单独设置 `CLAUDE_CODE_ENABLE_TELEMETRY=1`、`OTEL_LOGS_EXPORTER=otlp`、`OTEL_METRICS_EXPORTER=otlp` 和 `OTEL_EXPORTER_OTLP_ENDPOINT`。运行一次带新 `RUN_ID` 的模型任务，等待至少一个日志和指标导出周期。

通过条件是收集端收到预期 session、提示事件和指标，连接可以归属并解密，且没有访问未登记的收集端。需要额外比对 API 正文时，可以在这项测试中使用官方 `OTEL_LOG_RAW_API_BODIES=file:<dir>` 生成不截断的本地副本；它只作为实验室交叉检查，不能代替外层代理，也不能证明关闭该功能后的流量仍能完整捕获。[OpenTelemetry 内容记录说明](https://code.claude.com/docs/en/monitoring-usage#common-configuration-variables)

### 11. 阻断和报警

负向测试开始前，先建立专用 canary 网络命名空间。把测试用的私网、链路本地、云元数据、保留公网、DNS 和代理地址全部路由到 canary 中的受控接收端；canary 不得有通往宿主机局域网、真实云元数据或公网的路由。即使阻断规则失效，请求也只能到达 canary。

然后让 Claude Code 分别启动固定脚本，尝试：

- 未加入白名单的测试域名；
- IPv4 和 IPv6 直接连接；
- TCP/22 和代理 `CONNECT` 到 IP；
- 外部 DNS、DoT/853 和允许域名上的 DoH；
- UDP/443；
- 私网、`169.254.169.254`、DNS 重绑定和容器 loopback。

每次只测试一种。所有目标都使用 canary 中的自有接收端或保留测试地址，不扫描第三方，也不能触达真实内网。

这组负向测试在严格策略下执行。本文是透明迁移前的测试设计；当前实现允许普通公网域名解析，再由 Web 策略审核请求。直连、私网、外部 DNS、UDP 绕过或捕获失效仍应触发阻断并保留现场。当前行为以 [网络设计](../network.md) 为准。

## 进程和 TLS 捕获

Claude Code 不应只按一个 PID 检测。它可能启动 shell、Git、curl、hook、插件、LSP、stdio MCP、后台 supervisor 和其他 Claude Code worker。
官方还提供 `CLAUDE_CODE_PROCESS_WRAPPER` 来覆盖它自行启动的后台服务和 worker，提供 `CLAUDE_CODE_SHELL_PREFIX` 来覆盖 Bash、hook 和 stdio MCP；两者覆盖对象不同。[官方进程包装说明](https://code.claude.com/docs/en/corporate-launcher)

这些包装器只能作为辅助标记。最终范围仍由沙箱 cgroup 和专用虚拟网卡确定，因为：

- 终端直接启动的第一个 Claude Code 进程不受 `CLAUDE_CODE_PROCESS_WRAPPER` 覆盖；
- shell 子进程需要另一套包装方式；
- 插件和项目程序可以继续创建更多进程；
- 包装器配置错误不能导致审计范围缩小。

本机在 2026-07-28 做过一次只读观察：现有 `2.1.220` 是 `linux-x64` ELF，SHA256 与官方 manifest 一致；`ldd` 列出的动态依赖中没有 `libssl`。这只说明当前这个文件不能直接套用普通 OpenSSL 动态库探针，不证明它没有内置 TLS，也不代表未来版本相同。

因此第一套方案应这样分工：

1. 在专用虚拟网卡保存全部数据包；
2. 用 cgroup 级 eBPF 记录网络连接归属，用 tracepoint、BPF LSM、fanotify 或 audit 中经过验证的一种方案另行记录进程和文件变化；
3. 用外层解密代理和自定义 CA 保存 Claude Code 主程序的 TLS 明文；
4. 对每个子程序检查 `/proc/<pid>/exe`、文件哈希、`/proc/<pid>/maps` 和实际证书库；
5. 只对已确认使用某个 OpenSSL 文件或 Go TLS 的程序增加对应 eBPF 明文探针；
6. 代理无法解密、证书不被接受或出现未知 TLS 实现时，保持阻断并单独研究，不能自动密文放行。

eBPF 对 Claude Code 主程序的首要用途是连接归属和发现新进程，不应预先承诺某个 OpenSSL hook 能取得它的全部明文。

## 完整捕获验收标准

下面是把平台写成“高负载下也没有捕获缺口”前必须满足的标准。本机 API-key 日常策略只依据已覆盖真实工作流和基本门禁，不声称已经达到这套完整标准；公开发布也不继承本机私有端点或运行证据：

- 二进制版本和 SHA256 与基线一致；
- 二进制仍由 root 所有，且被测用户不能修改；
- 所有测试命令、模型 ID、配置、凭据类型和外层策略都有记录；
- 每条放行连接都有进程、域名、地址、端口、协议、PCAP 和策略版本；
- Claude Code 主程序及已启用子程序的每条 TLS 连接都有请求明文和响应元数据；需要响应正文的用例另设专项捕获；
- 已知测试内容的长度、顺序和 SHA256 能从明文记录中重新验证；
- 没有无法解释的 DNS、连接、重试、子进程或后台流量；
- PCAP 丢包、eBPF 丢事件和代理截断计数都为零，没有日志写入失败或密文透传；
- 捕获组件停止、日志目录不可写、CA 错误和未知连接都会切回阻断；
- 阻断测试的处理级别与预期一致；
- 测试结束后的空闲窗口没有未解释的连接。

严格分析期间发现新流量时先保持暂停并查清来源，不能因为域名看起来属于常见服务就直接加入规则。进入日常策略后，新的公网 HTTP/HTTPS 域名可以先放行并记录；当前没有主动首次域名提示。无法解释的进程、正文或应用层再次加密仍会使原验收结论失效。

## 必须现场确认的事项

下面的结论不能从官方文档直接推出，必须对固定版本实测：

- 官方固定主机表是否覆盖当前账号、地区和功能产生的全部连接；
- 每个域名实际使用的 CNAME、IP、重定向和协议；
- WebSearch 在本机是否只通过 Anthropic API，WebFetch 的实际发起进程是什么；
- Claude Code 主程序实际使用的 TLS 实现、是否接受解密 CA、是否存在不能代理的连接；
- HTTP/2、流式响应、连接复用、重试和会话恢复能否完整重建；
- 登录、令牌刷新和退出分别访问哪些主机；
- `--bare`、`--safe-mode` 和各关闭开关在当前版本是否确实消除对应的插件、MCP、遥测、更新和后台流量；
- Bash、Git、插件、hook、LSP 和 MCP 是否继承代理和 CA；
- cgroup 内是否出现新的可执行文件、动态库或更深的子进程；
- 代理、eBPF、PCAP 和应用输出能否通过同一个 session ID 和 `RUN_ID` 对齐；
- 捕获高负载、磁盘写满和组件退出时是否真正 fail closed；
- 更新到新版本后是否增加域名、进程、协议或新的证书处理方式。

Claude Code 的官方 GitHub 仓库并未提供当前原生 CLI 的完整可审计源码。因此，官方文档可以确定受支持的配置和已声明的主机，但不能替代流量实测，也不能单独证明“全部明文已经捕获”。
