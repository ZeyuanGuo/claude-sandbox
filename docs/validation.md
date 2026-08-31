# 公开验收摘要

这份文档只保存可公开、可迁移的结论。主机运行编号、会话标识、真实出口、私有接口、硬件清单、完整请求和原始证据不进入 Git。每台服务器必须保存自己的运行清单和审计证据，不能直接继承这里的结论。

## 发布级检查清单

公开发布提交固定了源码、镜像输入和策略摘要。发布前的可重复检查为：

```bash
PYTHONPATH=src python -m pytest -q
python -m ruff check src gateway tests
python -m compileall -q src gateway
bash -n bin/sandboxctl gateway/mitmproxy/entrypoint.sh
bin/sandboxctl policy validate policies/strict/0001-bootstrap.yaml
bin/sandboxctl policy validate policies/strict/0002-claude-account.yaml
bin/sandboxctl policy validate policies/daily/0001-public-web.yaml
```

公开策略摘要是：`strict/0001` `58e5267d...`，`strict/0002` `ff93b683...`，`daily/0001` `55712df7...`。省略号只用于文档阅读；部署清单和 Git 提交保存完整摘要。Claude Code 的固定版本契约见研究文档，主机私有凭据、出口、时区和运行证据不属于这份公开摘要。

## 已验证

- 单元和集成测试覆盖配置归属、策略解析、严格审核、日常 Web、DNS 公网地址校验、名称-IP 租约、透明目的地址核对、网关故障闭锁、镜像固定、会话脱敏迁移和审计状态。
- `verify-closed` 覆盖普通公网 DNS、危险解析结果、直接 IP、外部 DNS、TCP/22、UDP、原始 TCP、协议升级、应用层 `CONNECT`、策略摘要故障、审核存储故障和探针退出。
- 透明路径已用 curl、Git HTTPS、Node、系统 Python 和 Conda Python 验证标准 CA 信任；目标容器不需要代理变量或自定义 DNS 配置。
- Claude Code 的 API-key 基线覆盖连续对话、文件读写、测试、本地 Git、Git HTTPS、WebSearch、WebFetch、curl、子 agent、会话恢复、Skill、MCP 工具/资源/prompt 和 hook。
- 会话导入会生成新标识并脱敏已识别凭据；原始会话标识和本机恢复结果不会写入发布仓库。

## 已观察到的发送内容

Claude Code 的已测请求包含容器内核和平台、架构、项目绝对路径、Git 摘要、客户端版本、设备/会话标识、对话、工具定义、工具参数、工具输出和读取的文件内容。已测人工任务没有观察到实际时区、CPU/GPU 型号、内存、MAC、内网 IP、代理地址或 CA 路径。

这个结论只适用于被测版本、认证方式、配置和任务。没有命中某个字段不等于软件永远不会发送它；版本、认证、插件、MCP 或联网组件变化后必须重新测试。

历史 API-key 基线使用的私有端点和规则已从仓库删除。需要同类端点时，部署者必须在本地创建新的策略快照并重新验收；发布日常策略不会放行未登记的直接 IP。

## 仍未完成

- 账号登录、令牌刷新、退出和账号模式下的完整开发回归；
- 同一 Claude 任务在安装 CA 但不解密、显式解密、透明解密和不同 eBPF 状态下的随机顺序对照；
- 大正文、长连接、高并发、TLS 1.2/1.3、HTTP/1.1/2、PCAP 丢包和 eBPF 丢事件的完整压力矩阵；
- 自动轮转、磁盘上限和丢事件的持续联锁仍需在重启后的真实运行中验证。

因此当前结论是：框架已具备受控日常开发所需的透明 DNS/HTTP/HTTPS、基本旁路阻断和请求审计能力；它不是完整虚拟机隔离，也不构成对所有应用、版本和协议的普遍安全证明。

## 新主机验收

新主机必须按 [部署与操作](operations.md) 从固定提交开始，依次执行：

```bash
bin/sandboxctl config init
# 编辑 host.yaml，填写本机项目、环境和出口范围
bin/sandboxctl config validate
sudo bin/sandboxctl doctor --json
sudo bin/sandboxctl storage plan
sudo bin/sandboxctl init --policy policies/strict/0002-claude-account.yaml
sudo -E bin/sandboxctl build
sudo bin/sandboxctl start
sudo bin/sandboxctl verify-closed
```

随后进入容器验证实际 Python、关键 import、GPU 计算、Git HTTPS 和一项允许公开的 Claude 开发任务。只有本机生成的这些证据全部通过，才算复现成功。
