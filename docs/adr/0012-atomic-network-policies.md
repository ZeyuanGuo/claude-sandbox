# 网络策略使用完整快照和原子 generation

严格与日常策略是两份完整、不可原地修改的 YAML 快照。每份快照记录父摘要、默认 Web 动作、明确规则和证据；更新时新增文件，因此可以回滚。

`sandboxctl init --policy` 先校验策略和临时 Compose，再把策略、运行清单和 Compose 写入新的 generation。全部成功后才原子更新 `current` 符号链接；失败不会提前改动活动 generation。`start` 再核对策略摘要、控制源码以及目标/网关镜像标签。

当前切换流程是：

```text
stop -> init --policy -> build -> start -> verify-closed
```

严格策略暂停未知 Web 请求。日常策略默认允许普通公网 HTTP/HTTPS，并保存请求正文、双向头字段、响应状态和传输结果；当前没有首次域名提醒服务。公开日常策略默认阻断直接 IP；私有 API 测试端点必须由部署者在本机创建精确规则并重新验收。特殊主机名、外部 DNS、UDP/QUIC 和非 Web 协议不随日常策略放开。

当前控制器只允许部署 `strict` 和 `daily`。`maintenance`、`observe` 及自动 TTL 回退仍是未来设计，不能当作可用命令。
