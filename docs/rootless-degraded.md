# Rootless Docker 降级模式

4090a/4090b 的 Docker 是 rootless 用户级 daemon，因此不能复现默认模式依赖的宿主 nftables、目标 cgroup eBPF、目标/DNS/网关命名空间 PCAP、宿主网络转发和 root-only lifecycle lock。

`bin/sandboxctl-degraded` 提供独立降级路径：

```bash
sandboxctl-degraded doctor
sandboxctl-degraded import-images
sandboxctl-degraded render
sandboxctl-degraded up
sandboxctl-degraded status
sandboxctl-degraded down
```

需要把 target 的所有 IP 外联进一步收紧时，可在同一用户 shell 中设置
`CDM_DEGRADED_STRICT_LOCAL=1` 后再执行 `render` 和 `up`。该可选模式把 target
改为 `network_mode: none`，只保留 loopback，并由两个低权限 bridge 通过私有
Unix socket 把 `HTTP_PROXY/HTTPS_PROXY` 转入现有 gateway；清除代理变量、写死
公网 IP、TCP/UDP/QUIC 或 raw socket 都没有外部网卡可用。验证完成后，取消该变量
重新 render/up 即可回到兼容开发模式。

它保留目标 rootfs、Claude/CDM 代码、持久 Home、策略文件和 mitmproxy 应用层审计。目标容器只加入 `target_net`（Docker internal network），通过显式 `HTTP_PROXY/HTTPS_PROXY` 访问 gateway；gateway 才加入 egress 网络。没有配置 `CDM_DEGRADED_UPSTREAM_HOST/PORT` 时，gateway 没有公网网络，模式只用于离线和阻断测试。

保留能力：

- rootless Docker 下的主目标容器和 GPU 可见性（若 rootless CDI 已配置）；
- 目标容器持久 Home、项目和 Claude 配置；
- 网关正则 HTTP/HTTPS 代理、strict/daily 策略、请求审核、明文 flow 审计和 fail-closed addon；
- 目标不能从 `target_net` 直接访问公网，代理不可用时请求失败。

明确降级：

- 宿主 nftables 透明重定向不可用，目标侧使用显式代理环境变量；
- 宿主 tcpdump、目标/DNS/网关 PCAP、cgroup eBPF 和 watchdog 续租不可用；
- 网络证据以 gateway flow、应用审核记录和 Docker 网络拓扑为主；不能声称具备 root 模式的包级/进程级完整审计；
- 不自动启动真实 Claude 账号会话。先完成 `doctor`、镜像导入、离线 target 命令、网关策略和 direct-egress 负向测试，再单独核对出口、DNS、时区和语言。

严格本地模式的代价：普通直连 SSH、数据库、任意非 HTTP(S) 协议会失败；需要的协议必须
另做审计过的 Unix-socket bridge。target 内部的 loopback 和 Unix IPC 仍然是本地通信，
rootless 无法像宿主 root+nftables/eBPF 那样逐连接拦截或审计它们。

`CDM_DEGRADED_UPSTREAM_HOST/PORT` 只接受已核对的原 5090 代理地址；配置前不启动 egress 网络。真实账号测试必须在同一代理出口、同一策略和同一 CA trust 条件下由人工执行。
