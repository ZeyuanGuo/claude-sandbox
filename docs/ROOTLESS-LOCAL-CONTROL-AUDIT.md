# Rootless 本地流量控制审查

日期：2026-10-07（Asia/Shanghai）

本文只讨论 4090a/4090b 的 rootless Docker 降级拓扑，不把它描述成
5090 上的 root/透明模式。

## 当前边界

当前 `degraded_topology.py` 给 `target` 连接 `target_net`，并通过
`HTTP_PROXY`/`HTTPS_PROXY` 指向 gateway 的普通 HTTP 代理。`target_net` 是
Docker `internal` 网络，target 没有外部网络和默认公网路由；gateway/relay
才有到父代理的受控路径。因此，遵守代理环境变量的 HTTP(S) 请求会按策略
审查并经固定父出口转发，清除代理变量时仍因无路由而失败。

但这不是任意 socket 的拦截：

* `127.0.0.1`/`::1` 是 target 自己的 network namespace 的 loopback。该流量
  只在 target 内部进程之间流动，既不经过 target veth，也不可能被 sibling
  gateway 看到。`NO_PROXY=localhost,127.0.0.1` 目前还明确让标准客户端绕过代理。
* Unix-domain socket 是文件系统 IPC，不属于 IP 流量；同一容器内可访问的
  socket 不会经网关。挂载 Docker socket、宿主 agent socket 或可写 socket
  目录会形成独立的越权通道，当前拓扑没有自动拦截能力。
* 未使用代理的 TCP、UDP、QUIC、原始 socket、应用自带 DNS 等不能靠环境变量
  约束。当前无默认路由和 `CAP_NET_RAW`/`CAP_NET_ADMIN` 能阻断大部分外联，
  但不能证明“所有协议都被透明代理”。
* 容器内进程可以修改自己的环境变量；`LD_PRELOAD`、proxychains 等包装器
  是兼容性手段，不是恶意程序面向的安全边界。

### SSH

5090 的 SSH 白名单依赖宿主 `tailscale0` 和 `100.64.0.0/10` 地址。4090a/b
当前没有 Tailscale 接口或对应路由，因此不能把旧 SSH 规则原样宣称为已恢复；target
也没有直达 SSH 的外部路径。严格模式下 SSH、数据库等非 HTTP(S) 协议默认失败。
若以后宿主恢复 Tailscale，建议新增独立的固定目标 SSH bridge：只接受声明的
`100.64.0.0/10` 地址和端口，使用父 Mihomo 的 CONNECT，无 direct fallback，并为
每个目标写入审计记录；不要把 SSH 混入普通 HTTP(S) allowlist。

## 不依赖宿主 root 的最强可行方案

可以增加一个 **network-none + Unix proxy bridge** 变体：

1. target 使用 `network_mode: none`，只保留 loopback；不能看到任何 veth、
   内部网段、父代理或外部网卡。
2. 一个低权限 bridge 与 target 共享这个“无网” namespace，仅监听
   `127.0.0.1:8080`（以及可选的本地 DNS 端口），把字节流转发到一个
   **只读挂载目录中的 Unix socket**。
3. gateway 在自己的受控 namespace 中运行 Unix-socket-to-local-TCP
   forwarder，Unix socket 再转给现有 mitmproxy `127.0.0.1:8080`；gateway
   仍是唯一拥有 `target_net`/`upstream_net` 的审查点。
4. socket 目录对 target 只读、socket 文件由不同 UID/组拥有；target 可以
   连接但不能替换/删除 bridge socket。target 运行用户不应是 bridge 的
   所有者，避免普通 `kill`/替换。

这样，target 的任意 **IP 外联** 都没有接口可用；即使清掉代理变量、写死
公网 IP、发 UDP/QUIC 或创建 raw socket，也只能命中 loopback，无法离开
namespace。通过 `HTTP_PROXY=127.0.0.1:8080` 的 HTTP(S) 仍由 gateway 策略
审查并走固定洛杉矶父出口。Unix socket 本身仍然是受控的单一代理入口，
不是一个可被网关审查的通用 IPC 总线。

## 代价与不能隐瞒的限制

* 这不是对现有 Compose 的无风险开关：需要 bridge 镜像/进程、socket 生命周期
  和健康检查；target 必须先启动 bridge，再接受开发命令。
* 运行在 target 内的标准 HTTP 客户端通常兼容显式代理；自行建立 TCP/UDP、
  需要直连数据库/SSH 的工具会失败。可为明确的协议增加独立、审计过的
  Unix-socket 协议代理，但不能给 target 恢复一张普通网卡。
* DNS：HTTP CONNECT 客户端可让 gateway 远端解析域名；需要本地解析的程序
  必须使用 Unix-socket DNS bridge（或只提供固定 hosts），不能把 `/etc/resolv.conf`
  指向一个 target 可直连的网段 DNS，否则会重新引入绕过路径。
* target 内部的进程间 loopback/Unix IPC 仍可互相通信；rootless 模式无法像
  root+nftables/eBPF 那样观察或阻断同一 namespace 内部通信。应通过不挂载
  敏感 socket、只读 socket 目录、不同 UID、最小文件权限降低风险。
* 若 bridge 与 target 共享 namespace，必须保证 bridge 监听端口和 Unix socket
  不能被 target 用户替换；否则 bridge 仅是约定而非边界。

## 备选方案比较

| 方案 | 外联控制 | 本地 IPC 控制 | 兼容性 | 结论 |
| --- | --- | --- | --- | --- |
| 当前 internal network + 显式代理 | 可靠阻断无路由外联；遵守代理时可审计 | 不控制 loopback/Unix | 高 | 适合日常开发，不能宣称任意协议 |
| `network_mode:none` + Unix proxy bridge | 最强：无 IP 外联接口 | 可限制代理 socket；同 namespace IPC 仍存在 | 中 | 若“尽可能全控”优先，建议新增隔离模式 |
| 共享 gateway namespace | 有外联路由，应用可直连 relay/parent | 不安全 | 高 | 不采用，会产生绕过 |
| LD_PRELOAD/proxychains | 仅包装部分动态程序 | 不控制 | 中/低 | 只能作开发便利，不作安全边界 |
| rootful nftables/eBPF/TUN | 可透明拦截并记录任意 IP 流量 | 仍需额外 IPC 策略 | 高 | 只有取得宿主 root 时才可恢复 5090 级别 |

## 建议验收

在不触碰真实账号的情况下，对新变体执行：清除所有代理变量、写死公网
IPv4/IPv6、TCP/UDP/QUIC、DNS、IPv6 loopback、Unix socket 替换/删除和
bridge/gateway 停止测试；预期全部外联失败，代理 HTTP(S) 仍通过策略和固定
父出口。真实 Claude 测试只能在该验收完成、同一 LA 父代理与 CA/策略一致后
进行。
