# 出口代理与网络隔离方案调研

本文回答一个问题：第一版应怎样组合代理、DNS、容器网络和外部代理/VPN，做到默认拒绝、允许流量可审计、解密失败不自动透传。

本文依据官方资料做设计判断，**没有在本机完成配置或端到端实测**。下文凡是具体组合、参数和故障行为，均是建议或待验证项，不能视为当前已经具备的能力。

本文记录透明迁移前的方案比较和风险清单。后续实现已经改为自有受控 DoH、DNS-IP 租约、nftables 透明重定向和审计出口租约，不再使用 `deny DNS + mitmproxy regular` 作为当前路径。当前状态以 [网络设计](../network.md) 和 [公开验收摘要](../validation.md) 为准；下文中的“首版”“建议”和“尚未实现”保留为当时的研究结论，不是当前运行状态。

## 结论

建议第一版采用：

```text
目标容器
  |  显式 HTTP(S)_PROXY；网络只可达项目 DNS 与代理端口
  v
mitmproxy regular 模式 + 策略连接器
  |  按策略检查域名、端口和协议；一次解析并固定实际连接 IP
  |  终止 TLS；记录双向明文并按字节验收完整性
  v
TUN / VPN 出口适配器
  |  只负责把已批准连接送到外部出口
  v
互联网
```

受控 DNS、mitmproxy 策略和网络规则必须由同一份带版本的策略快照生成。外部 Clash 可用 YAML 或 VPN 配置只交给出口适配器，不能交给目标容器，也不能决定放行哪些域名。

项目 DNS 的首版组合建议固定为 `dnsdist + Unbound`：dnsdist 在严格策略下执行精确域名或显式受信后缀规则，在日常策略下接受公网域名，并记录全部查询；Unbound 负责递归解析、DNSSEC 校验和危险地址过滤。DNS 查询本身不判断后续协议，HTTP/HTTPS 限制由代理与网络层执行。二者不是两套独立策略，所有规则都由同一策略快照生成；mitmproxy 的策略连接器也只使用这条解析路径。

这里的“策略连接器”不能只是先查一次 DNS、再让 mitmproxy 自己重新解析。建议第一版把它实现为 mitmproxy addon 的一部分：它读取 CONNECT authority，使用项目 DNS 得到候选地址，拒绝全部危险地址，选择一个批准 IP，并在上游 socket 创建前把该连接固定到这个 IP；原域名继续用于 SNI、Host 和证书名称校验。具体 mitmproxy API 和事件顺序必须先用受控域名、DNS rebinding 与 PCAP 证明；若无法证明没有第二次解析或先连接后检查，该原型失败并保持阻断。

每条 Web 连接都要由同一段策略代码执行以下检查：域名先做统一的大小写、末尾点和 IDNA 规范化；严格策略只允许精确名称或单独批准的受信子域，日常策略可接受新的公网 Web 名称；HTTPS 的 CONNECT 域名、端口、TLS SNI、解密后的 HTTP Host 或 HTTP/2 `:authority` 以及上游证书名称必须一致；普通 HTTP 的目标域名与 Host 必须一致。IP 形式 CONNECT、无 SNI 的 HTTPS、策略外端口和无法规范化的名称直接拒绝。CONNECT 后必须完成受控 TLS 解密，不能透传 raw TCP。任何检查都必须发生在发送应用正文之前。

历史首个实现步骤没有做透明代理；它用于建立 API-key 功能和内容基线。之后已经完成透明迁移并重新执行网络门禁。显式运行的业务结果仍是历史证据，不能自动写成透明条件下相同任务的行为对照。

第一版仍不能只靠 mitmproxy 自身守住边界。网络层必须保证目标容器无法直连公网；mitmproxy 的策略插件必须在上游连接前执行当前完整策略；出口层还必须检查最终连接地址。任何一层失效，都不能出现直连或密文透传。

## 代理选择

| 组件 | 官方能力 | 关键限制 | 本方案判断 |
|---|---|---|---|
| mitmproxy | 支持显式、透明、上游和 TUN 等模式；可终止 TLS、保存 HTTP 流并用 Python addon 检查事件 | `allow_hosts`/`ignore_hosts` 会让未处理流量原样通过；addon 报错后进程不一定退出；透明和上游是不同入口模式 | 第一版明文审计核心，但授权不能依赖内置 host 过滤；必须配独立网络阻断和健康联锁 |
| Squid 6/7 | `ssl_bump` 可解密 TLS；ACL、父代理和 `never_direct` 可构成独立控制层 | `ssl_bump` 无匹配规则时默认 `splice`；Squid 8 已移除相关指令；访问日志不等于完整正文 | 可作为第二道元数据策略或备选实现；不是首版必需项，加入前先验证版本、无透传和父代理故障行为 |
| Envoy | HTTP dynamic forward proxy、RBAC、DNS 缓存和私网地址过滤能力较强 | SNI dynamic forward proxy 是 TLS 透传且标为 alpha；通用按任意目标动态签证书不是官方 DFP 路径；CONNECT 配置复杂 | 适合以后做外围策略或连接层原型，不作为首版 TLS 明文核心 |
| HAProxy | ACL、SNI、动态解析、上游 TLS 校验；3.2 手册还提供透明正向代理的动态证书生成 | 官方日志能力不等于完整双向正文；任意目的连接、完整审计和外部上游组合仍需额外设计 | 技术上能做部分透明 MITM，不能写成“完全不支持”；但首版选择它会增加自研和验证范围，因此不采用 |

### mitmproxy 必须避开的错误用法

1. 不使用 `allow_hosts` 或 `ignore_hosts` 实现安全白名单。官方说明它们决定哪些连接由 mitmproxy 处理；未处理连接会原样转发，而不是拒绝。[官方说明](https://docs.mitmproxy.org/stable/howto/ignore-domains/)
2. 显式固定 `connection_strategy=lazy`，并在固定镜像版本上导出实际选项核对。官方[选项页](https://docs.mitmproxy.org/stable/concepts/options/)与[事件页](https://docs.mitmproxy.org/stable/api/events.html)对默认值的描述存在差异，不能依赖默认行为。
3. 策略检查不能只放在普通 HTTP `request` 事件。待实现时至少要验证 `http_connect`、`tls_clienthello` 和 `server_connect` 的执行顺序，确保拒绝发生在真实上游连接之前。[事件顺序](https://docs.mitmproxy.org/stable/api/events.html)
4. 关闭未知 raw TCP 和 HTTP/3/QUIC 路径；UDP 在网络层默认拒绝。任何无法解密的连接都终止，不能设置 `ignore_connection`，因为该设置会转成密文直通。[TLS API](https://docs.mitmproxy.org/stable/api/mitmproxy/tls.html)
5. 保持上游证书校验，不能启用 `ssl_insecure`。大正文若使用流式转发，还要验证正文确实被保存；官方选项说明流式正文默认不会保存在 flow 中。[选项说明](https://docs.mitmproxy.org/stable/concepts/options/)
6. addon 发生异常时不能只依赖 mitmproxy 自己退出。官方说明 addon 错误会记录日志，而 addon 继续加载；因此出口放行必须受独立健康联锁控制。[Addon 说明](https://docs.mitmproxy.org/stable/addons/overview/)

### Squid 的正确边界

若第二阶段加入 Squid，建议只让它承担独立的域名、端口、父出口和元数据审计，不再做第二次 TLS 解密。若单独评估 Squid MITM，则必须固定 Squid 6/7，并满足：

- `ssl_bump` 规则显式覆盖批准路径，最后以 `terminate all` 收尾；官方默认和未匹配结果都是 `splice`。[ssl_bump](https://www.squid-cache.org/Doc/config/ssl_bump/)
- 精确域名与受信后缀分开生成。`dstdomain` 中前导点表示包含子域名，不能误当精确匹配。[ACL](https://www.squid-cache.org/Doc/config/acl/)
- 父代理使用 `cache_peer` 并配合 `never_direct allow all`；必须实测父代理停机后没有直接连接。[cache_peer](https://www.squid-cache.org/Doc/config/cache_peer/)、[never_direct](https://www.squid-cache.org/Doc/config/never_direct/)
- 不关闭上游证书校验，不允许证书错误继续。
- 访问日志只能证明元数据，不等于保存完整请求和响应正文。若引入 ICAP/eCAP 保存正文，适配服务故障也必须触发阻断。[内容适配说明](https://wiki.squid-cache.org/SquidFaq/ContentAdaptation)

### 为什么暂不选 Envoy 或 HAProxy

Envoy 的 HTTP dynamic forward proxy 可做动态目的连接和上游 TLS 校验，但官方明确警告不受信客户端可能把它变成访问内部服务的代理，必须另配防火墙和默认拒绝。SNI dynamic forward proxy 仍是 TLS 透传，不满足明文审计。[HTTP DFP](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/dynamic_forward_proxy_filter)、[SNI DFP](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/sni_dynamic_forward_proxy_filter)

HAProxy 3.2 官方手册确实提供 `generate-certificates` 与 `ca-sign-file`，可在透明正向代理中按 SNI 生成证书，因此不能简单写成“不支持动态 MITM”。问题在于它不是完整正文审计工具；若补齐内容保存、连接控制和外部出口，首版需要较多自研。[HAProxy 3.2 配置手册](https://docs.haproxy.org/3.2/configuration.html#generate-certificates)

## 容器网络边界

目标容器只连接一个专用网络，不连接宿主默认 bridge、外部网络或出口适配器网络，也不发布端口。代理和网关组件可以分别连接目标侧网络和出口侧网络。

Docker `internal` 只阻断外部路由，官方明确说明容器仍可访问 bridge 网关地址上的宿主服务。Docker 28 以后可结合 IPv4/IPv6 `gateway_mode=isolated`，让该 bridge 不给宿主分配网关地址；这应作为首选待验证方案，而不是把 `internal` 单独当作完整隔离。[network create](https://docs.docker.com/reference/cli/docker/network/create/)、[Docker 28 发布说明](https://docs.docker.com/engine/release-notes/28/)

### 必须解决的“无路由与数据包记录”冲突

当前测试要求每次连接尝试都留下数据包记录。但 `internal` 网络没有默认外部路由时，程序对公网地址调用 `connect()` 可能在本机直接得到 `ENETUNREACH`，根本不会产生数据包。两项要求不能同时默认成立。

首版建议保留 `internal + isolated` 的无外部默认路由，不为制造数据包而增加一条 L3 转发面。正式验收口径应改为：

> 所有连接尝试都有目标 cgroup 的系统调用记录；所有实际发出的数据包都有 PCAP。对内核在路由前拒绝、因此没有数据包的尝试，记录调用参数和返回错误，不伪造包证据。

这要求后续同步修改 `docs/testing.md` 和 `docs/audit.md` 中“所有尝试都有数据包”的表述。使用 cgroup `connect4`/`connect6` 和 UDP `sendmsg` hook 记录尝试，再用对应的 `sys_exit` 事件记录 `ENETUNREACH` 等返回结果；代理和项目 DNS 作为同一内部网络上的明确服务仍可访问。只有在以后确有透明转发需求时，才单独评估默认路由到受控网关的方案；届时必须增加 IPv4/IPv6 FORWARD 默认拒绝、无 NAT、规则失效测试和独立 TUN 命名空间，不能直接复用首版结论。

目标容器还应移除不需要的 capabilities，至少不持有 `NET_ADMIN`、`NET_RAW` 和宿主 Docker socket。外层管理员需要 root 操作时，由宿主执行；不能把宿主控制能力交给容器内用户。

### Docker 防火墙后端

实现前先只读确认 Docker 实际使用 iptables 还是 nftables 后端，不能混用两套假设：

- iptables 后端有 `DOCKER-USER` 链，可在 Docker 转发规则前加限制。[iptables 后端](https://docs.docker.com/engine/network/firewall-iptables/)
- nftables 后端没有 `DOCKER-USER`。项目应建立自己的 table/base chain，按专用 bridge、veth、子网和 chain priority 限定，不能修改 Docker 自建表。[nftables 后端](https://docs.docker.com/engine/network/firewall-nftables/)

不建议为了本项目切换共享宿主的 Docker 防火墙后端。无论使用哪种后端，都必须测试 Docker daemon 重启、容器重启和网络重建后隔离仍然存在，且不影响同机其他用户网络。

### nftables 闸门的建议结构

建议把出口适配器放在项目专用网络命名空间，并只管理该命名空间中的项目 table；不要修改 Docker 创建的 table、chain 或同机全局规则。候选规则先用 `nft -c -f` 做语法和引用检查，再用 `nft -f` 整批加载。nftables 官方手册说明 `-c` 只检查不应用，官方 wiki 说明 `-f` 可原子替换一批规则。[nft 手册](https://netfilter.org/projects/nftables/manpage.html)、[原子替换](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement)

首版规则原型应满足以下不变量：

- 基础策略默认拒绝，只允许管理面、项目 DNS、目标到显式代理，以及代理连接器到 TUN 的已批准路径。
- 使用带 timeout 的 nft set 保存短期出口租约；官方手册支持 set element timeout。监督器仅在所有必需组件健康且策略版本一致时续租。
- 每个出口包都先检查租约，再考虑 `ct state established,related`。如果先接受 established，关闸只能拦新连接，已有长连接仍可能传输。
- 不启用绕过该检查的 flowtable/offload。关闸切换策略时停止旧代理连接，并清理项目专用网络命名空间中的旧连接状态；重新开闸后不能让旧长连接按新策略继续。
- 规则只匹配项目专用接口、容器地址和网络命名空间。任何全局修改都必须先停下并单独确认。

这些是待实现不变量，不是已验证的 nft 规则。尤其是“租约过期后已有连接在规定窗口内停止”必须用持续 HTTP/2/WebSocket 流量做故障测试，不能只测试新建连接。

## DNS 与实际连接地址

域名策略和 IP 安全检查是两件事，二者都必须通过：

1. 严格策略下，DNS 只回答策略版本允许的精确域名或显式受信后缀；日常策略下可回答公网域名。dnsdist 支持精确 `QNameRule`/`QNameSetRule` 与独立的后缀规则，可用作统一策略前端。[dnsdist selectors](https://www.dnsdist.org/reference/selectors.html)
2. Unbound 作为后端解析器，对 A、AAAA、CNAME、HTTPS/SVCB 结果做检查。它的 `private-address` 可过滤配置的私网结果，但默认没有自动启用全部目标范围，必须明确配置并实测。[Unbound 配置](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
3. 本地连接控制层再次检查实际使用的 IP，拒绝回环、RFC 1918、链路本地、CGNAT、IPv6 ULA/链路本地、组播和云元数据等目标，防止 DNS rebinding 和代理层目的地变化。
4. 目标容器只可访问项目 DNS 的 53/UDP 和 53/TCP；外部 DNS 和 DoT 由网络层阻断。严格策略阻断未批准的 DoH；日常策略可阻断已知 DoH，但新域名上的自建 DoH 可能与普通 HTTPS 无法区分，不能承诺发送前识别。

需要单独测试 CNAME 链、轮换地址、TTL 过期、双栈回退、HTTPS/SVCB、ECH 和 DNS rebinding。ECH 已由 [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html) 标准化，透明 SNI 规则不能假定总能看到真实域名。显式代理可在 CONNECT authority 上先做策略，但仍要验证目标软件的实际 ECH 行为。

## 外部 Clash/VPN 上游的边界

上游只负责传输，不负责安全判定。推荐优先使用本地 TUN/L3 出口：本地受控层完成解析、IP 检查和连接选择，TUN 再把已批准流量送到用户提供的外部出口。

若直接把 HTTP/SOCKS 父代理交给 mitmproxy，父代理可能远端解析域名。本地此时可能看不到最终目的 IP；mitmproxy 官方 API 也说明上游代理模式下 `peername` 可能为空。[连接 API](https://docs.mitmproxy.org/stable/api/mitmproxy/connection.html)

因此：

- 使用远端解析的 HTTP/SOCKS 上游时，不能声称“本地 DNS 结果与最终出口 IP 一致”。
- 若必须使用这类上游，需要由本项目控制的连接适配层，或者接受只能验证域名、不能独立验证最终 IP 的明确降级；严格模式下不应接受该降级。
- 出口适配器的物理网络连接只允许到 VPN/代理服务器端点；上游断开时必须停止应用出口，不得回落到宿主直连。
- Mihomo 等实现的控制端口、监听地址和认证必须限制在本地管理面，不能暴露给目标容器。官方配置提供 HTTP/SOCKS/mixed 和 TUN 等入口，但具体采用哪一种要由原型验证决定。[Mihomo 入口](https://wiki.metacubex.one/en/config/inbound/port/)、[TUN](https://wiki.metacubex.one/en/config/inbound/tun/)

## 审计与故障关闭

审计至少需要两处抓包：

- 目标侧 veth：证明目标发出了什么，以及绕过代理的尝试如何被丢弃。
- TUN 加密前的接口或出口适配器入口：证明代理选择了哪个业务目的地址。TUN 加密后的物理接口通常只能看到 VPN/代理服务器端点，不能把该地址误写成业务目的地址。

两处记录要通过运行编号、连接时间、五元组、代理 flow ID 和策略版本关联。代理结构化记录还要在同一个 flow ID 下保存客户端五元组、规范化域名、固定后的业务 IP 和上游五元组。mitmproxy 记录 HTTP flow，PCAP 保存实际网络包，eBPF/系统调用记录补充进程归属和无包连接尝试；正文完整性仍须用已知字节数和哈希验收。任何一种记录都不能单独宣称“覆盖全部明文”。

### 两处 PCAP

正式实现先使用宿主 `nsenter + tcpdump` 分别进入目标和网关网络命名空间，写入同一运行编号下的独立 PCAP。不要抓宿主物理网卡后再按 PID 过滤，因为那会混入其他用户流量。以后如需 pcapng、ring buffer 或更细的统计，再在不改变隔离边界的前提下评估 dumpcap。

日常模式可以使用按时间和大小轮转、限制文件数量的 ring buffer；正式测试运行则把对应窗口固化，不能在分析前被环形覆盖。监督器至少检查：

- 两个捕获进程都存活，接口仍是预期接口；
- 输出目录可写、剩余空间高于阈值；用短周期轮转和本地 canary 包确认每个周期都有可读的已关闭文件，避免空闲期误判；
- `tcpdump` 进程没有退出，PCAP 文件持续增长且进程日志没有写入错误；
- 文件轮转成功，关闭后的 pcapng 可由读取工具打开；
- 捕获接口重建或名称变化时先闭闸，不能默默继续抓一个失效接口。

`-B` 只能增加缓冲区，官方也提醒系统可能调整实际大小，不能把“进程正常”当作零丢包。任何非零丢包、统计不可读、文件不可解析或写入停滞，在严格测试中都应让出口租约失效。日常保留策略和磁盘阈值可配置，但不能因此放宽故障关闭。

### cgroup v2 归属与系统调用记录

目标应有专用 cgroup v2 根节点。第一版原型建议在该范围验证以下 hook：

- `cgroup/connect4`、`cgroup/connect6`：限定并记录 TCP 和已连接 UDP 的连接尝试及目的地址、端口；
- `cgroup/sendmsg4`、`cgroup/sendmsg6` 或当前内核对应的 UDP sendmsg hook：覆盖未先 `connect()` 的 UDP 发送；
- `sys_enter`/`sys_exit` 的 connect、sendto/sendmsg 事件：按 TID 配对，补充 `ENETUNREACH` 等最终返回结果；只保留目标祖先 cgroup 的事件；
- `cgroup_skb/egress`：核对实际发出的包；
- exec/exit 事件：维护 PID、可执行文件、容器运行编号和 socket 记录的生命周期关系。

Linux 内核文档列出了 cgroup 的 connect、sendmsg 和 skb attach 类型；helper 文档提供当前 PID/TGID、当前 cgroup ID、socket cgroup ID 与祖先 cgroup ID。[程序类型](https://www.kernel.org/doc/html/latest/bpf/libbpf/program_types.html)、[BPF helpers](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)

这里有三个不能掩盖的边界：

1. Docker 可能在容器 cgroup 下再创建子 cgroup，直接比较“当前 cgroup ID 等于一个固定值”会漏掉子节点。必须验证 hook 对后代的实际生效范围，或用祖先 cgroup ID/受控后代清单归属，并测试子进程和嵌套 cgroup。
2. packet hook 执行时未必仍有可靠的当前用户进程上下文，不能只靠包事件里的 PID。应在 connect/sendmsg 时记录 socket cookie、五元组和进程，再与 egress 包、PCAP 关联；关联失败就是覆盖失败。
3. cgroup 路径或 ID 解析失败不能退化为“不限制”。启动器必须确认目标 cgroup、已附加 hook、运行编号和事件消费者都一致，否则不开闸。

目标没有 `NET_RAW` 时可减少 raw socket 路径，但仍要用 TCP、UDP、fork/exec、子进程、长连接和进程退出后的 socket 逐项验证。eBPF ring/perf buffer 任何丢事件也必须进入不健康状态。

“进程还活着”也不足以证明审计正常。建议设计一个短租约的出口闸门：只有 DNS、策略代理、两处抓包、必要 eBPF、日志目录可写、磁盘空间和当前策略版本全部健康时，网关才续期允许出口；检查失败或监督器退出后，租约自动过期并阻断出口。租约上限应在实施前固定，首版可把“不超过 1 秒”作为待验证目标；实际承诺值必须由持续传输故障测试确定，不能写成无延迟。该机制尚未实测，实施时要证明：

- 代理、DNS、PCAP、eBPF 任一停止后，新连接和已建立长连接都在记录的租约上限内停止传输；
- 日志目录只读、磁盘写满或流事件丢失时，不会继续放行；
- 策略更新只在全部组件加载同一版本后原子切换，失败时回滚整个快照；
- 规则恢复和回滚不会影响同机其他用户。

## 实施前必须关闭的风险

1. **策略插件可能晚于上游连接执行。** 必须用受控服务器和抓包证明严格策略中的未知域名，以及所有策略下的危险地址、异常端口和身份错误，在检查前都没有真实公网 SYN。
2. **mitmproxy addon 错误不等于代理退出。** 必须验证异常、语法错误和策略文件损坏都会让出口租约失效。
3. **透明代理不能按旧配置自动串父代理。** 透明对比实验应通过同一个 TUN/L3 出口，不能假定 `transparent + upstream_proxy` 可用。
4. **远端 DNS 隐藏最终 IP。** HTTP/SOCKS 父代理路径不能通过本地 DNS 日志证明最终目的地址安全。
5. **Docker internal 仍可能访问宿主。** 必须验证 isolated gateway、宿主监听端口、IPv4/IPv6、容器重启和 Docker 重启后的结果。
6. **“每次尝试都有包”与无默认路由矛盾。** 首版必须同步修改正式验收文档，改为所有尝试有 cgroup 事件、所有实际包有 PCAP；不通过新增路由制造证据。
7. **只抓目标 veth 会漏代理到上游。** 两处 PCAP 与 flow 的关联必须在首个端到端原型中完成。
8. **正文可能因流式传输、压缩、WebSocket、HTTP/2 或应用层二次加密而不完整。** 需要用大于 64 KiB 的双向随机 canary 按字节数和哈希验收。
9. **ECH、QUIC、无 SNI、IP 形式 CONNECT 和证书固定会改变可见性。** 未逐项通过前保持阻断。
10. **加入 Squid 会增加版本和故障面。** 只有在独立策略层确实降低风险、且无透传测试通过后再引入。

## 一键切换与回滚

日常操作可以做成一个命令，但 DNS、mitmproxy、eBPF、tcpdump、TUN 和 nftables 是多个进程，不能宣传为真正的跨进程原子切换。建议只暴露四个用户入口：

- `sandbox-net strict`：关闭公网出口，只保留本地受控测试服务；
- `sandbox-net daily`：加载已验证的日常 Web 策略；
- `sandbox-net inspect <run-id>`：固定策略版本并开启正式审计运行；
- `sandbox-net rollback <version>`：回滚整份策略快照。

所有入口内部执行同一状态机：

1. 先停止续租并等待 nft 出口闸门关闭；确认已有连接不能继续传输。
2. 生成候选快照，同时校验策略 schema、域名、端口、mitmproxy addon 和出口配置，并执行 `dnsdist --check-config`、`unbound-checkconf` 与 `nft -c -f`。这些命令只能完成静态检查，不能代替后续受控流量测试。[dnsdist 命令](https://www.dnsdist.org/manpages/dnsdist.1.html)、[Unbound 配置检查](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound-checkconf.html)
3. 在闸门关闭状态加载候选；用 `nft -f` 只替换项目 table；停止旧代理连接和项目专用旧连接状态。
4. 检查所有组件报告同一策略版本，两处 PCAP 与 eBPF 已开始写入，磁盘与上游健康。
5. 只在全部检查通过后写入短期租约并持续续租。任何一步失败都保持阻断；可整包恢复上一版本，但恢复成功前也不开闸。

策略仓库保存输入、生成物摘要、版本、变更说明和回滚点；运行机上的大 PCAP、明文正文和普通日志不进入 Git。命令的最终输出应只有当前模式、策略版本、闸门状态和日志目录，日常使用不要求用户手工管理各组件。

## 建议的验证顺序

### 阶段 0：固定边界

- 固定目标软件、容器镜像、Docker 版本、代理版本和策略 schema。
- 只读确认 Docker 防火墙后端、IPv4/IPv6 和宿主已有规则，不修改共享配置。
- 建立一份最小策略：仅本地受控测试域名，其他全部拒绝。

### 阶段 1：最小网络原型

- 建立专用 internal+isolated 网络、目标容器、显式代理服务和项目 DNS；目标没有外部默认路由，也不持有 `NET_ADMIN`。
- 验证直连公网 IP、私网、宿主 bridge 地址、外部 DNS、UDP/443、IPv6 和元数据地址均失败；每次尝试有目标 cgroup 事件，实际发出的包有目标侧 PCAP。
- 建立项目 nft table 和关闭状态的短租约闸门，先验证规则加载、过期和已有连接阻断，再接入真实外部出口。
- 停止代理或 DNS、重启容器和 Docker 后重复检查。任何旁路先修网络，不进入代理测试。

### 阶段 2：显式代理与受控 DNS

- 启动固定版本 mitmproxy regular 模式和最小 fail-closed addon。
- 先验证拒绝：未知域名、IP CONNECT、无 SNI、raw TCP 和 QUIC 均不能触发公网连接。
- 对已批准域名单独测试错误客户端 CA 和错误上游证书：允许发生必要的上游 TCP/TLS 探测，但不得发送应用请求正文，发现错误后必须关闭连接。
- 再放行一个受控 TLS 服务，验证域名、解析地址、代理 flow、两处 PCAP 和完整双向明文可关联。
- 注入 addon 崩溃、DNS 停止、日志只读、磁盘不足和上游断开，验证出口关闭。

### 阶段 3：接入外部出口

- 首先验证 TUN/L3 方案：物理出口只有 VPN/代理服务器端点，应用流量没有直连回退。
- 用同一域名制造公有 IP、私网 IP和 DNS rebinding，验证最终连接地址检查。
- 若评估 HTTP/SOCKS 父代理，单独记录“远端解析不可独立验证最终 IP”的限制，不与严格路径混为一谈。

### 阶段 4：Claude Code 对照测试

- 第一个实现步骤先完成显式 `HTTPS_PROXY`。透明 MITM 属于独立第二阶段：实现透明重定向后，复跑阶段 1-3 的网络和审计验收，再做无 CA、只安装 CA、透明解密和显式代理对照。它不影响对当前显式路径单独下结论。
- 登录后完成若干正常请求，比较域名、连接、协议、正文内容和重试行为；测试凭据本身不写入日志或仓库。
- 只有在已批准连接全部有进程、两处网络包和完整明文证据，且未批准连接全部被阻断后，才增加其必要业务域名。

### 阶段 5：日常策略与迁移

- 从严格策略起步；核心流量、真实任务和基本门禁通过后，由操作者单独决定是否进入日常公网 HTTP/HTTPS。当前实现保存首次出现域名的 flow，但没有主动提示服务；拒绝规则、非 Web 例外和策略默认动作的每次变更都生成不可变版本、差异、确认记录和回滚点。
- 同一用户只有一个沙箱；新增项目只增加挂载，不创建第二套网络环境。
- 多服务器只发布网络控制逻辑、镜像定义、策略 schema、部署脚本和文档；本地工作目录与大量日志不打包。
- 每台机器都重新执行网络、故障关闭和明文覆盖验收，不能用一台机器的结果替代其他服务器。

## 候选增强方案的通过条件

若以后实现本研究中的完整 DNS/TUN 方案，只有同时满足以下条件才可声称该增强方案通过；这不是当前显式代理 API-key 日常状态的描述：

- 目标容器不存在绕过显式代理的 IPv4、IPv6、DNS、UDP 或宿主访问路径；
- 未知域名、IP CONNECT、无 SNI、私网解析结果和外部 DNS 不产生公网连接；
- 外部出口、代理、DNS 或任何必需审计组件故障时没有直连或密文透传；
- 每条允许连接可关联进程、策略版本、DNS 结果、固定后的业务目的地址、两处 PCAP 和完整双向明文；
- 正式测试和审计文档已统一为“所有连接尝试有 cgroup 事件；所有实际发出的包有 PCAP”；
- 所有规则只作用于该用户的专用网络，不影响同机其他用户和进程。
