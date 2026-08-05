# 受控开发机中的 TLS 明文捕获

本文只回答一个问题：怎样尽可能完整地保存沙箱内 TLS 流量的明文，并且不抓取同机其他用户的通信。

## 结论

不能把 eBPF、私有根证书或抓包工具中的任何一个单独当成“全部明文保证”。可行的做法是：

1. 在沙箱专用虚拟网卡上保存全部数据包。
2. 普通 TLS 默认经过会终止 TLS 的解密代理；不能解密时直接拒绝，不能改成密文透传。
3. 再按目标软件实际使用的库和可执行文件启用 eBPF、TLS 会话密钥或应用内 hook。
4. 指定软件的每条允许连接必须能关联到进程、网络包和完整明文；做不到就保持阻断。
5. 必要的捕获组件、日志存储或磁盘失效时，目标软件必须失去外网访问，而不是绕过审计继续运行。

这里的“TLS 明文”是 TLS 层收到或交付的字节。如果软件在 TLS 里面又做了一层加密，TLS 代理和 TLS eBPF 看到的仍是第二层密文；这种软件必须另加应用级 hook。

当前已经用透明 mitmproxy 完成普通 TLS 明文，并用 cgroup eBPF 做连接归属；没有部署 eCapture 明文探针。目标、DNS、网关通过短期 nftables 放行项联网，任一登记 PCAP/eBPF 探针退出后 watchdog 停止续期。本文其余 eCapture 和按 TLS 库补充探针的内容仍是增强依据，不代表当前能力。

## eCapture 能覆盖什么

以下结论以当前正式版 [eCapture v2.5.2](https://github.com/gojue/ecapture/releases/tag/v2.5.2) 为准。

### 默认不是“容器内全部 TLS”

`--pid=0` 只表示不按 PID 过滤。eCapture 仍然只会挂到指定的库文件或可执行文件：

- OpenSSL 模块只挂一个 `libssl` 文件中的 `SSL_read` 和 `SSL_write`。系统 OpenSSL、Conda OpenSSL 和软件自带的 BoringSSL 如果是不同文件，就要分别启动探针。[OpenSSL 探针源码](https://github.com/gojue/ecapture/blob/v2.5.2/internal/probe/openssl/openssl_probe.go#L232-L270)
- GoTLS 模块必须指定一个 Go ELF 文件。软件及其子进程如果启动了多个不同的 Go 可执行文件，每个文件都要单独处理。[GoTLS 探针源码](https://github.com/gojue/ecapture/blob/v2.5.2/internal/probe/gotls/gotls_probe.go#L228-L236)
- `--pid=0`、`--uid=0` 的官方含义都是“不限制”，不是自动识别容器。[CLI 源码](https://github.com/gojue/ecapture/blob/v2.5.2/cli/cmd/root.go#L158-L174)

因此，不能在共享宿主上直接使用“所有 PID、没有 cgroup 限制”的默认方式。只要其他用户加载了同一个被挂载的库文件，就可能把他们的明文也抓进来。

### cgroup 可以限定容器，但有明确边界

OpenSSL 和 GoTLS 模块支持 `--cgroup_path`。实现方式是把当前进程的 cgroup v2 ID 与目标 ID 做**完全相等**比较；它不是按容器名、网络命名空间或 cgroup 子树匹配。[过滤源码](https://github.com/gojue/ecapture/blob/v2.5.2/kern/ecapture.h#L93-L123)、[cgroup ID 解析源码](https://github.com/gojue/ecapture/blob/v2.5.2/pkg/util/ebpf/cgroup_linux.go#L28-L59)

使用时必须额外检查：

- 目标容器的所有进程是否确实处于同一个 cgroup ID；进入子 cgroup 的进程可能漏掉。
- cgroup 路径解析失败时，eCapture 只报警并把 ID 设为 0，也就是取消 cgroup 限制。外层启动器必须把这种报警当成启动失败。[OpenSSL 失败处理源码](https://github.com/gojue/ecapture/blob/v2.5.2/internal/probe/openssl/openssl_probe.go#L643-L657)
- 当前 NSPR 模块虽然暴露 `--cgroup_path`，实际写入的目标 cgroup ID 固定为 0，不能用它隔离其他用户。[NSPR 源码](https://github.com/gojue/ecapture/blob/v2.5.2/internal/probe/nspr/nspr_probe.go#L250-L289)
- 当前 GnuTLS 模块仍是未完成的框架代码，没有真正加载探针和事件 map，不能用于覆盖承诺。[GnuTLS 源码](https://github.com/gojue/ecapture/blob/v2.5.2/internal/probe/gnutls/gnutls_probe.go#L32-L141)

eCapture 的 PCAP 模式也不能代替网络范围隔离：TC 程序无法把某个包关联到进程时，仍会输出该包，不会执行 cgroup 检查。因此，完整抓包必须绑定沙箱自己的 veth、网桥端口或网关接口，不能抓宿主主网卡再依赖 eCapture 过滤。[TC 源码](https://github.com/gojue/ecapture/blob/v2.5.2/kern/tc.h#L225-L278)

### 当前实现支持和不支持的范围

| 实现 | 当前源码能确认的范围 | 结论 |
|---|---|---|
| OpenSSL | 1.0.2a-u、1.1.0a-l、1.1.1a-w、3.0.0-21、3.1.0-8、3.2.0-6、3.3.0-7、3.4.0-6、3.5.0-7、3.6.0-2、4.0.0-1 | 仍需对目标文件和调用方式实测 |
| BoringSSL | Android 13-16 和一个非 Android 配置 | 二进制接口不固定，必须按目标软件的准确构建实测 |
| Go `crypto/tls` | 对指定 Go ELF 分析并挂探针 | 每个不同 ELF 单独验证 |
| NSPR/NSS | 当前已有 `PR_Read`、`PR_Write` 探针 | cgroup 限制当前无效，不适合直接用于共享宿主 |
| GnuTLS | 当前命令存在，但实现仍是 stub | 不可依赖 |
| LibreSSL | README 声称支持，但 v2.5.2 没有单独识别和版本映射 | 不作为已验证能力 |
| rustls、mbedTLS、wolfSSL、Java JSSE、自定义 TLS | 官方当前没有对应可用探针 | 默认视为未覆盖 |

OpenSSL 的准确版本映射见 [eCapture 源码](https://github.com/gojue/ecapture/blob/v2.5.2/internal/probe/openssl/libs.go#L176-L310)。BoringSSL 官方明确说明它不保证 API 或 ABI 稳定，因此一个通用偏移不能代替目标构建实测。[BoringSSL 官方说明](https://boringssl.googlesource.com/boringssl/)

即使库版本匹配，也不能只看进程是否启动成功：

- OpenSSL 明文探针只挂 `SSL_read` 和 `SSL_write`，而 OpenSSL 还公开了 `SSL_read_ex`、`SSL_write_ex`、early data 和 QUIC 等其他入口。[eCapture 挂载点](https://github.com/gojue/ecapture/blob/v2.5.2/internal/probe/openssl/openssl_probe.go#L240-L270)、[OpenSSL 官方头文件](https://github.com/openssl/openssl/blob/master/include/openssl/ssl.h.in)
- OpenSSL 的单个 text 事件最多保存 16 KiB，超过会截断。不能只用 text 模式证明大请求完整。[eCapture 截断源码](https://github.com/gojue/ecapture/blob/v2.5.2/kern/openssl.h#L170-L188)
- 高负载时 perf buffer 会丢事件，eCapture 只记录 `lost_samples` 报警。只要它是必需捕获路径，出现一次丢失就应判为不合格。[丢失处理源码](https://github.com/gojue/ecapture/blob/v2.5.2/internal/probe/base/base_probe.go#L351-L365)
- eCapture 的 pcapng 模式把原始包和捕获到的 TLS 密钥写入同一文件，并不等于所有负载已经无条件变成明文。[PCAP 与密钥写入源码](https://github.com/gojue/ecapture/blob/v2.5.2/internal/probe/openssl/openssl_probe.go#L359-L503)

## 私有根证书和解密代理的边界

私有根证书适合作为普通 TLS 的主要捕获方法，但要满足两个条件：流量确实经过代理，而且客户端确实信任该根证书。代理会分别与客户端和真实服务器建立 TLS 连接，因此能直接保存中间的明文字节。[mitmproxy 证书说明](https://docs.mitmproxy.org/stable/concepts/certificates/)

必须按以下规则处理：

- 只把根证书放入目标环境；根证书私钥保留在外层代理中，目标软件不能读取。
- 操作系统证书库、应用自带证书库和运行时证书库要分别验证。只改系统证书库，不能证明所有程序都信任该证书。
- 证书固定会拒绝代理生成的证书。mitmproxy 官方说明，这类连接需要修改目标程序才能拦截。[证书固定说明](https://docs.mitmproxy.org/stable/concepts/certificates/#certificate-pinning)
- 需要 mTLS 时，代理还要能够向上游提供正确的客户端证书和私钥；否则握手会失败。[mTLS 说明](https://docs.mitmproxy.org/stable/concepts/certificates/#mutual-tls-mtls-and-client-certificates)
- 解密失败时必须关闭连接，不能使用 `splice` 或其他密文透传作为自动回退。Squid 的官方设计也把 `bump`、`splice` 和 `terminate` 视为不同的最终动作。[Squid Peek and Splice](https://wiki.squid-cache.org/Features/SslPeekAndSplice)

### QUIC

QUIC 不是“TCP 上的普通 TLS”。TLS 只提供握手和密钥，应用数据由 QUIC 自己在 UDP 包中保护。[RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)

mitmproxy 当前只对特定模式和 QUIC v1 提供 HTTP/3 支持，并明确说明实现兼容性主要用 cURL 测试。[mitmproxy 协议说明](https://docs.mitmproxy.org/stable/concepts/protocols/)

因此，初始和日常模式应默认阻断 UDP/443 和其他未批准 UDP，让普通客户端回落到 TCP TLS。目标软件如果必须使用 QUIC，就要把它列为单独路径，验证对应的 QUIC 代理、应用密钥日志或专用 hook；未通过前不能放行。

## 把“全部明文”改成可验收要求

不能证明一个任意未来版本、任意代码路径的软件永远可见。可以对一个固定版本和固定运行方式做以下承诺：

> 对已登记的软件版本、启动命令、配置、子进程、TLS 库和允许的网络路径，每条实际放行的外部连接都必须关联到发起进程、完整 PCAP 和可重建的双向 TLS 明文字节流。任何未登记路径、捕获失败或记录失败都保持阻断。

### 验收前固定范围

记录并校验：

- 目标软件包或镜像摘要；
- 主程序和会联网子程序的文件哈希；
- 实际加载的 TLS 库文件及哈希；
- 启动命令、关键配置和允许的协议；
- 负责该路径的明文捕获方法。

上述任一项变化后，原验收结果失效，必须重新检查。

### 每条连接必须有的记录

每条放行连接至少要能关联到：

- 进程、可执行文件和 cgroup；
- 域名、地址、端口、协议和策略版本；
- 原始网络包；
- 使用哪种方法得到明文；
- 双向明文的字节数、内容或分段哈希；
- 捕获组件是否有丢包、丢事件、截断或写盘错误。

没有明文记录的连接不应被解释为“软件没有发送内容”，而应直接判定为覆盖失败。

### 必做测试

针对软件实际使用的路径，用本地受控服务发送唯一随机内容，并预先记录内容长度和 SHA-256。至少覆盖：

- 上传和下载均大于 16 KiB，建议不少于 64 KiB；
- 启动、登录、更新、搜索、代码访问和异常重试；
- 软件实际使用的 TLS 1.2、TLS 1.3、HTTP/1.1、HTTP/2 或 QUIC；
- 并发连接、长连接、会话恢复和子进程；
- 软件实际存在的证书固定、mTLS 或内置证书库。

通过条件是：重建后的双向字节数和 SHA-256 与测试数据一致，所有连接都有归属，没有 `lost_samples`、截断、未识别连接或写盘错误。

还要主动制造故障：停止代理或必要探针、让审计目录不可写、给出错误 CA、替换库文件、尝试直接 IP、外部 DNS 和 UDP/QUIC。每种情况下都必须看到连接被阻断，不能看到自动直连或密文透传。

## 建议的分层方案

### 第一层：全部网络包

在沙箱专用 veth、网桥端口或网关接口抓取进入和离开沙箱的全部包。抓包范围由专用接口保证，不依赖 PID 或 eCapture 的包关联能力。

### 第二层：普通 TLS 解密代理

普通 TCP TLS 默认经过会终止 TLS 的代理。目标环境信任沙箱专用根证书；代理保存请求、响应或原始明文流。没有 SNI、证书不受信、代理不支持或日志无法落盘时，连接终止。

代理是标准 TLS 的主要明文来源，eBPF 是独立核对和特殊情况补充。

### 第三层：按目标文件启用 eBPF 或会话密钥

盘点目标软件实际加载的每个 TLS 库和 Go ELF，再逐个启用探针：

- OpenSSL 和 GoTLS 必须限定到目标 cgroup；
- 一个库文件或 Go ELF 对应一套明确的探针配置；
- 优先把会话密钥与独立 PCAP 配合使用，text 输出用于实时检查和交叉验证；
- 所有启动报警、丢事件和版本识别失败都进入失败状态。

不得为了方便而在共享宿主上使用无 cgroup 限制的全 PID 捕获。

### 第四层：目标软件专用办法

遇到证书固定、静态链接、rustls、GnuTLS、QUIC 或 TLS 内再次加密时，针对该软件选择：

- 软件原生 TLS key log；
- 补充 uprobe 或应用函数 hook；
- 在确认不改变行为后修补证书固定；
- 专用 QUIC 解密代理；
- 在再次加密之前记录应用数据。

没有经过实际内容测试的办法不能进入“已覆盖”清单。

### 第五层：阻断和运行状态

目标软件启动前先启动抓包、代理、必要探针和日志存储。外层持续检查：

- 必要组件是否存活；
- cgroup 和文件哈希是否仍匹配；
- 磁盘是否可写且空间足够；
- 是否出现丢包、丢事件、截断或新连接类型。

当前实现用 watchdog 每秒核对目标、DNS、网关、三处 PCAP 和目标 cgroup eBPF 的进程身份；只有全部匹配才续期 5 秒 nftables 放行项。已实测停止目标 PCAP 后放行项过期，DNS 和 Web 都停止。磁盘空间、tcpdump 内核丢包和 eBPF 丢事件还没有进入自动闭锁，仍需通过启动预检和使用后审查发现。

## 其他流量的标准

空闲沙箱不应主动访问公网。目标软件运行期间，除已登记的目标进程、包管理器和开发工具外，其他进程产生的外部连接都应视为待查事件。

验收时应达到：

- 空闲观察窗口内没有未解释的外部连接；
- 运行期间每条连接都有发起进程和用途；
- 严格策略下的新 Web 请求暂停审核，非 Web 保持阻断；日常策略下普通公网 HTTP/HTTPS 允许并记录，当前没有主动首次域名提示；私网探测、直接 IP、非 Web 未知协议和绕过代理仍然阻断；
- 每条可疑记录最终写明来源、目的、处理结果和是否需要修改策略。

这比只搜索日志中的“恶意关键字”更可靠：流量种类本来就很少，无法解释的连接本身就是需要处理的问题。
