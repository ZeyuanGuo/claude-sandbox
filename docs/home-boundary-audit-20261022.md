# Home 外沙盒残留盘点（2026-10-22）

目标：用户可写、需要跨机一致的沙盒状态全部位于共享 Home；Home 外只保留 root-only 的控制面与审计。本文只做盘点，**未删除任何文件**，删除需逐项确认。

## 已经在 Home 内的

| 路径 | 内容 | 状态 |
| --- | --- | --- |
| `~/.local/share/controlled-dev-machine/claude` | 沙盒 Claude 配置/凭据/会话，跨机共享 | 4090-48 已用；4090 已配置，待启动生效 |
| `~/claude_code_config/{rules,skills,agents}` | 提示词与工具配置，子挂载进 `.claude` | 两机一致 |
| `~/.codex/config.toml` 等 | Codex 共享配置 | 既有 |

## Home 外仍存在的（4090）

| 路径 | 大小 | 用途 | 处置建议 |
| --- | --- | --- | --- |
| `/var/lib/controlled-dev-machine/gzy/managed-home` | 40M | 9 月旧沙盒私有 Home（含旧 `.claude`、过期凭据、9 月会话） | 保留作恢复证据；确认后可归档到 `~/.local/share/controlled-dev-machine/archive/` 再删 |
| `/var/lib/controlled-dev-machine/gzy/renewed-20261021` | 8.1M | 当前受控挂载源、profile、prompt 备份 | 控制面，必须留在 Home 外 |
| `/var/lib/controlled-dev-machine/gzy/runtime` | 6.9M | 旧 generation / 运行态 | 控制面，保留 |
| `/var/log/controlled-dev-machine/gzy/renewed-20261021` | 340K | 审计/明文流量 | 审计面，必须 root-only |
| `/local/controlled-dev-machine/{releases,gzy}` | 1.8M+ | 冻结控制代码、旧数据 | 控制面，保留 |
| `/etc/controlled-dev-machine` | 92K | root-only 主机配置 | 控制面，保留 |
| `/opt/controlled-dev-machine` | 152M | 冻结安装副本 + venv | 控制面，保留 |

## Home 外仍存在的（4090-48）

| 路径 | 大小 | 用途 | 处置建议 |
| --- | --- | --- | --- |
| `/local/controlled-dev-machine/4090-48/managed-home` | 1.2M | 受控挂载源（claude-fresh 等） | 受控挂载约束，保留 |
| `/local/controlled-dev-machine/4090-48/runtime` | 4K | 运行态、CA、compose | 控制面，保留 |
| `/local/controlled-dev-machine/4090-48/audit` | 4K | 审计 | 审计面，保留 |
| `/local/controlled-dev-machine/4090-48/python{,312}` | 207M | 容器工具链 | 可考虑迁入 Home，但属镜像/工具链，暂不动 |
| `/local/controlled-dev-machine/4090-48/incoming` | 1.3M | 导入暂存 | 一次性数据，可清 |
| `/etc/controlled-dev-machine` | 56K | 主机配置 | 控制面，保留 |
| `/opt/controlled-dev-machine` | 48M | 安装副本 | 控制面，保留 |
| `/local/controlled-dev-machine/releases` | 1.5M | 冻结 release | 控制面，保留 |

## 为什么这些不搬进 Home

- `persistent_home` 位于 Home 内时控制器直接拒绝启动（`workspace.controlled_mounts` 与 `share_host_home` 的硬约束）。
- 控制代码与配置由 root 执行；放进用户可写目录等于让用户改控制面（提权）。
- 审计/PCAP 上限 100G，Home 配额紧张，且审计必须防用户篡改。
- 运行态（docker compose、nft、CA、租约）每台主机独立，不能跨机共享。

## 真正可以清的候选（待确认）

1. `4090:/var/lib/controlled-dev-machine/gzy/managed-home`（40M，9 月旧环境）——先打包到 Home 归档再删。
2. `4090:/var/lib/controlled-dev-machine/gzy/renewed-20261021/managed-home/.controlled-mounts/.claude`（已不再使用，仅 rules/CLAUDE.md）。
3. `4090:/var/lib/controlled-dev-machine/gzy/renewed-20261021/managed-home/.controlled-mounts/.cache/claude*`（已取消受控覆盖，应为空）。
4. `4090-48:/local/controlled-dev-machine/4090-48/incoming`（导入暂存）。
