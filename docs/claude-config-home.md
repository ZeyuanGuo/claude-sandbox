# Claude 配置目录与共享 Home

## 结论（2026-10-22）

沙盒里的 `/home/gzy/.claude` 现在是一个**普通 bind 挂载**，源目录在共享 Home 内：

```text
/home/gzy/.local/share/controlled-dev-machine/claude   （mainstorage NFS，多机共享）
        │  mount
        ▼
容器内 /home/gzy/.claude
```

`CLAUDE_CONFIG_DIR=/home/gzy/.claude`，因此 Claude 的全局 JSON、凭据、会话都写在这个目录里；凡是挂载同一 `/home/gzy` 的服务器（4090、4090-48、3090、a800……）看到的都是同一份。

目录初始只有全局提示词与工具配置，不含宿主历史、宿主认证：

| 内容 | 来源 |
| --- | --- |
| `CLAUDE.md` | `@/home/gzy/claude_code_config/CLAUDE.md` 引用 |
| `settings.json` | 从宿主 settings 过滤掉 `ANTHROPIC_API_KEY`、`ANTHROPIC_BASE_URL` 等认证项 |
| `rules/`、`skills/`、`agents/` | `~/claude_code_config/{rules,skills,agents}` 子挂载 |

首次在沙盒内 `claude` 里 `/login` 后，`.credentials.json` 与 `.claude.json` 落在同一目录，随 Home 在所有主机一致可见；不再需要每台机器各登录一次。

## 为什么不用 `controlled_mounts`

控制器硬性要求：`workspace.controlled_mounts` 启用时 `paths.persistent_home` 必须在 `target.home` **之外**（防止用户改写受控挂载源）。而本需求正相反——Claude 配置必须在 Home 内、且跨机一致。因此 `.claude` 走 `mounts`（普通项目挂载），其余受控目录（`claude-fresh` 系列）保持原样。

`host.yaml` 关键片段（4090-48 已生效）：

```yaml
workspace:
  share_host_home: true
  controlled_mounts: [...]          # 不含 .claude
mounts:
- host_path: /home/gzy/.local/share/controlled-dev-machine/claude
  container_path: /home/gzy/.claude
  access: rw
- host_path: /home/gzy/claude_code_config/rules
  container_path: /home/gzy/.claude/rules
  access: rw
# skills、agents 同理，注意 .claude 必须排在这三个子挂载之前
```

配置变更不会热更新：需要 `sandboxctl stop` → `sandboxctl init --policy <当前快照>` → `systemctl start`（直接 `restart` 会复用旧 generation，挂载不会生效）。

## Home 外只保留控制面与审计

以下仍位于 Home 外，且**不应**搬进 Home：

| 路径 | 原因 |
| --- | --- |
| `/etc/controlled-dev-machine/<user>/` | root-only 主机配置，用户可改就会被绕过控制面 |
| `/opt/controlled-dev-machine`、`/local/controlled-dev-machine/releases` | 冻结控制代码，root 执行，不能落在用户可写目录 |
| `/local/controlled-dev-machine/<host>/runtime` | 每台主机独立的 Docker/NFT/CA 运行态，不能跨机共享 |
| `/local/controlled-dev-machine/<host>/audit` | 审计/PCAP，root-only 且体积大（上限 50G），Home 配额敏感 |
| `/local/controlled-dev-machine/<host>/managed-home` | 受控挂载源，按控制器约束必须在 Home 外 |

规则：**用户可写、需要跨机一致的沙盒状态一律放 Home 内；控制面和审计只在 Home 外，且每台主机独立。**

## 日常操作

```sh
ssh 4090-48
sbc claude                 # 首次进去 /login
ls -la ~/.local/share/controlled-dev-machine/claude
```

- 备份：`tar czf ~/claude-config-$(date +%F).tgz -C ~/.local/share/controlled-dev-machine claude`
- 清会话历史（保留配置）：`rm -rf ~/.local/share/controlled-dev-machine/claude/{projects,sessions,history.jsonl,shell-snapshots,file-history}`
- 同一时刻只在一台主机上跑交互式 Claude，避免 `.claude.json` 并发写。

## 2026-10-22 事故与恢复结论

- 14:00 左右，宿主 `lbt` 账号执行批量清理，删除 `/var/lib/controlled-dev-machine/gzy/renewed-20261021/managed-home`（当时的私有 `.claude`）与容器；14:49 再次删除容器。
- 14:45 的恢复只重建了策略目录和 `rules`，**没有**恢复凭据、会话和历史。
- 2:00–2:14 的测试记录证明当时确有可用的 Claude Pro 登录（交互会话 `65b95971-6f09-4e64-90cd-1124ac871a6c`，headless 会话 `8ece2c34-0c43-4e56-92ef-b04f60ec0a8f`），但 transcript 与 `.credentials.json` 都在被删目录内。
- 16:04 生成的冻结盘镜像上 `extundelete` 恢复 0 个 inode（journal 已回卷）；对镜像做 token 前缀/会话 ID 的后台扫描仍在进行，但默认按**未恢复**处理：重新登录。
- 4090-48 于 18:24 完成改造并验证；4090 于 18:41 完成同一份 `mounts` 并重新生成 generation（服务未启动，下次 `sbc start` 生效），4090 上原来单独覆盖到 `/var/lib` 的 `.claude`、`.cache/claude*` 已取消。
