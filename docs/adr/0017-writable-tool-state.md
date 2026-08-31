# 非关键工具状态允许读写

状态：已接受

## 决定

`config init` 创建宿主 `~/claude_code_config`，只把 `CLAUDE.md`、`settings.json`、`rules`、`skills` 和 `agents` 分项读写挂载到容器 `~/.claude`。通用 agents skills、Codex 整棵 `~/.codex`、Git 配置目录和 `.condarc` 也使用读写挂载。这样容器内更新行为配置后，宿主立即可见，其他主机按相同生成规则复现。

SSH 目录仍只读，因为其中包含私钥和 `authorized_keys` 等关键凭据。Claude 的凭据、会话数据库、历史、插件和设备状态仍保留在沙箱持久 Home，不进入共享目录。宿主默认 `~/.claude` 不作为挂载源，宿主 Claude Code 不会自动读取 `~/claude_code_config`。`.bashrc`、`.profile`、`.gitconfig` 和 `.tmux.conf` 仍以受控只读副本挂入。`CLAUDE.md` 不是网络强制边界，编辑它不会改变网关策略。

## 边界

读写挂载不是秘密隔离。目标程序可以读取并修改这些目录中的全部内容，网络审计也不能保证凭据不会被发送。主机迁移时只迁移通用规则和文档；Codex 登录状态、Git 凭据和项目数据仍属于主机私有状态。
