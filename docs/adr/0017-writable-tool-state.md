# 非关键工具状态允许读写

状态：已接受

## 决定

`config init` 对常用工具状态使用同路径读写挂载：Claude skills、Claude agents、通用 agents skills、Codex 整棵 `~/.codex`、Git 配置目录和 `.condarc`。这样容器内安装或更新技能、agent、Conda 配置和 Git credential store 后，宿主立即可见，其他主机按相同生成规则复现。

SSH 目录仍只读，因为其中包含私钥和 `authorized_keys` 等关键凭据。Claude 的 `.claude` 会话数据库仍保留在沙箱持久 Home；生成的 `CLAUDE.md` 作为用户可编辑的工作提示词以读写方式挂入，`.bashrc`、`.profile`、`.gitconfig` 和 `.tmux.conf` 仍以受控只读副本挂入。`CLAUDE.md` 不是网络强制边界，编辑它不会改变网关策略。

## 边界

读写挂载不是秘密隔离。目标程序可以读取并修改这些目录中的全部内容，网络审计也不能保证凭据不会被发送。主机迁移时只迁移通用规则和文档；Codex 登录状态、Git 凭据和项目数据仍属于主机私有状态。
