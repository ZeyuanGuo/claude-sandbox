# 配置时选择是否提供宿主凭据

> 历史状态：本文记录最初的凭据挂载边界。当前非关键的 skills、agents 和 Conda 配置已由 [ADR 0017](0017-writable-tool-state.md) 改为读写；SSH 私钥及其 `Include` 配置目录仍保持只读，精确 Tailscale 放行见 [ADR 0018](0018-scoped-tailscale-ssh.md)。

目标软件自己的账号凭据可以正常使用。为了保持日常开发环境一致，`config init` 会把实际存在的宿主 Git 配置默认读写挂载、把 SSH 和 Conda 配置默认只读挂载；不会复制整棵宿主 Home。生成后必须检查挂载清单，并删除不愿交给目标软件的条目。目标软件能够读取并复制所有保留下来的凭据。

凭据直接同路径挂载，不维护沙箱副本。Git 使用宿主 `~/.config/git` 读写目录，以支持 credential store 的锁文件和原子更新；SSH 使用宿主 `~/.ssh` 及其 `Include` 的 `~/.local/share/gamma-ssh` 只读目录。抓包和 eBPF 默认开启，但不能作为凭据不会泄露或泄露一定会被发现的保证。
