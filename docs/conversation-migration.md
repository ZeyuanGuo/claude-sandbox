# Claude Code 会话迁移

会话迁移的目标是保留工作进度，同时不把宿主原会话编号、已识别的凭据和整套 Claude 状态带进沙箱。

## 迁入一个会话

在宿主以目标用户执行：

```bash
cd "$HOME/claude-sandbox"
bin/sandboxctl session import SOURCE_SESSION_ID
```

也可以通过 `sudo` 执行；工具会把结果所有者改回 `host.yaml` 中的目标用户。成功输出包含新的 `new_session_id` 和本机 manifest 路径；迁移结果和 manifest 不记录源编号。命令参数仍可能进入操作者自己的 shell 历史。

工具会一次性完成：

- 找到唯一主 JSONL，并复制所有同名跨项目 companion；
- 复制子代理、workflow、journal 和持久工具结果；
- 把会话专属 `/tmp` 转存到持久 companion 的 `imported-tmp/`，同步改写引用；
- 将安全的会话内符号链接解析成普通文件；链接指向其他 Claude 状态时拒绝迁移；
- 一致重编号会话、消息链、request、tool、agent、workflow 和任务标识；
- 脱敏常见 API key、访问令牌、认证头、Cookie、密码字段、JWT、AWS access key 和私钥形态的值；
- 把旧 `file-history` 保存为 `imported-file-history/` 归档，不放入活动 rewind 目录；
- 在写入前后校验源指纹，源变化、目标碰撞或任何残留检查失败时回滚。

不会迁移：

- `session-env`、账号状态、全局 settings 和固定凭据文件；
- `history.jsonl`、`.claude.json` 的最近会话指针和无关 shell snapshot；
- 整棵宿主 `.claude`；
- 会话目录之外的 `/tmp`。历史中若引用这些外部临时文件，恢复后可能仍然不可读。

## 恢复

项目键来自会话最初的工作目录。当前这种从 Home 启动的会话要这样恢复：

```bash
sudo bin/sandboxctl shell
cd "$HOME"
claude --resume NEW_SESSION_ID
```

不要再加 `--fork-session`：迁入时已经生成新编号。不要对迁入会话使用 `--rewind-files`；旧文件历史只是归档参考，当前项目可能已经继续变化。

恢复会把历史对话、工具结果和读取过的内容重新发送给模型。迁移本身不联网；真正运行 `--resume` 后的下一次请求才联网。

## 验收

迁移工具已经检查：

- 主记录全部使用新编号；
- 消息父链、leaf、source tool 和 `tool_use`/`tool_result` 引用没有悬空；
- JSON/JSONL 可解析；
- 源会话编号和源内部标识在目标路径及内容中均无残留；
- 检出的密钥形态值已脱敏；
- companion、临时任务输出和文件历史归档可读；
- 目标权限为私有，容器普通用户可以读取。

这不是任意凭据的数学证明：没有明确字段名、没有已知格式的普通字符串无法可靠判断。工具会拒绝仍含已知高风险格式的结果；第一次真实恢复仍应在受控网络中完成，并检查明文记录。

若只想准备会话而不继续工作，到此停止。容器内的可见性可以只读检查，不需要启动 Claude，也不会产生模型请求。

## 本机记录边界

每次导入的报告可能包含源路径、目标路径、新会话编号、文件数量和运行编号。这些信息只保存到本机权限受限的状态目录，不进入 Git。发布文档只保留迁移方法、脱敏规则和验证边界。
