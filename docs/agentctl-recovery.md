# 恢复中断的协作任务

恢复的完成条件是：旧会话已经停止，新尝试有独占 worktree 和新令牌，旧产物仍可追溯。
租约过期本身不会停止 Agent，也不会自动把任务交给别人。完整状态契约见
[协作台账](subsystems/coordination.md)，常规操作见 [agentctl 手册](agentctl.md)。

## 先确认现场

在包含 `scripts/agentctl.py` 的 checkout 根目录运行以下只读命令；重启后也使用同一入口：

```bash
python3 scripts/agentctl.py show YC-EXAMPLE
python3 scripts/agentctl.py integration
```

`show` 返回状态、owner、attempt、worktree、expires 和事件。先确认任务 ID、旧工作区和实际会话。
台账在 Git common dir 下，linked worktree 共享它；不要重新建同名任务来绕过原记录。
令牌只用于对应尝试，保存在工作区外，不提交到 Git。命令示例中的占位值必须替换后执行。

| 现场 | 下一步 |
| --- | --- |
| `running`，会话仍活跃且租约有效 | 原 owner 可用 `renew` 续租，不启动第二个写入者 |
| 租约已过期，或会话已退出 | 确认旧会话停止后 `recover`，再 `claim` 新尝试 |
| `provisioning` 中断 | 确认创建进程停止，保留已有路径和分支，再 `recover` |
| 有该任务的集成槽 | 先由集成人处理或释放槽；`recover` 会拒绝占槽中的任务 |
| 尝试次数耗尽 | 停止重试，重新判断任务与环境；不要删台账或换 ID 掩盖失败 |

有效租约只能在 `running` 状态续期：

```bash
python3 scripts/agentctl.py renew YC-EXAMPLE --token '<当前claim令牌>' --seconds 3600
```

已过期的租约会报 `Lease expired`。续租失败后检查现场，不修改系统时间来延长租约。

## 停止旧会话，再创建新尝试

操作者先在原工具中停止会话及其仍在写入的操作，确认它不会再改旧 worktree。
`--stopped` 是操作者作出的确认，CLI 不检查或终止进程。无法确认时保持阻塞，不能抢占。
记录旧工作区的提交、未提交草稿和外部日志位置，保留原件。

```bash
python3 scripts/agentctl.py recover YC-EXAMPLE --stopped --reason '旧会话已结束；保留草稿后接手'
python3 scripts/agentctl.py claim YC-EXAMPLE --owner new-session --harness codex --base main
python3 scripts/agentctl.py handoff YC-EXAMPLE > /tmp/YC-EXAMPLE-handoff.json
```

`--base` 选择已同意的基线；在尚未合并 main 的试验中应使用实际试验分支，而不是默认 main。
`claim` 返回新的 `attempt`、`token`、`worktree` 和 `expires`。把实际返回的目录交给新会话，
不要继续使用旧路径。四种工具都通过同一 handoff 文件接手，`--harness` 只记录工具标签。

例如第 1 次尝试中断后，第 2 次尝试使用主 checkout 内的
`.worktrees/agentctl/YC-EXAMPLE-2`；旧 `YC-EXAMPLE-1` 及其草稿保留。
新 owner 阅读事件和旧产物，核对新基线，再选择性移植有用内容；不要覆盖旧 worktree 或直接搬入未经审查的全部差异。
恢复会移除旧的当前提交/评审状态，但事件保留；新尝试需要重新实现、验证和独立验收。

恢复后，旧令牌的 `renew` / `submit` 会报 `Stale or incorrect attempt token`。
这个拒绝只保护台账状态，不阻止旧进程写文件，因此停止确认不能省略。
新 owner 完成后，在新 worktree 运行统一门禁、本地提交；将结果报告放在工作区外，
再用新令牌和实际完整 SHA 提交。后续操作沿用 [执行与验收流程](agentctl.md)。

## 集成中断后继续或释放

只有获得对应目标分支合并授权的集成人才能继续集成。运行 `integration` 读取持久槽：
任务提交、目标分支、原目标基线、集成人及集成令牌。它与任务的 claim 令牌不是同一个值。
重启不会自动释放槽，也不会自动合并。

先核对目标 checkout 的分支、HEAD、未提交变更和冲突，并确认上一个集成人已停止操作。
若继续：核实任务批准仍对应实际 head，完成手动集成，在干净的目标 checkout 最终提交运行
`bash scripts/verify.sh`，保存真实日志和门禁记录到工作区外。记录必须包含：

```json
{"head":"<最终完整SHA>","worktree":"<目标checkout绝对路径>","command":"bash scripts/verify.sh","exit_code":0,"log":"<真实日志位置和结果摘要>"}
```

```bash
python3 scripts/agentctl.py finish --token '<集成令牌>' --head '<最终完整SHA>' --evidence /tmp/gate.json
```

未完成门禁、门禁失败或目标仍有未提交变更时，不能用成功记录结束任务。
`finish` 核对版本和工作区，但不会执行门禁，也不能把手写 JSON 变成运行证据。
如需暂停，保留冲突、代码和日志，在停止本轮集成后释放槽：

```bash
python3 scripts/agentctl.py release --token '<集成令牌>' --reason '本轮集成已停止，保留现场等待处理'
```

`release` 只释放台账槽，不回滚 Git、不清理 worktree，也不恢复冲突文件。
下次重新 `reserve` 会取得新集成令牌；旧令牌不能完成新槽的集成。
任务已批准但代码变化时，重新 submit/review，不沿用旧批准。
`integrated` 要结合 `integrated_target` 阅读：进入试验分支不等于进入 main，更不等于发布。

本流程只协调同一用户下的会话，不提供身份认证或强制沙箱。合并、推送、发布分别遵守授权边界。
