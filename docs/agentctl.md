# agentctl 操作手册

真实 agy 执行和不同模型验收见 [运行器说明](agy-runner.md)。

第一次使用先看 [快速上手](agentctl-quickstart.md)；会话中断时看 [恢复指南](agentctl-recovery.md)。

在包含第二阶段代码的 checkout 运行 `python3 scripts/agentctl.py --help`。
可用 `--repo <checkout>` 指定仓库；linked worktree 自动共享同一个台账。
首次运行 `python3 scripts/agentctl.py init`。Python 3.9+ 和 Git 即可，无额外包。

## 建立任务

参考 [JSON 模板](templates/task.json)，填写具体目标、验收和允许路径，然后：

```bash
python3 scripts/agentctl.py add /tmp/task.json
python3 scripts/agentctl.py claim YC-EXAMPLE --owner author-session --harness codex --base main
python3 scripts/agentctl.py handoff YC-EXAMPLE > /tmp/YC-EXAMPLE-handoff.json
```

claim 返回 worktree、attempt、token 和 expires。保存 token，交给对应会话；不要提交到 Git。
工作区位于主 checkout 的 `.worktrees/agentctl/<id>-<attempt>`，默认独立 target。
在该目录打开你选择的 agy / Codex / pi / omp 会话，并给它 handoff 文件。
操作者核对所有工具权限；handoff 不启动模型或进程。

任务源、验收、范围必须在 add 时明确。allowed_paths 接受精确文件或目录前缀，不是 glob。
depends_on 只能引用已有任务，且领取基线要包含依赖的实际集成提交。
每个 owner 独占一项 worktree；默认重测试串行、最多两个实现会话，由协调者控制启动数量。

## 执行和验收

```bash
python3 scripts/agentctl.py show YC-EXAMPLE
python3 scripts/agentctl.py renew YC-EXAMPLE --token <claim-token> --seconds 3600
python3 scripts/agentctl.py submit YC-EXAMPLE --token <claim-token> --head <full-sha> --evidence /tmp/result.md
python3 scripts/agentctl.py review YC-EXAMPLE --reviewer independent-session --head <full-sha> --verdict PASS --evidence /tmp/review.md
python3 scripts/agentctl.py queue
```

实现者先运行统一门禁并本地提交，再 submit；证据文件放在 worktree 外以保持工作区干净。
评审者依据任务和实际代码独立检查；PASS/ISSUES/BLOCKED 都需证据。
新提交使旧批准不可集成，重新 submit/review。超时不要更改系统时间或无限续期；确认状态后处理。
任务和事件包含工作产物，证据只写测试材料，不写真实口令/私钥。

## 中断与集成

领取租约到期或进程退出后，先停止并确认旧会话不会继续写入，再执行：

```bash
python3 scripts/agentctl.py recover YC-EXAMPLE --stopped --reason '旧会话已结束，保留草稿后接手'
python3 scripts/agentctl.py claim YC-EXAMPLE --owner new-session --harness omp --base main
```

旧 worktree 不会删除。接手者先读 show 中的事件和旧产物，再选择性移植；不要让两个会话同时写同一目录。
旧 token 不再有效，耗尽 max_attempts 时停止并重新审视任务。

只有已获得合并授权的集成人才执行以下流程：

```bash
python3 scripts/agentctl.py reserve YC-EXAMPLE --target main --integrator integration-session
python3 scripts/agentctl.py integration
```

核对返回的目标基线和任务 SHA，在目标 checkout 手动集成；处理冲突后重新审查受影响内容，
在干净的目标 checkout 最终提交运行 `bash scripts/verify.sh`。记录 `/tmp/gate.json`：

```json
{"head":"<最终完整SHA>","command":"bash scripts/verify.sh","exit_code":0,"worktree":"<目标checkout绝对路径>","log":"<命令、退出码、日志位置及摘要>"}
```

```bash
python3 scripts/agentctl.py finish --token <integration-token> --head <最终完整SHA> --evidence /tmp/gate.json
```

失败或需要暂停时，保留现场，停止本轮集成后用 `release --token <integration-token> --reason <原因>`
释放槽。重启后通过 integration 查看未完成记录，不自动抢占。
reserve/finish 不运行 merge/push/release；也不会将未经实际运行的 JSON 变成验证证明。

数据库是本机状态，源码分支与事件是不同存储。需要备份时先停止写入，再用 SQLite backup API；
不要仅在活跃写入时复制数据库文件。损坏、版本不支持或找不到数据库会非零退出，不自动重置。
