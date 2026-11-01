# 第一次用 agentctl 完成任务

这个流程把任务交给独立会话执行，协调者保存状态、令牌和证据。
以下命令从包含第二阶段工具的 YaCrypt checkout 运行；实现者则在 claim 返回的 worktree 工作。
需要 Python 3.9+、Git，以及 [完整门禁的工具](verification.md)。

1. 运行 `python3 scripts/agentctl.py init`，复制 [任务 JSON](templates/task.json)
   到仓库外（如 `/tmp/YC-EXAMPLE.json`）。替换示例目标、验收和 allowed_paths，保留唯一 id。
2. 创建并领取任务：

   ```bash
   python3 scripts/agentctl.py add /tmp/YC-EXAMPLE.json
   python3 scripts/agentctl.py claim YC-EXAMPLE --owner author-session --harness codex --base main
   python3 scripts/agentctl.py handoff YC-EXAMPLE > /tmp/YC-EXAMPLE-handoff.json
   ```

   保存 claim 返回的 token 与 worktree。将 handoff 文件交给在该目录打开的独立会话。
   harness 可选 agy/codex/pi/omp，它是记录标签，不会启动程序。
3. 实现者读取 AGENTS.md、相关子系统和教训，只修改允许范围。完成后运行
   `bash scripts/verify.sh` 并本地提交。报告写在 worktree 外，记录实际 SHA、测试结果、未执行项。
   协调者用 `renew YC-EXAMPLE --token <claim-token> --seconds 3600` 续有效租约；
   `show YC-EXAMPLE` 查看状态和事件。
4. 提交结果，再由独立会话验收：

   ```bash
   python3 scripts/agentctl.py submit YC-EXAMPLE --token <claim-token> --head <完整SHA> --evidence /tmp/result.md
   python3 scripts/agentctl.py review YC-EXAMPLE --reviewer reviewer-session --head <完整SHA> --verdict PASS --evidence /tmp/review.md
   python3 scripts/agentctl.py queue
   ```

   只有实际通过才填写 PASS。ISSUES/BLOCKED 也保留报告；代码变化后必须重新 submit/review。
   queue 中 eligible=false 表示历史批准已不对应当前工作区，不可直接集成。
5. 获得目标分支合并授权后，集成人 reserve，手动合并并在干净的最终 checkout 运行门禁。
   按 [操作手册](agentctl.md) 保存带最终 head/worktree/command/exit_code/log 的证据，再 finish。
   reserve/finish 只控制协作记录，不代替 Git 合并、权限批准或真正运行验证。

台账位于 Git common dir 的 agentctl/ledger.sqlite3；不同 linked worktree 共享它。
不用复制聊天记录来恢复状态，但仍需保存外部日志和工作产物。令牌、真实口令与私钥不进入 Git。
过期和中断请先停止旧会话，再按 [操作手册的恢复流程](agentctl.md#中断与集成) 接手；
工具不会自动终止旧会话，也不会自动删除旧 worktree。
