# YC-002 证据归档

日期：2026-11-01（Asia/Shanghai）。macOS arm64；Python 3.14.5；Rust/Cargo 1.92.0；cargo-deny 0.20.2。
真实门禁命令为 `PATH=/private/tmp/yacrypt-phase1-tools/bin:$PATH bash scripts/verify.sh`，各日志退出码均为 0。
最终门禁包含 5 个入口回归、13 个台账回归、59 个 Rust 测试；fmt/clippy/build/deny 均通过。
审计保留 index-failure/yanked 状态查询和 license-not-encountered 警告，未修改 deny.toml。

| 完整压缩日志 | 解压后 SHA256 |
| --- | --- |
| [phase1-main](phase1-main.log.gz) | `c89650383dbc87db37e0f8234cbeb7ca426543fe0069a9097a32f1ce7872ab01` |
| [phase2-fixed](phase2-fixed.log.gz) | `62e5f89892eec307a87ec7d638ed428e5e07c595eb070e99707e3667384a7bab` |
| [YC-003-task](YC-003-task.log.gz) | `ae9deae2faa71c0dadcfb56c65aea5813215ec3e98776e375da803ae1ebd2847` |
| [YC-003-integrated](YC-003-integrated.log.gz) | `9cf80142f22e99c069d3dea7706f15e1c24a15ad3afd62d6139e81dcdd072eeb` |
| [YC-004-task](YC-004-task.log.gz) | `6ffb548d272c511d6fa18725f6629c582ba25a0c5121450c45a8f7ff6942d2b2` |
| [YC-004-integrated](YC-004-integrated.log.gz) | `93da0b98f2066545dc1af14410c03d46cee430aa9f8d1fb5933230adeff96aec` |

用 `gzip -dc <日志>` 查看。phase1-main 是已授权合并后第一阶段基线；phase2-fixed 是修复独立审查发现后的实现；
两个 task 日志来自各自 worktree，integrated 日志来自第二阶段目标分支。最终目标版本为
`c5650c0d476580a44f2a376dece1f76ed5cf0e1e`。

台账快照：[正常任务](YC-003-ledger.json)、[恢复任务](YC-004-ledger.json)。
快照保存事件和证据原文，不含 claim 或 integration 令牌；实时数据库仍在 Git common dir。
恢复检查：[过期与旧令牌拒绝](recovery-checks.json)、[保留的中断草稿](interrupted-draft.md)。
原草稿仍位于旧 attempt worktree，并未清理；本次是受控中断演练，不声称发生了真实进程崩溃。

独立报告：[YC-003](YC-003-review.md)、[YC-004](YC-004-review.md)。
作者报告：[YC-003](YC-003-result.md)、[YC-004](YC-004-result.md)。
报告中临时日志路径对应上述持久归档；正文作为当时证据保存，不回写历史 SHA。

Linux、远端 CI、真实模型工具自动启动/终止和发布未运行；没有模型 API 费用调用。
