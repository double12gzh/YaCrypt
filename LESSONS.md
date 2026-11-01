# 开发教训

修改前阅读；条目记录规则、事件证据和验证。可自动判定的规则优先固化为检查。
一般经验重复出现时合并到工程规范；严重安全问题不等重复发生。

## YC-001：完整门禁只维护一个入口

旧 CI/hook 的默认 Cargo 包选择与 check 技能的 --workspace 范围不同。
有根 package 的 workspace 默认测试可能漏掉成员 crate 的单元测试。
使用统一入口并让故障成员测试阻断它；工具缺失或审计失败仍须报告，不能绕过。
本轮事实和结果见 [任务](docs/tasks/YC-001.md) 与 [复盘](docs/tasks/YC-001-retrospective.md)。

## YC-001：Git 测试隔离配置与环境，不只隔离目录

首轮独立验收用临时模拟的全局 hooksPath 证明测试会写到 fixture 仓库外；
Git hook 还可能传入 GIT_DIR/GIT_INDEX_FILE。测试清理 GIT_*、隔离 HOME/全局与系统 Git 配置，
并用外部 hook 内容不变的断言防复发。另验证同内容 hook 的执行位，而不只比较字节。
证据见 [独立验收](docs/tasks/YC-001-acceptance.md)。Seen：2026-11-01（一次）。

## YC-002：按协议处理路径，验证绑定干净 checkout

独立验收发现 `.strip()` 会把 Git diff 首个路径的前导空格删除，从而绕过允许目录判断；
finish 仅核对目标 ref 时也会接受脏工作区。路径保留原始分隔内容，验收同时核对目标 checkout、
分支、SHA 和干净状态；不要用 `.git` 字符串前缀误禁 .github 等合法治理路径。
三个问题均已加入 scripts/test_agentctl.py 的回归。Seen：2026-11-01（一次）。
证据：[YC-002 独立验收](docs/tasks/YC-002-acceptance.md)。

## YC-005：真实进程与 CLI 路径也必须进入验收

仅导入模块的测试漏掉了 CLI 作为 __main__ 加载的 Error 类身份差异；独立 Claude 审查后增加真实 CLI 回归。
执行快照必须在提交前后稳定，包括删除和重命名。正常退出也需停止本次进程组，之后才保存快照。
不能用服务 SUCCESS、手工工具标签或格式不合规的 PASS 代替有效产物；原始回执与提交 SHA 必须可追溯。
证据：[真实 agy 复盘](docs/tasks/YC-005-retrospective.md)。Seen：2026-11-01（一次）。

## EV-fc87a9cc433a：自动探针的已验证记录

探针 snapshot_directory_replacement 在 e423762366a47a2a422e58f7edf168f42c637d7a 失败，在 9a27ea19ef03f1993871e5bc98e37a2ab4877555 通过。
这是一条事实记录，尚未自动晋升为工程规范。证据见 [复盘](docs/tasks/EV-fc87a9cc433a-retrospective.md)。

## YC-007：协议、审查与恢复都要绑定可复现事实

真实 pi 完成事件可带 agent_settled；只凭退出码或单一末事件判断会丢弃合法产物。显式 responseModel 冲突应拒绝，不能用工具标签证明模型。审查的阻塞意见须核对源码与复现，非阻塞建议不等于失败；保留原结论并显式复核，不能改写成 PASS。恢复前先检查租约能覆盖验证时间，过期不先消耗门禁/模型资源。上述协议、失败不重派、worktree 隔离与租约边界已有回归。见 [复盘](docs/tasks/YC-007-retrospective.md)。Seen：2026-11-01（一次）。

## YC-008：验证实际入口解释器，不能仅核对 Python 版本

同机 Homebrew Python 提供 waitid/WNOWAIT，Apple Python 3.9.6 没有。完整门禁在前者通过并不能证明用户终端的后者可启动。CLI 在台账副作用前做能力检查，必要时选择已安装兼容解释器；子进程 PATH 用绝对目录以跨 worktree cwd 保持有效，不降级 PID 保留和进程组清理。加入真实 Apple Python 单轮 watch 和无候选失败检查。见 [任务](docs/tasks/YC-008.md)。
