# 本地任务协作

## 职责与状态来源

[agentctl.py](../../scripts/agentctl.py) 是 Python 3.9+ / SQLite / Git 本地 CLI。
`Ledger` 管理台账和状态转换；Git 保存代码；`handoff` 输出跨工具任务说明。
数据库位于 Git common dir 的 `agentctl/ledger.sqlite3`，所有 linked worktree 共用，
不进 Git、不上传。task 表存当前状态，events 表追加状态历史及证据快照。
证据最多 1 MiB UTF-8，写入台账时保存原文和 SHA256，原文件后续改变不影响快照。

此工具面向同一操作系统用户下的协作，不是恶意 Agent 的安全边界。
owner/reviewer 是操作者声明的会话标识；检查二者不同，但不验证身份。
路径范围在提交时核对，不是 OS 写入沙箱。任务说明来自用户选择的来源，不授予额外权限。

## 状态与中断

`ready → provisioning → running → review → approved → integrated`。
领取使用 BEGIN IMMEDIATE 原子保留任务、尝试编号和随机令牌，再创建独占 worktree；
Git 与 SQLite 不是跨系统事务。创建中断会保留 provisioning，必须人工确认旧会话停止后 recover。
恢复只使任务重新 ready，保留旧 worktree、分支和事件；新尝试使用新路径及新令牌。
租约到期不会自动重派，不会杀进程；renew 只续有效 running 租约。
同任务默认最多 3 次尝试，耗尽后停止；任务依赖必须已 integrated 且集成提交包含在所选 base 中。

submit 检查有效令牌/租约、干净工作区、实际分支/HEAD、base 祖先关系和允许路径。
验收绑定提交，作者与验收者标识必须不同；ISSUES/BLOCKED 返回 running，并保留评审原因。
批准后若工作区 HEAD/内容变化，queue 显示 eligible=false，reserve 拒绝；重新 submit 清除旧评审。
approved 表示历史批准，不能单独当作当前可集成证明。

## 串行集成

reserve 占用数据库唯一集成槽，记录任务 head、目标本地分支与基线、集成人和令牌。
它不执行 Git 合并。人工获得授权后合并并在最终版本运行完整门禁。
finish 核对目标分支最新 SHA、所含任务提交和基线、仍有效的批准及门禁证据结构、同仓库目标 checkout 的干净 HEAD，才记录 integrated。
门禁证据包含 head、worktree、command、exit_code、log；它是操作者提交的运行记录，CLI 不伪称自己执行了验证。
integration 可查看持久集成槽并恢复令牌；release 记录原因并释放，Git 冲突/产物由原操作者处理。
这个槽只序列化使用本 CLI 的协作，不阻止其他终端直接执行 Git。
integrated 必须连同 integrated_target 阅读；集成到试验分支不等于进入 main 或发布。

## 工具边界与验证

agy / Codex / pi / omp 首版共用手动适配器：handoff → 在指定 worktree 启动独立会话 →
外部日志/本地提交 → submit。harness 字段只是运行工具标签，不对应未验证的自动启动 API。
观察用 show/list/queue；停止由操作者完成，recover 的 --stopped 是明确确认。
不提供后台唤醒、自动合并、推送、发布、模型调用或强杀进程。

[test_agentctl.py](../../scripts/test_agentctl.py) 使用隔离 HOME/Git 配置及真实临时仓库，覆盖并发、
重启、租约、创建中断、旧结果隔离、范围/脏状态、独立评审、版本变化、串行集成和证据快照。
统一门禁调用该测试；任务演练见 [YC-002](../tasks/YC-002.md)。
