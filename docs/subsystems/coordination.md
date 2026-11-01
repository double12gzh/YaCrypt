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

`ready → provisioning → running → review → approved → integrated`（评审 `ISSUES` 返回 `running`，`BLOCKED` 进入 `blocked`）。
领取使用 BEGIN IMMEDIATE 原子保留任务、尝试编号和随机令牌，再创建独占 worktree；
Git 与 SQLite 不是跨系统事务。创建中断会保留 provisioning，必须人工确认旧会话停止后 recover。
恢复只使任务重新 ready，保留旧 worktree、分支和事件；新尝试使用新路径及新令牌。
租约到期不会自动重派，不会杀进程；renew 只续有效 running 租约。
同任务默认最多 3 次尝试，耗尽后停止；任务依赖必须已 integrated 且集成提交包含在所选 base 中。

submit 检查有效令牌/租约、干净工作区、实际分支/HEAD、base 祖先关系和允许路径。
验收绑定提交，作者与验收者标识必须不同；PASS 进入 approved，ISSUES 返回 running 并保留评审原因，BLOCKED 持久化为 blocked。
blocked 任务拒绝 renew、submit 和执行运行（run --role execute），直至人工确认旧会话停止后显式 recover --stopped 回到 ready；下次 claim 创建新尝试与新令牌，历史评审证据保留在事件中。
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

agy 已提供显式 `run` 适配器，源码为 [agy_runner.py](../../scripts/agy_runner.py)，操作见
[agy 运行说明](../agy-runner.md)。它实际查询模型目录、启动 print 子进程，并持久保存请求模型、
运行参数、conversation_id、退出码、用量、日志哈希与状态；不再只记录工具标签。
pi/omp 已接入 [runtime_adapters.py](../../scripts/runtime_adapters.py)，可用 run --harness 指定验收工具。Codex CLI 仍为手动 handoff。

run 在数据库中先保留 active_run，再启动独立进程组；有效执行租约必须覆盖超时及清理余量。
active_run 阻止重复运行和手动 submit/review。异常退出时保留失败回执；监督进程被强杀时可能
留下 starting/running，操作者必须先停止旧进程组，再 recover --stopped，新结果由尝试和 run ID 隔离。
正常退出、超时、SIGINT/SIGTERM/SIGHUP/SIGQUIT 都会终止所创建的进程组；waitid/WNOWAIT 保留 leader PID 到清理完成，随后才验证产物；不承诺控制自行脱离该组的进程。
日志位于 common Git dir/agentctl/runs，保留原始结果但不自动加入 Git。

执行模型使用 accept-edits + sandbox，验收模型使用 plan + sandbox。这些是 agy 策略，
不是本 CLI 提供的 OS 权限沙箱。验收完成还核对工作区未改变、提交未漂移，失败时保留现场。
跨模型验收要求本次尝试有成功执行回执，并且模型 ID 除 effort 后不同；不把 high/low 当作不同模型。
agy JSON 当前不返回可证明的后端模型身份，所以 requested_model 表示明确传入且被服务接受的选择，
不能冒称独立验证了服务内部实际使用的模型。运行成功也不等于任务通过，review 回执须由协调者检查后
用原 review 命令写入判定；agy 任务要求回执的 actor/head/verdict 和 response 哈希匹配，不能用任意手写报告代替。
提交也必须匹配成功执行后的文件快照，协调者修改产物后需重新执行。不会自动批准、合并或发布。

执行快照覆盖 Git 可见的文件路径、内容、执行位及符号链接目标；不跟随链接，悬空或指向目录的链接也计入。
索引仍列出、但工作区已删除或被真实目录替换的旧文件路径不计入；目录内 Git 可见的文件和链接仍逐一校验。
因此删除、重命名和文件替换为目录在暂存/提交前后快照一致。协调者改动子文件或链接目标仍使 submit 失败。

[test_agentctl.py](../../scripts/test_agentctl.py) 使用隔离 HOME/Git 配置及真实临时仓库，覆盖并发、
重启、租约、创建中断、旧结果隔离、范围/脏状态、独立评审、版本变化、串行集成和证据快照。
统一门禁调用该测试；任务演练见 [YC-002](../tasks/YC-002.md)。

[运行器测试](../../scripts/test_agy_runner.py) 使用本地假 agy 子进程验证参数、失败、交叉模型、超时和进程组清理；真实模型演练单独记录，测试不访问模型服务。

任务 diff 和额外指令各限 80 KiB，组合提示词限 96 KiB，超限失败关闭并要求拆分。

支持范围：任务路径采用 UTF-8；非 UTF-8 文件名会失败关闭，不在本版跨平台支持范围。
信号处理不是与 SQLite 原子提交绑定的事务：保留 active_run 后、安装处理器前，以及切换清理信号
处理器的极短窗口内被中断，仍可能留下 starting/running；这与硬崩溃一样必须确认进程停止后 recover。
清理期间忽略重复中断是正常已安装处理器路径的行为，不承诺消除这些窗口。

## 有限自动闭环

[evolution.py](../../scripts/evolution.py) 管理确定性探针、候选去重、独占 cycle 锁、单任务执行、完整门禁、独立验收、候选分支集成和复盘写回。
操作与失败契约见 [自进化说明](../evolution.md)。candidates 表是可增量建立的本地状态，原任务 schema 保持兼容。
queued 候选不自动重派；阶段日志和任务令牌属于不同权限数据，公开 cycle.json 不包含令牌。
每轮最多两个受超时约束的 agent 会话，不自动重试、改政策、合并 main 或发布。成功后下一轮使用候选分支的新经验。
pi/omp 的实际 run 标记 runtime_managed，submit/review 同样强制绑定真实回执；旧的手动 pi/omp handoff 兼容。
运行器按路由末段与 effort 归一化模型身份；显式 responseModel 不匹配时拒绝。NDJSON 必须有会话及最终完整结束事件。
新增 [适配器回归](../../scripts/test_runtime_adapters.py) 和 [闭环回归](../../scripts/test_evolution.py) 纳入统一门禁。

显式 resume --recheck 只支持原租约仍覆盖门禁时间的失败提交；过期/余量不足先拒绝，不自动续期或消耗模型预算。已提交内容保留，跨租约恢复须先检查现场再 reconcile --stopped。

运行监督需要 Python 的 POSIX waitid/WNOWAIT API；Apple 自带 Python 3.9.6 可能未编译这些 API。evolution 的 scan/tick/watch/resume/diagnose 和 agentctl run 在打开台账前检查；缺失时探测 PATH、/opt/homebrew/bin/python3、/usr/local/bin/python3 的现有解释器，打印提示并保持参数重启，同时为本进程及子进程优先使用所选 python3。不安装软件、不改全局 PATH；没有可用解释器则明确失败，不派工。纯台账操作仍可使用原解释器。直接运行完整门禁时也须将具备该 API 的 Python 放在 PATH 首位。

## 质量证据入口

[quality_intake.py](../../scripts/quality_intake.py) 将完整门禁运行记录存入 quality_diagnostics，将不可变任务正文与显式批准存入 quality_proposals；候选通过 approved_backlog 接入原串行闭环。诊断和提案不调用模型；环境/未知/高风险范围只报告。批准绑定精确 HEAD 与正文哈希；漂移成为 stale，需重新提案，不能自动扩大范围。原两种扫描候选的自动权限不扩展到任意测试失败或模型建议。失败阶段分类仅用于恢复提示，不增加重试预算。契约和风险白名单见 [使用说明](../evolution.md)。
