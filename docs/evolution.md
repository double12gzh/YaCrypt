# 有边界的自进化闭环

入口为 `python3 scripts/evolution.py --repo <checkout> scan|status|tick|watch`。
这是一套前台、有限次数的维护循环；不安装守护进程，不自动合并 main、push 或发布。
模板中的模型已在本机目录发现，真实可用性必须看运行证据；修改路由前确认项目内容可交给对应服务。

## 发现与范围

scan 只在干净 checkout 上运行两个固定检查，不调用模型：

- 用真实临时 Git 仓库验证“文件替换为目录后，执行快照在提交前后稳定”的不变量；失败才建立候选。
- 检查 docs 下受版本控制的 Markdown 本地相对文件链接；忽略归档证据、代码块、外链、锚点和编码路径。不是完整 Markdown 语法验证器。

候选记录具体证据、源码 HEAD、目标及允许路径；不是把任意 TODO、网页或模型建议直接变成执行权限。
SQLite 中按问题键去重，queued 候选不重复调用。第一次没有任务就退出 idle，零 agent 会话。
新增发现器需要确定性证据和独立审查；密码学、依赖升级、权限、门禁及发布策略不在自动派工范围。

## 执行一次

```bash
python3 scripts/agentctl.py init
python3 scripts/evolution.py scan
python3 scripts/evolution.py tick --policy docs/templates/evolution-policy.json
python3 scripts/evolution.py status
```

tick 最多选择一个白名单候选，独占文件锁；新建任务、作者 worktree 和候选集成 worktree。
实现使用 policy.author，验收使用 policy.reviewer；harness 不同不能代替模型不同。
作者只能读/改任务文件，协调器检查允许路径、重跑原探针、执行完整 verify、提交，并核对执行快照。
评审只能读文件，协调器提供真实门禁结果，原始响应必须通过 schema、SHA、模型、内容哈希及工作区校验。
PASS 后仅快进专属 `codex/evolution-EV-*` 候选分支，运行最终门禁并记录 integrated_target。

随后确定性生成 `docs/tasks/EV-*-retrospective.md` 和 LESSONS 事实条目，运行完整门禁再提交。
复盘包含发现证据、作者/验收者模型、提交版本及回执 ID；不把模型建议直接写成永久工程规范。
代码和复盘都在 Git 中，不只留在聊天或台账。候选分支进入人工集成流程。

## 有限持续运行

```bash
python3 scripts/evolution.py watch --policy docs/templates/evolution-policy.json --cycles 4 --interval 300
```

默认只跑一次，最多 24 轮。每轮最多两个 agent 会话，无自动返修；每个会话和每次完整门禁各有超时。
一次 agent 会话内部可以发生多次模型请求；这里限制的是会话数与墙钟时间，不承诺金额或 token 硬限。
成功后下一轮扫描上一轮的候选分支，执行者因此能读到新写回的 LESSONS；不会静默切换主工作区。
本轮未配置系统定时启动。要长期运行，应先观察成本与返工率，再明确周期、账号授权期限和预算。

## 失败、中断与恢复

cycle.json 位于 Git common dir/agentctl/evolution/<ID>，分阶段原子写入，保留 PID、运行阶段与日志路径。
失败立即停止，保留任务 worktree、集成槽和未提交的失败复盘；不把失败复盘写成成功教训。
监督进程退出后锁由 OS 释放，但 queued 标记不自动解除，因此重启不会重复消费预算。
确认旧进程停止后，先用 agentctl release 释放本任务持有的集成槽（如有），再运行 `evolution.py reconcile --task <ID> --stopped --reason <原因>`。它保存旧草稿/事件，结束旧尝试并显式授予新 generation 的预算；不直接启动模型。已经 integrated 的任务不能这样重跑。半途创建任务/工作区的崩溃不是跨系统原子事务，需人工核对。
台账与代码需要一起看；integrated 到候选分支不等于 main 已合并或发布。源候选尚未合入当前扫描分支时保持 queued。

## 运行器边界

agy 保留原适配；pi/omp 复用同一进程组监督、超时、信号、执行快照和 SHA 绑定。
pi/omp 禁止自动扩展/技能/上下文发现，执行仅提供 read/edit/write，验收仅提供 read；不提供 shell 或子 agent 工具。
这些工具限制不是操作系统文件沙箱；适用于本机同用户、可信仓库的协作，任务提示明确禁止读取 .git/认证/真实密钥。
pi/omp 读取真实目录并要求完整 NDJSON session→assistant stop→agent_end，错误/截断/缺末尾事件均失败。
若 responseModel 显式反驳所请求模型，失败关闭；没有该字段时只能证明服务接受了明确选择，不能认证服务内部后端。
跨路由相同末段模型 ID、仅 effort 不同均不能交叉自审；无法识别的服务内部别名仍需运营者核对。

pi 的合法 agent_settled 尾事件（aborted=false）也会接受；若为中止、将要重试或结束后仍有新模型事件则拒绝。
pi/omp 会话显式使用 low thinking，避免隐式继承全局高思考配置耗尽有限墙钟预算；模型 ID 和 effort 是不同维度。

## 对已提交结果复核并继续

`resume --task <ID> --recheck --reason <原因> --instructions <复核事实文件>` 显式授予一次额外验收会话：
先在相同干净提交重跑完整门禁，保留旧 ISSUES/失败记录，再取得新的真实模型结论；PASS 后继续候选集成和复盘。
不加 --recheck 时必须已经有当前提交的独立 PASS。变更过的工作区、BLOCKED、活跃进程或未释放的集成槽不能跳过。
本命令不是自动重试，额外会话计入 agent_runs；原循环仍最多两个会话。执行前需准备 verification.md 所列工具并确保 PATH 能找到 cargo-deny。
