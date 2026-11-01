# 用 agy 实际执行与跨模型验收

先确认项目内容允许交给所使用的模型服务。运行器不会读取认证文件；agy 使用本机已有登录状态。
本版需要 POSIX 进程组及 waitid/WNOWAIT，需要可执行的 `agy`。`agy models` 返回当前账号模型目录，目录可见不等于调用一定成功。

## 执行

按 [agentctl 手册](agentctl.md) 建任务，以 `--harness agy` 领取；保存返回的 token 和 worktree。
任务只允许对应 owner 写入。运行：

```bash
python3 scripts/agentctl.py run YC-EXAMPLE --role execute --model gemini-4-argon-high --actor author-session --token '<claim-token>' --seconds 300
```

此命令会真正启动 agy。模型 ID 必须来自本机目录；示例值来自 2026-11-01 的本机探测，未来请重新查询。
执行租约必须比超时多至少 5 秒，必要时先 renew。可用 `--instructions /tmp/task-notes.txt` 增补任务要求，
但不得扩展任务权限。提示词包含目标、范围和验收，不含 claim token。
模型被要求不提交、合并或推送；协调者检查 diff、运行完整门禁，再按人类 Git 身份提交和 submit。submit 校验成功执行后的文件快照；
若协调者修改了产物，需重新执行取得新快照，不能把修改归功于旧模型运行。

## 不同模型验收

提交进入 review 后，以不同会话标识和不同模型运行：

```bash
python3 scripts/agentctl.py run YC-EXAMPLE --role review --model claude-sonnet-5-5-medium --actor reviewer-session --seconds 300
```

验收者读取真实提交和 base diff；返回 head、verdict、findings 和 checks。只有 effort 不同会被拒绝。
如果输出格式不正确、提交不匹配或工作区被修改，运行失败且不会批准任务。
返回 receipt 中含 review 结构和日志目录。协调者检查完整结果后，用 `review --head ... --verdict ... --evidence <response.txt>`
记录实际判定；agy 任务会核对 response.txt 的哈希及 actor/head/verdict，手写替代报告会被拒绝。不要仅凭 status=succeeded 填 PASS。运行器不自动合并或发布。

## 观察与停止

run 前台运行，另一个终端可用 `show <id>` 查看 active_run、pid、请求模型及持久回执。
正常退出、超时和 Ctrl-C/SIGTERM/SIGHUP/SIGQUIT 都会在保存快照前清理本次进程组；清理期间忽略重复中断，保留 stdout/stderr/prompt/receipt。
监督进程被 SIGKILL 或机器中断后，先查现场、停止实际进程组，再 recover --stopped；不根据过期 PID 盲目杀进程。
失败后的部分文件保留，不自动还原。先复查 diff，再恢复新尝试或确认修正后重新运行。

本地日志可能含项目内容，原始日志不自动进 Git；归档前只选择必要的脱敏证据。
回执记录 requested_model、明确 argv、conversation_id 和用量。agy 当前 JSON 未提供后端模型认证字段；
“使用某模型”在本工具中指显式请求并被 agy 服务接受，不是后端身份的独立证明。

共享 .git 目录不暴露给模型。协调器验证分支和SHA，将仅本次任务diff放入验收提示词；模型读取源码，不能自行访问完整Git历史。

无交互调用通过 `--settings` 仅为本次会话允许两条命令：`python3 scripts/test_agentctl.py`、
`python3 scripts/test_agy_runner.py`。不修改全局权限，不跳过权限检查。其他命令需要协调者运行，
不得通过拼接 shell 命令扩展权限；出现 denied_actions 或空答复即失败，即使 agy 标记 SUCCESS。

单段 diff/额外指令限 80 KiB，组合提示词限 96 KiB，以适配命令行参数上限；更大任务需拆分。

支持范围：任务路径采用 UTF-8；非 UTF-8 文件名会失败关闭，不在本版跨平台支持范围。
信号处理不是与 SQLite 原子提交绑定的事务：保留 active_run 后、安装处理器前，以及切换清理信号
处理器的极短窗口内被中断，仍可能留下 starting/running；这与硬崩溃一样必须确认进程停止后 recover。
清理期间忽略重复中断是正常已安装处理器路径的行为，不承诺消除这些窗口。

## pi / omp

同一 run 命令支持 pi/omp claim；验收可加 `--harness omp` 跨工具。模型必须使用完整 provider/model selector。
例：pi 作者 `magpie/agentrouter/gpt-6.1-sol`，omp 验收 `magpie/amd/DeepSeek-V4.1-Flash`。
这些是本机明确路由示例，不是通用默认模型。完整闭环与约束见 [自进化说明](evolution.md)。
