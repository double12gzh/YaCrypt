# YC-007 验收报告

## 已执行的独立验收

- 自动任务提交：9a27ea19ef03f1993871e5bc98e37a2ab4877555。真实 pi 执行回执 058b6e5bc7041a79a4970eec；真实 omp 复核回执 1ca2b97c4467aaf1d6db0386，PASS、findings=[]。首次 ISSUES 回执 2dc0c8eca629a19ddb07983b 保留。
- 自动闭环：EV-fc87a9cc433a state=complete、agent_runs=3（默认两次，明确恢复额外一次），候选结果 f7436c51e0b34d013149206e75a0707470bd196b；代码、独立验收、集成门禁、LESSONS 和任务复盘均有实际记录。自动目标不是 main。
- 控制器 716129b：agy/Claude 运行 9 项闭环、3 项协议回归通过，发现租约时限问题。已加入门禁前拒绝和过期无副作用回归，最终代码版本 0ddd59f6713eb0419556c2041f8ddb5cafcbcf78 已获独立 Claude PASS；原 ISSUES 保留。
- 反证：pi 新增的两项关键回归在 e423762 的旧摘要实现上产生预期行为失败。原缺陷修复后的作者、复核、集成及复盘完整门禁均通过。

## 证据与限制

[证据清单](evidence/YC-007/manifest.json) 给出每份归档 SHA256；runtime 文件含明确模型选择、会话 ID、实际回执及输出哈希。原始输出流保留本机，不归档思考与完整工具上下文。
没有替模型执行权限限制编造测试结果：pi/omp 只用文件工具，协调器运行完整门禁；agy/Claude 实际运行了允许的隔离回归。
只验证本机 macOS/POSIX，未做其他平台、真实终端交互或发布验收。模型内部后端身份未被认证；本轮没有配置永久后台守护程序。

## 最终结论：PASS

agy/Claude 会话 4d7e530c-d470-4be3-9b38-b5fb0cb9b4ea 对最终代码提交 0ddd59f 给出 PASS、findings=[]，实际执行 9 项闭环测试。协调器完整入口通过 56 项 Python、59 项 Rust 测试及 fmt/clippy/build/deny。后续只补充此验收证据，不改变已验收代码。
再扫描返回 []；再次 tick 为 idle、agent_runs=0，候选状态 resolved。证据见同目录归档。
审查限制如实保留：Claude 未独立校验所有归档哈希，协调器已核对；它自报额外运行了只读 ls/grep，超出提示中指定的单一测试命令，但没有改文件。agy allow 配置并非严格 shell 命令白名单或 OS 沙箱，本轮不据此承诺更强隔离。
自动候选集成与人工交付分开：自动循环不写 main、不 push；本轮由协调器按用户已确认的 GitHub 目的地执行最终交付。
