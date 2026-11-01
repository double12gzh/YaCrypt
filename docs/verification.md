# 验证与证据

## 完整入口

从仓库根目录运行 `bash scripts/verify.sh` 或 `make verify`。脚本也支持通过绝对路径从其他目录运行。
需要 Bash、Python 3.9+、Rust/Cargo（rustfmt、clippy）和 cargo-deny 0.20.2。
工具缺失时先安装到明确的工具目录（例如 `cargo install cargo-deny --version 0.20.2 --locked --root <目录>`），
再将其 bin 加入 PATH；不要把缺失步骤当作通过。脚本不会自动安装。
Cargo 依赖及 RustSec 数据库初次获取需要网络；审计不可达是阻塞，不是干净结果。

源码依赖使用 Cargo.lock，Cargo 检查带 --locked；审计数据库仍会随时间变化。
报告记录工具版本、平台和审计时间，不承诺不同日期有相同审计结果。

## 隔离和记录

- 每个写入会话独占 `.worktrees/<task>`；构建默认使用该 worktree 的 target。
  如果环境设置了共享 CARGO_TARGET_DIR，改为该任务独立目录后运行。
- 测试使用临时数据与测试口令，不操作真实 keystore。更改测试前核对其文件/子进程清理。
- 记录 base/head SHA；未提交阶段记录 base SHA、差异及新增文件的内容哈希清单。
  最终独立审查绑定实际提交，后续实现修改使原结论失效。
- 保留命令、退出码、关键输出及完整日志位置；只有完整入口退出 0 才能写完整门禁通过。
- 修复类任务应在临时副本撤销修复或注入故障，看到针对行为的失败，再恢复并通过。
  编译错误、跳过测试、工具缺失均不能充当行为失败证据。

## 补充验证

分项 `cargo test -p yacrypt-core <filter>` 用于诊断，不能替代完整门禁。
密码学、存储、CLI/TUI 的风险场景见 [子系统索引](subsystems/README.md)。
验收报告必须列出未运行平台、真实终端/发布资产等缺口。
首次任务及证据见 [YC-001](tasks/YC-001.md)。
统一入口同时运行 scripts/test_agentctl.py，验证真实临时 Git/SQLite 的协作状态与隔离。

运行器回归 scripts/test_agy_runner.py 使用本地假进程，不访问真实 agy 或模型服务；完整门禁包含该检查。

多运行器协议回归 `scripts/test_runtime_adapters.py` 和自动闭环回归 `scripts/test_evolution.py` 已纳入同一完整入口。测试采用临时 Git/SQLite 和假 CLI 子进程；不访问模型服务。真实模型演练另存任务证据。

运行监督需要 Python 的 POSIX waitid/WNOWAIT API；Apple 自带 Python 3.9.6 可能未编译这些 API。evolution 的 scan/tick/watch/resume 和 agentctl run 在打开台账前检查；缺失时探测 PATH、/opt/homebrew/bin/python3、/usr/local/bin/python3 的现有解释器，打印提示并保持参数重启，同时为本进程及子进程优先使用所选 python3。不安装软件、不改全局 PATH；没有可用解释器则明确失败，不派工。纯台账操作仍可使用原解释器。直接运行完整门禁时也须将具备该 API 的 Python 放在 PATH 首位。

质量入口回归 scripts/test_quality_intake.py 纳入完整门禁，使用临时 Git/SQLite、实际子进程和假模型 CLI，覆盖证据去重/漂移/篡改、批准前零派工、风险范围、原批准失效及批准后的完整反馈。真实产品覆盖缺口另用可失败的回归证明，不能用干净门禁代替不存在的产品验收。
