# CLI 与 TUI

[main.rs](../../src/main.rs) 调用 `try_mlockall`，随后通过 Clap 分发。
无子命令或 `tui` 进入 [tui/mod.rs](../../src/tui/mod.rs)，其他命令进入
[cli.rs](../../src/cli.rs)，再调用 core；密码提示属于交互层。

TUI 的 [app.rs](../../src/tui/app.rs) 管理标签、弹窗、文件选择、口令输入和操作状态；
[ui.rs](../../src/tui/ui.rs) 负责绘制，TestBackend 测试覆盖无头渲染。
按键事件改变 app 状态，文件操作调用 core，成功或错误转成可见状态。
修改一个工作流时检查 CLI 与 TUI 两个入口，避免只修其中一个。

`run` 开启 raw mode 和 alternate screen，安装 panic hook；事件循环返回后清理秘密并恢复终端。
初始化中途的 `?` 返回与正常事件循环退出路径不同，不能把当前实现描述成覆盖所有失败的 RAII 守卫。
终端恢复的新保证必须有针对失败路径的验证。

验收：单测验证状态与绘制，[cli_e2e.rs](../../tests/cli_e2e.rs) 使用 PTY 驱动口令交互。
渲染测试不代替真实终端的输入、取消与退出检查；UI 变更报告需注明两种证据及未执行项。
完整门禁见 [验证](../verification.md)。
