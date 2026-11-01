# YC-001 独立验收

- 当前判定：修正后的内容复验通过，等待绑定最终实现提交。
- 验收者：独立 Agent `/root/independent_acceptance`（与实现会话分离，只读代码）。
- base：45afbb9b107f397bc11bc5d9f65c81e0fe4fcda4；head 待实现提交后记录。
- 日期与平台：2026-11-01，macOS arm64。
- [任务卡](YC-001.md)；[真实完整门禁证据](evidence/YC-001/README.md)。

## 首轮：ISSUES

验收者独立运行当时 4 个流程回归，读取本体完整门禁日志，抽查写入、验签、回滚、TUI 源码。
发现三个问题：

1. 两个技能文档的相对链接多退一层（已修为 ../../../docs）。
2. 临时 Git 测试继承用户全局 hooksPath 和 GIT_*；用临时模拟的外部 hooks 路径重现：
   测试退出 0，却在外部目录留下被写成 user-hook 的 pre-commit。
3. installer 对相同内容直接返回，未恢复执行位；可能报告已安装而 Git 实际忽略 hook。

## 修正与独立复验

- fixture 清理继承的 GIT_*，设置临时 HOME、GIT_CONFIG_GLOBAL=/dev/null、GIT_CONFIG_NOSYSTEM=1；
  保留 Cargo/rustup 路径，使临时 HOME 不破坏工具链。
- 增加外部 hooks 与 Git 定位环境回归：确保外部文件及目录保持不变。
- 相同内容 hook 恢复可执行权限，测试先去除权限再验证幂等安装。
- 验收者独立运行修正后的 5 项测试全部通过，并重新运行首轮外部 hooks 复现：退出 0，外部目录仍为空。
- 技能链接已修复；所抽查子系统文档与当前源码匹配。

## 范围与缺口

完整门禁由实现会话运行，验收者检查日志；独立验收者另外运行流程回归与外部 hooks 场景。
Rust 59 个测试通过；审计退出 0，但 yanked 查询警告保留，不能声称该项完整核验。
Linux/远端 CI、真实交互式 TUI、发布均未运行。第一阶段未增加 macOS CI 测试矩阵。
未推送、合并或发布；后续实现变化需重新验收。
