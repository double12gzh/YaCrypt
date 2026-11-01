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
