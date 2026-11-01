# 开发与交付

## 唯一完整门禁

[scripts/verify.sh](../../scripts/verify.sh) 定义检查顺序和 workspace 范围；
任一步失败立即非零退出，仅全部通过打印 VERIFY PASS。它从自身位置定位仓库，
无跳过参数，不自动安装工具、不格式化源码、不清理 target、不改审计政策。
Python 回归检查先运行，Cargo 格式、lint、测试、构建和依赖审计随后执行。

调用者：check 技能、release 准备技能、Makefile 的 verify/all、
[原生 hook](../../.githooks/pre-commit)、[pre-commit 配置](../../.pre-commit-config.yaml)
与 [CI check job](../../.github/workflows/cicd.yml)。分项 Make/Cargo 命令仅用于调试。
`make all` 现在执行门禁，既不格式化/clean，也不生成 release 构建；发布构建仍显式运行。

[install-hook.sh](../../scripts/install-hook.sh) 使用 Git 解析的 hook 路径，支持 linked worktree；
幂等安装同内容 hook，已有不同 hook 时保留并报错，由使用者迁移。
多个 worktree 可能共用 hooks，hook 在运行时解析当前 checkout 根目录。
不需要同时安装原生 hook 和 pre-commit；二者任选，CI 不依赖本地 hook 存在。

## 发布交接与边界

当前 CI 的 check 在 Ubuntu 执行；build 在 Linux、两个 macOS target 构建。
macOS 本地完整验证可记录，但 CI 中 macOS 全套行为测试仍是后续任务。
tag 的 publish-crate 与 create-release 都依赖 check/build，彼此独立；
GitHub Release 存在不代表 crates.io 发布成功。远端保护规则未在本地验证。
第一阶段产出可审查分支及证据，合并、推送和发布需要对应授权；没有后台调度器。
