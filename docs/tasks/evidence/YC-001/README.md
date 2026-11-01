# YC-001 验证证据

- 日期：2026-11-01（Asia/Shanghai）
- 环境：macOS / Darwin arm64；rustc 1.92.0；Cargo 1.92.0；Python 3.14.5；cargo-deny 0.20.2。
- 命令：`PATH=/private/tmp/yacrypt-phase1-tools/bin:$PATH bash scripts/verify.sh`
- cwd：YaCrypt/.worktrees/phase1；退出码：0。
- 流程回归 5/5；Rust 测试 3（TUI）+ 7（CLI E2E/PTY）+ 49（core）= 59/59；doc-tests 0。
- fmt、clippy、workspace build 均通过；cargo-deny 退出 0，输出 advisories/bans/licenses/sources ok。
- 审计警告：license-not-encountered；index-failure（无法查询若干包的 yanked 状态）。
  不能将工具退出成功描述成所有 registry 状态已核验；未改 deny.toml 或忽略项。
- Rust/Cargo 提示用户旧 config 文件名弃用；未改用户配置。

[完整压缩日志](verification.log.gz) 可用 `gzip -dc` 查看，解压后 SHA256：
`d4f75b6851d449734640818d8812e0be6eda58752d2bd14d4c841f7d0a91b807`。
[故障注入日志](mutation.log)：在临时副本移除 --workspace，回归用例以 AssertionError 失败；
原工作区未改变。日志中的 VERIFY PASS 是被故意破坏的替身流程错误放行，正是测试捕获的缺陷，
不能当作本体门禁结果。真实 Cargo 用于成员测试，其他 Cargo 阶段在该小夹具中使用替身。

本机未执行 Linux、Intel macOS、远端 Actions、交互式 TUI 人工运行、发布资产验证。
测试没有使用真实私钥或用户文件；临时工具安装不属于项目交付依赖，其他机器按验证文档准备工具。
