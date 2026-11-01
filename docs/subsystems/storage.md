# 存储与密钥环

## 来源与边界

[keystore.rs](../../crates/yacrypt-core/src/keystore.rs) 的 `generate_and_store_keys_in_dir`
生成 Ed25519 / X25519 密钥，`scan_keystore` 列出配对和完备状态。
[utils.rs](../../crates/yacrypt-core/src/utils.rs) 的 `write_file_strict_with_options`
统一写入敏感输出；调用者负责决定路径与 `force`。

## 当前写入语义

默认 `create_new` 拒绝覆盖；force 模式打开目标后设置 0600，先截断再写入并 `sync_all`。
入口检查符号链接/非普通文件，open 使用 O_NOFOLLOW / O_NONBLOCK，随后检查已打开的 fd。
这些措施不等于所有路径竞态均被消除，也不提供崩溃原子替换：写入/同步中途失败时可能
留下新建的部分文件，force 模式可能已破坏旧内容。更强保证属于单独设计任务。

密钥目录设置 0700，敏感输出设置 0600。内存秘密通过 Zeroizing / Zeroize 等路径处理；
仅凭磁盘权限测试不能证明内存已完全清零。

## 失败与回滚

[workflow.rs](../../crates/yacrypt-core/src/workflow.rs) 的 `encrypt_workflow_with_new_keys`
在密钥生成成功而文件加密失败时尝试删除本轮生成的文件；删除结果被忽略，属于尽力回滚。
说明文件写入失败通过 `instructions_written=false` 表达，不能把它描述成整笔事务失败。
CLI/TUI 必须保留这些差异。既有文件与其他任务的密钥不属于本轮清理范围。

## 验证

utils 单测覆盖拒绝覆盖、force 权限、符号链接及 FIFO；CLI E2E 覆盖新密钥回滚。
修改写入行为时补充失败后的文件内容/存在性验证，并在目标 Unix 平台运行。
Windows 不是当前文件 I/O 实现的支持承诺。完整入口见 [验证](../verification.md)。
