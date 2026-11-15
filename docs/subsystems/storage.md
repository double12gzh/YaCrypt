# 存储与密钥环

## 来源与边界

[keystore.rs](../../crates/yacrypt-core/src/keystore.rs) 的 `generate_and_store_keys_in_dir` /
`generate_and_store_keys_with_label` 生成 Ed25519 / X25519 密钥，`scan_keystore` 列出配对、完备状态与本地别名；
`export_public_key_bundle` / `import_public_key_bundle` 导出与验证导入附带 Ed25519 对 X25519 公钥自签名绑定的合并公钥包
（`--force` 导入时亦禁止将本地已有私钥配对的 `x25519_public_<FP>.asc` 覆盖为不匹配的 X25519 公钥）；
`change_keypair_password` 使用新随机 salt/nonce 同步轮换两把私钥备份口令。
`resolve_keystore_dir` 按 `--keystore-dir` > `YACRYPT_KEYSTORE` > 当前工作目录已存在的 `./keystore` >
`$HOME/.yacrypt/keystore`（`0700`）解析生效密钥环目录。
本地密钥别名仅保存在 `keystore/labels.tsv`（`0600`，自动过滤已删除密钥的孤立条目），严守 M-3 绝不写入密文、AAD 或导出的公钥包。
[utils.rs](../../crates/yacrypt-core/src/utils.rs) 的 `open_regular_file_nonblocking`、`preflight_check_output_path` 与
`write_file_strict_with_options` 统一检查普通文件输入与敏感输出；调用者负责决定路径与 `force`。

## 当前写入语义

`preflight_check_output_path` 在提示口令与 Argon2id 派生前检查符号链接/非普通文件、无条件拒绝
`input` 与 `output` 相同 Unix `(dev, ino)`（含硬链接，即使 `force=true` 亦拒绝），并在 `!force`
时提前拦截既有目标文件。
落盘阶段默认 `create_new` 拒绝覆盖；force 模式打开目标后设置 0600，先截断再写入并 `sync_all`。
入口检查符号链接/非普通文件，open 使用 O_NOFOLLOW / O_NONBLOCK，随后检查已打开的 fd。
这些措施不等于所有路径竞态均被消除，也不提供崩溃原子替换：写入/同步中途失败时可能
留下新建的部分文件，force 模式可能已破坏旧内容。更强保证属于单独设计任务。

密钥目录（含新建的 `~/.yacrypt`）设置 0700，敏感输出与 `labels.tsv` 设置 0600。内存秘密通过
Zeroizing / Zeroize 等路径处理；仅凭磁盘权限测试不能证明内存已完全清零。

## 失败与回滚

[workflow.rs](../../crates/yacrypt-core/src/workflow.rs) 的 `encrypt_workflow_with_new_keys_opts`
在密钥生成成功而步骤 2 文件加密失败时尽力删除本轮生成的 5 个密钥文件并移除本轮写入的本地别名；
`change_keypair_password` 与 `import_public_key_bundle` 在双文件更新的第二步失败时尽力恢复首个文件旧内容。
伴生 `.decrypt.txt` 默认跳过（`instructions_skipped=true`）；仅显式开启写入时若写入失败才通过 `instructions_written=false`（区别于 `instructions_skipped=true`）
表达，不能把它描述成整笔事务失败；CLI/TUI 均显式展示告警。既有文件与其他任务的密钥不属于本轮清理范围。

## 验证

utils / keystore 单测覆盖拒绝覆盖、同 inode 拦截、force 权限、符号链接、FIFO、公钥包自签名绑定与口令轮换；
CLI E2E 覆盖前置冲突拦截与步骤 2 新密钥/别名回滚。
修改写入行为时补充失败后的文件内容/存在性验证，并在目标 Unix 平台运行。
Windows 不是当前文件 I/O 实现的支持承诺。完整入口见 [验证](../verification.md)。
