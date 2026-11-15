# CLI 与 TUI

[main.rs](../../src/main.rs) 调用 `try_mlockall`，解析全局 `--keystore-dir` 并通过 Clap 分发，
顶层错误统一使用人类可读 `Display` 输出。无参数运行在交互式 TTY 进入 [tui/mod.rs](../../src/tui/mod.rs)，
在非 TTY 环境自动输出帮助信息并以状态码 `0` 退出；显式 `yacrypt tui` 在非 TTY 返回可读错误。
其他子命令进入 [cli.rs](../../src/cli.rs)（含 `key-export`、`key-import`、`change-key-password`、
`key-label`、`completions`），在选钥与提示口令前先通过 `O_NONBLOCK` 普通文件检查、输出路径冲突/`(dev, ino)`、
公钥算法类型及 `inspect_file`（含 `SGPGv1`/`SGPGv2` 子类型与签名要求拒绝）完成预检；交互式 TTY 下省略选钥值时通过
`dialoguer::Select` 列表选钥，`encrypt --sign-key` 显式依赖 `--key`。CLI `gen-keypair` 已移除易留存 Shell 历史的 `name`/`email` 位置参数，且新建私钥备份口令交互默认首选自动生成 48 字节高熵随机口令；CLI `encrypt` 默认输出匿名 `<16hex>.pubenc`/`.enc` 并默认跳过 `.decrypt.txt`（需显式 `--instructions` 才写入）；CLI `decrypt` 对 `.pubenc` 默认要求有效 Ed25519 签名（与 TUI 对齐，无签名 `.pubenc` 需显式 `--allow-unsigned` 放行），对 `.enc` 对称容器仅在显式传入 `--require-signature` 或 `--signer` 时拒绝。

TUI 的 [app.rs](../../src/tui/app.rs) 管理 4 个标签页、弹窗、口令缓冲（`Drop` 兜底清零）与操作状态；
[i18n.rs](../../src/tui/i18n.rs) 提供双语（`UiLang::{En, Zh}`）支持与内置文件指南：`TuiApp::new` 固定默认 `En` 保证测试确定性，
真实终端入口通过 `detect_initial` 按 `<keystore_dir>/ui_lang`（非阻塞普通文件校验）>`YACRYPT_LANG`>`LC_ALL`/`LC_MESSAGES`/`LANG` 识别语言，
运行中可通过 `Shift+L` 或 `F2` 实时切换中英文，并在 `keystore_dir` 已存在时按 `0600` 写入 `<keystore_dir>/ui_lang`（绝不擅自建空目录）；
[ui.rs](../../src/tui/ui.rs) 负责无副作用绘制，TestBackend 测试覆盖无头渲染：
- 字符输入过滤 `CONTROL` / `ALT` / `SUPER` / `META` 修饰键，支持 `Ctrl+U` 清空/清零、`Ctrl+H` 退格，口令长度校验与掩码统一按 `.chars().count()` 计数；
- 对称加密采用 `SymmetricPassword` 双框确认；自动生成 64 字符备份口令采用已保存复选确认锁、最小宽度保障单行展示、展示用途说明及本次加密输出路径提示、提供 `[p]` 无边框自动换行复制视图，确认关闭并清零秘密缓冲后自动衔接展示 `OperationSummary`；
- 加解密完成后均展示居中 `OperationSummary` 结果摘要弹窗（含自动口令新密钥加密关闭备份弹窗后的自动衔接），直观展示模式、产物路径、签名/指纹与跨电脑注意事项，并可直接按 `?` 进入说明指南；
- `[1] Keyring` 详情面板内联展示 5 类密钥文件的用途与保密级别；非空密钥环按 `Enter` 直接选中当前高亮密钥并切往 `[2] Encrypt`（仅空密钥环按 `Enter` 或任意时刻按 `'n'` 打开新建密钥对弹窗），`?` / `F1` 在任意页面（含摘要弹窗内）呼出可滚动的 `HelpGuide` 文件作用、受众、保密与跨电脑使用指南；
- `[2] Encrypt` 启动时若本地已有完整自有密钥对则默认选中首组自有密钥（避免重复生成新密钥对），默认勾选跳过生成伴生 `.decrypt.txt`（`enc_no_instructions = true`），输出路径留空时生成匿名随机名 `<16hex>.pubenc`/`.enc`（`pending_encrypt_output` 在前置校验时单次锁定，确保预检与落盘路径一致），新建密钥对弹窗默认启用自动生成 48 字节高熵备份口令（`auto_generate = true`）；同时支持接收方公钥（含导入的对端公钥与外部 `.asc`）与自有签名私钥（仅列含 `ed25519_enc_path` 条目或无签名）解耦选择，密钥环刷新按指纹保持已选项；
- `[3] Decrypt` 在输入路径变更时立即清空 `dec_last_verified_fp`，私钥仅列自有 `x25519_enc_path`，`Expected Signer` 默认锚定解密密钥所有者（支持手动切换本地密钥环条目，绝不从密文头自动预填），遗留 `SCFv1` 头部指纹不一致、显式无签名 `SCFv1` (`has_signature == Some(false)`) 或对无签名对称容器 (`SGPGv1`/`SGPGv2`) 显式指定签名者时标黄预警并拦截；`SCFv2` 因签名隐藏于 AEAD 内层 (`has_signature == None`)，透视栏显示“已随密文内层加密”与长度填充状态，不前置误报无签名，而在解密阶段严格先验签后落盘；
- `[1] Keyring` 与文件浏览器均按视口实际高度切片滚动，保证选中项始终可见；耗时 Argon2id 前先绘制进度遮罩并在返回后排空积压按键；输错口令立即清零旧缓冲并保留弹窗供重试；路径栏未进入编辑态时防单次误触 `'q'` 直接闪退。
[tui_viewport.rs](../../tests/tui_viewport.rs) 固化 80×12 等窄小窗口与长 Unicode 路径/名称测试。

[tui/mod.rs](../../src/tui/mod.rs) 使用 `TerminalSessionGuard`（RAII `Drop`）按已成功进入的状态逆序恢复
Alternate Screen、光标可见性、Raw Mode 与 Panic Hook，并通过注入式 `TerminalLifecycleOps` 单测验证初始化半途失败回滚。

验收：单测验证状态、恢复守卫与无头绘制，[cli_e2e.rs](../../tests/cli_e2e.rs) 使用 PTY 驱动口令交互与补全语法校验。
渲染测试不代替真实终端的输入、取消与退出检查；UI 变更报告需注明两种证据及未执行项。
完整门禁见 [验证](../verification.md)。
