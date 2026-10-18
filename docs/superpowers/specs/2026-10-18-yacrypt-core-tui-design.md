# YaCrypt Core 拆分与 TUI 四合一工作台设计规范

- **日期**：2026-10-18
- **状态**：已确认（Approved）
- **范围**：Workspace 架构演进（`crates/yacrypt-core` 物理拆分）+ 单二进制 CLI/TUI 融合入口 + `ratatui` 四合一终端交互工作台原型

---

## 1. 背景与目标

YaCrypt 当前为单包 CLI 结构（所有源码位于 `src/` 下），密码学原语、密钥管理、工作流编排与终端 I/O（`println!`、`dialoguer::Password`、`dialoguer::Confirm`）耦合在同一层。此外，用户在日常加解密与管理多套 `Ed25519 + X25519` 密钥对时，需要手动复制 64 位 SHA-256 指纹路径并区分签名密钥与加密密钥文件，存在较高的操作心智负担。

本次架构演进与 TUI 原型设计旨在达成以下目标：

1. **编译器级 Core 隔离**：通过 Cargo Workspace 拆出独立的 `crates/yacrypt-core` 库，物理剥离 `clap`、`dialoguer`、`ratatui`、`crossterm` 等 UI/CLI 依赖，提供纯数据驱动的 Rust API，为当前 CLI、TUI 以及未来可能的桌面 GUI 提供统一内核。
2. **100% 向后兼容的单二进制体验**：保留根目录 `yacrypt` 主二进制包；带原有子命令（`encrypt`、`decrypt`、`gen-keypair`、`gen-password`、`encrypt-file-with-key`、`decrypt-private-key`）运行时行为与输出格式保持 100% 兼容；直接运行无参数 `yacrypt` 或 `yacrypt tui` 时进入交互式 TUI 工作台。
3. **四合一 TUI 终端工作台**：基于 `ratatui` + `crossterm` 实现包含「密钥环管理（Keyring）」「文件加密（Encrypt）」「文件解密与验签（Decrypt）」「强口令生成（Password）」四个 Tab 的终端 UI，消除手动拼写长指纹路径的痛点。
4. **严格坚守 6 条安全红线**：
   - 先验签、后落盘（Verify-Before-Write）；
   - 敏感数据即时擦除（TUI 口令输入框与生成缓冲统一使用 `Zeroizing<String>`）；
   - 最小权限与原子同步（`0o600`、`O_NOFOLLOW`、`sync_all()`）；
   - Argon2 参数硬上限校验；
   - AAD 元数据强绑定；
   - Linux 下启动时调用 `try_mlockall()`。

---

## 2. Workspace 拓扑与模块划分

采用 **Root 混合 Workspace** 结构：根目录同时作为 `[workspace]` 与主二进制包 `yacrypt`，核心逻辑下沉至 `crates/yacrypt-core`。此结构保证 `cargo install --path .`、`Makefile` 构建目标 `target/release/yacrypt` 与现有 CI 脚本无缝兼容。

```text
YaCrypt/
├── Cargo.toml                  # [workspace] members = ["crates/yacrypt-core"] + [package] name = "yacrypt"
├── crates/
│   └── yacrypt-core/           # 纯核心库（零 CLI / TUI / 终端提示依赖）
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs          # 公共模块与类型重导出
│           ├── constants.rs    # 算法与二进制格式常量 (SGPGv1 / SCFv1)
│           ├── error.rs        # 统一错误类型 CryptError
│           ├── crypto.rs       # Argon2id、XChaCha20-Poly1305、HKDF、SGPGv1/SCFv1 编解码
│           ├── password.rs     # 拒绝采样高熵口令生成（返回 Zeroizing<String>）
│           ├── utils.rs        # try_mlockall、write_file_strict、指纹计算、AAD 解析与转义
│           ├── keystore.rs     # 密钥生成、私钥解密导出、keystore 目录扫描与解析
│           ├── file_ops.rs     # X25519 混合公钥加密与内嵌 Ed25519 签名核心逻辑
│           └── workflow.rs     # 高层加解密编排、AAD/签名一致性校验、.pubenc 免密头部自检
└── src/                        # 主二进制包 (CLI 适配层 + TUI 工作台)
    ├── main.rs                 # try_mlockall() + 路由分发（无参数或 Tui 子命令 -> tui::run()）
    ├── cli.rs                  # Clap 参数定义 + dialoguer 终端交互与标准输出格式化
    └── tui/                    # Ratatui 终端交互界面
        ├── mod.rs              # 终端 Raw Mode / Alternate Screen 生命周期与 Panic Hook
        ├── app.rs              # TUI 核心状态机、事件分发、Zeroizing 敏感缓冲管理
        └── ui.rs               # 顶栏 Tab 导航、四面板布局渲染与模态弹窗组件
```

---

## 3. `yacrypt-core` 核心 API 设计

`yacrypt-core` 中所有公开函数均不执行 `println!` 或调用 `dialoguer`，统一返回 `Result<T, CryptError>`。

### 3.1 统一错误类型（`yacrypt_core::error::CryptError`）

扩展 `CryptError` 以覆盖原先散落的 `String` / `Box<dyn Error>` 错误场景：
- `CryptError::Io(std::io::Error)`：文件读写、权限或目录创建错误
- `CryptError::Crypto(String)`：AEAD 解密失败、签名验证失败、低阶点公钥拒绝等
- `CryptError::Format(String)`：二进制 Magic 不匹配、AAD 格式错误、字段越界等
- `CryptError::Key(String)`：Argon2 参数越界、密钥长度错误、PKCS#8 DER 解析失败、口令长度不合规等

### 3.2 口令生成模块（`yacrypt_core::password`）

- `pub fn generate_strong_password(length: usize) -> Result<Zeroizing<String>, CryptError>`
  - 校验 `1 <= length <= 4096`，使用 `OsRng` 与拒绝采样从 `PASSWORD_CHARSET` 生成无模偏差随机字符串，封装在 `Zeroizing<String>` 中返回。

### 3.3 密钥环管理与自动发现（`yacrypt_core::keystore`）

1. **数据结构**：
   ```rust
   pub struct GeneratedKeys {
       pub fingerprint: String,
       pub signing_key: SigningKey,
       pub x25519_pub_path: PathBuf,
       pub x25519_enc_path: PathBuf,
       pub enc_path: PathBuf,
       pub pub_path: PathBuf,
       pub instr_path: PathBuf,
       /// 若使用自动生成口令，则返回该口令供调用方展示；若为用户传入口令则为 None
       pub auto_generated_password: Option<Zeroizing<String>>,
   }

   #[derive(Debug, Clone)]
   pub struct KeyringEntry {
       pub fingerprint: String,
       pub name: Option<String>,
       pub email: Option<String>,
       pub ed25519_pub_path: Option<PathBuf>,
       pub ed25519_enc_path: Option<PathBuf>,
       pub x25519_pub_path: Option<PathBuf>,
       pub x25519_enc_path: Option<PathBuf>,
   }
   ```
2. **核心函数**：
   - `pub fn generate_and_store_keys_in_dir(keystore_dir: &Path, name: &str, email: &str, password: Option<&str>) -> Result<GeneratedKeys, CryptError>`
     - 当 `password` 为 `Some(pass)` 时校验口令长度 `[MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH]`；当 `password` 为 `None` 时自动生成 48 字节 URL-safe Base64 随机口令并填入 `auto_generated_password`。
     - 保持内存中完成全部 Argon2id 派生与加密后再原子写入 `keystore_dir`（`0o700`）并支持失败回滚（H-2）。
   - `pub fn decrypt_signing_key_from_backup(enc_path: &Path, password: &str) -> Result<SigningKey, CryptError>`
   - `pub fn decrypt_private_key_backup_to_file(enc_path: &Path, password: &str, out: Option<&Path>, force: bool) -> Result<PathBuf, CryptError>`
   - `pub fn scan_keystore(keystore_dir: &Path) -> Result<Vec<KeyringEntry>, CryptError>`
     - 扫描指定 `keystore` 目录（若目录不存在则返回空 `Vec`），识别 `public_<FP>.asc`、`x25519_public_<FP>.asc`、`private_<FP>.asc.enc`、`x25519_private_<FP>.asc.enc` 及 `recovery_instructions_<FP>.txt`，按 64 位十六进制指纹聚合为 `KeyringEntry` 列表，并解析说明文件中的 `Name:` 与 `Email:` 元数据。

### 3.4 文件加密与工作流编排（`yacrypt_core::file_ops` & `yacrypt_core::workflow`）

1. **文件头部免密自检**：
   ```rust
   #[derive(Debug, Clone)]
   pub struct PubencInfo {
       pub has_signature: bool,
       pub signer_fingerprint: Option<String>,
       pub ephemeral_pub_hex: String,
       pub ciphertext_len: usize,
   }
   pub fn inspect_pubenc_file(path: &Path) -> Result<PubencInfo, CryptError>;
   ```
   - 无需口令或私钥，直接读取并校验 `SCFv1` 头部与 AAD，提取签名存在性及签名公钥的 SHA-256 指纹，供 TUI 在解密前即时预览并验证签名者信息。

2. **文件公钥混合加密**：
   - `pub fn encrypt_file_with_key(input: &Path, public_key_path: &Path, output: Option<&Path>, signing_key: Option<&SigningKey>, force: bool) -> Result<PathBuf, CryptError>`

3. **完整加密/解密工作流**：
   ```rust
   pub struct EncryptReport {
       pub encrypted_file: PathBuf,
       pub instructions_file: PathBuf,
       pub key_path: PathBuf,
       pub private_key_path: Option<PathBuf>,
       pub fingerprint: Option<String>,
       pub signed: bool,
       pub auto_generated_password: Option<Zeroizing<String>>,
   }

   pub struct DecryptReport {
       pub decrypted_file: PathBuf,
       pub verified_signer_fingerprint: Option<String>,
   }
   ```
   - `pub fn run_encrypt_workflow(...) -> Result<EncryptReport, CryptError>`
   - `pub fn run_decrypt_workflow(input: &Path, private_key_path: &Path, password: &str, output: Option<&Path>, signer: Option<&str>, require_signature: bool, force: bool) -> Result<DecryptReport, CryptError>`
     - 内部严格调用 `verify_pubenc_aad_and_signature`，确保在落盘前完成 AAD 一致性、防签名剥离（M-1）、Ed25519 签名验证与信任锚比对（H-1）。

---

## 4. CLI 与 TUI 融合路由设计

在根包 `src/cli.rs` 中：
- `Cli.command` 类型定义为 `Option<Commands>`。
- `Commands` 枚举在保留全部既有 6 个子命令的基础上，新增 `Tui` 子命令（`yacrypt tui`）。
- `src/main.rs` 启动时首先调用 `yacrypt_core::utils::try_mlockall()`，随后匹配 `cli.command`：
  - `None | Some(Commands::Tui)` $\rightarrow$ 进入 `tui::run()`；
  - 其余 6 个子命令 $\rightarrow$ 通过 `cli` 层中的 `dialoguer` 收集口令后调用 `yacrypt-core` 对应函数，并输出与原先完全一致的终端提示文本。

---

## 5. TUI 四合一工作台设计（`src/tui/`）

### 5.1 整体布局与导航

- **顶栏（Header）**：展示应用标题 `YaCrypt TUI Workbench` 与 4 个 Tab 标签（支持 `Tab` / `Shift+Tab` 或数字键 `1`~`4` 切换）：
  1. `[1] 🔑 Keyring (密钥环)`
  2. `[2] 🔒 Encrypt (文件加密)`
  3. `[3] 🔓 Decrypt (文件解密与验签)`
  4. `[4] 🎲 Password (口令生成)`
- **主内容区（Body）**：根据当前激活的 Tab 渲染对应面板。
- **底栏（Footer / Status Bar）**：展示当前面板快捷键提示与最近一次操作的状态通知（成功 `✅` / 警告 `⚠️` / 错误 `❌`）。
- **模态弹窗层（Modal Overlay）**：用于在生成密钥、签名加密或解密私钥时安全收集口令与表单项，支持 `Esc` 取消并立即 `zeroize()` 输入缓冲区。

### 5.2 四个功能面板详细交互

1. **Tab 1: Keyring（密钥环管理）**
   - **左栏**：展示 `scan_keystore("keystore")` 扫描到的密钥对列表（显示 `Name <Email>` 与短指纹前 12 位）。按 ` ↑ / ↓ ` 移动选中项，按 `r` 刷新列表。
   - **右栏**：展示选中密钥对的完整 64 位 SHA-256 指纹，以及 4 个关联文件（Ed25519 公私钥、X25519 公私钥）的存在状态与路径。
   - **新建密钥（按 `n`）**：弹出模态表单，输入 `Name`、`Email`，选择是否自动生成口令（或手动输入口令确认），调用 `generate_and_store_keys_in_dir`。若为自动生成口令，则在安全弹窗中展示一次口令（按 `Esc`/`Enter` 关闭弹窗时立即 `zeroize()` 清零）。

2. **Tab 2: Encrypt（文件加密）**
   - **表单字段**（按 ` ↑ / ↓ ` 在字段间切换，`Enter` 编辑/触发）：
     1. `Input File`：待加密文件路径输入框。
     2. `Output File`：可选输出路径（留空默认 `<input>.pubenc`）。
     3. `Recipient Key`：通过 ` ← / → ` 在本地 `KeyringEntry` 列表中切换选择接收方 X25519 公钥（亦支持切换为“新建密钥对并加密”模式）。
     4. `Sign File`：布尔开关（空格键切换），开启时自动关联所选密钥对的 `private_<FP>.asc.enc` 签名私钥。
     5. `Overwrite (--force)`：布尔开关（空格键切换）。
     6. `[ 🚀 Execute Encryption ]` 按钮：触发时若需解密签名私钥或新建密钥，弹出密码输入框，完成后调用 `yacrypt-core` 加密并在状态栏显示生成的 `.pubenc` 路径与签名指纹。

3. **Tab 3: Decrypt（文件解密与验签）**
   - **表单字段**：
     1. `Encrypted File (.pubenc)`：输入路径后自动调用 `inspect_pubenc_file` 实时预览文件头信息（显示文件是否携带签名、内嵌签名者指纹 `signer_fingerprint`、密文大小）。
     2. `Private Key`：通过 ` ← / → ` 从本地 `KeyringEntry` 列表中选择 `x25519_private_<FP>.asc.enc`（若内嵌签名指纹与本地某把密钥匹配，自动高亮推荐该密钥）。
     3. `Expected Signer`：可选信任锚指纹或留空使用密钥默认绑定指纹。
     4. `Require Signature` & `Overwrite (--force)`：布尔开关。
     5. `[ 🔓 Decrypt & Verify ]` 按钮：弹出私钥口令输入框（掩码 `*` 显示，`Zeroizing<String>` 存储），调用 `run_decrypt_workflow`。验签并落盘成功后展示绿色验签通过徽章与输出路径；若验签或解密失败，红色高亮显示具体安全拦截原因，且磁盘不产生任何残留文件。

4. **Tab 4: Password（强口令生成器）**
   - 支持通过 ` ← / → ` 或 `- / +` 调整口令长度（默认 32，支持步进调节）。
   - 按 `g` 或 `Enter` 调用 `generate_strong_password` 重新生成高熵口令（存储在 `Zeroizing<String>` 中）。
   - 按 `v` 切换掩码隐藏（`********`）与明文显示（防肩窥）；切换离开展板或退出应用时自动清零内存。

---

## 6. 安全与异常处理设计

1. **敏感内存管理**：
   - `TuiApp` 结构体中的口令输入缓冲（`password_input: Zeroizing<String>`、`confirm_input: Zeroizing<String>`）及生成的随机口令（`generated_password: Option<Zeroizing<String>>`）全部使用 `zeroize::Zeroizing`。
   - 任何弹窗关闭、操作执行完毕或应用退出时，显式清空敏感字符串。
2. **终端状态安全恢复**：
   - 在 `tui::run()` 中安装自定义 `std::panic::set_hook`，确保即使发生 panic，也会先执行 `disable_raw_mode()` 和 `LeaveAlternateScreen`，防止用户终端乱码或回显失效。
3. **依赖合规与许可证审计**：
   - 新增 TUI 依赖仅引入社区标准的 `ratatui` 与 `crossterm`（均为 MIT 许可证），确保 100% 通过 `cargo deny check`（符合 `deny.toml` 白名单）。

---

## 7. 测试与质量门禁策略

1. **Core 单元测试**：
   - 原 `crypto::tests`、`utils::tests`、`password::tests`、`workflow::tests` 全部迁移至 `crates/yacrypt-core` 并保持 100% 通过。
   - 为新增的 `scan_keystore`、`inspect_pubenc_file`、`run_encrypt_workflow`、`run_decrypt_workflow` 补充端到端单元测试。
2. **TUI 状态机单元测试**：
   - 在 `src/tui/app.rs` 中编写针对 Tab 切换、表单导航、弹窗口令擦除（验证关闭弹窗后缓冲区立即为空）及 Buffer 渲染（使用 `ratatui::backend::TestBackend`）的无头单元测试。
3. **全量质量门禁**：
   - 严格通过 `cargo fmt -- --check && cargo clippy --all-targets -- -D warnings && cargo test && cargo deny check`。
