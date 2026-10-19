# YaCrypt 通用文件自检 (`inspect`)、密钥环列表 (`key-list`) 与纯口令对称加解密 (`--symmetric`) 设计规范

- **日期**：2026-10-19
- **状态**：已确认（Approved）
- **范围**：`yacrypt-core` 通用自检与对称文件加解密 API + CLI `inspect` / `key-list` / `--symmetric (-c)` + TUI 联动升级

---

## 1. 目标

1. **通用文件免密自检（`yacrypt inspect <file>`）**：无需口令即可安全解析 `SCFv1`（`.pubenc` 公钥加密文件）与 `SGPGv1`（`.enc` 对称加密文件及 `.asc.enc` 私钥备份），展示格式、算法成本参数、AAD 域类型、内嵌签名指纹，并自动比对本地 `keystore/` 匹配状态。
2. **命令行密钥环列表（`yacrypt key-list` / `yacrypt keys`）**：在 CLI 中直接调用 `scan_keystore` 列出本地所有密钥对指纹及 5 个关联文件的完备状态。
3. **纯口令对称文件加解密（`--symmetric` / `-c`）**：允许用户无需生成公私钥对即可直接使用 Argon2id + XChaCha20-Poly1305（`SGPGv1` 容器，AAD 绑定 `type=file` 实现域分离）对任意文件进行口令加密与自动识别解密，并在 TUI 中同步支持。

---

## 2. `yacrypt-core` API 设计

### 2.1 对称文件加解密（`yacrypt_core::file_ops`）

- `pub fn encrypt_file_symmetric(input: &Path, password: &str, output: Option<&Path>, force: bool) -> Result<PathBuf, CryptError>`
  - 校验口令长度 `[MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH]`；
  - 读取输入文件至 `Zeroizing<Vec<u8>>`；
  - 使用 `DEFAULT_ARGON_M_COST_KIB` (64 MiB)、`DEFAULT_ARGON_T_COST` (2)、`DEFAULT_ARGON_P_COST` (1) 与 16B 随机 Salt 派生 32B 密钥；
  - 使用 24B 随机 XNonce 与 AAD `b"type=file"` 进行 XChaCha20-Poly1305 加密并打包为 `SGPGv1`；
  - 默认输出路径为 `<input>.enc`（通过 `write_file_strict_with_options` 以 `0o600` 写入）。
- `pub fn decrypt_file_symmetric(input: &Path, password: &str, output: Option<&Path>, force: bool) -> Result<PathBuf, CryptError>`
  - 解析 `SGPGv1` 头部与 AAD，强制校验 `aad_map.get("type") == Some("file")`（拒绝将 `type=ed25519` 或 `type=x25519` 私钥备份当作普通文件解密）；
  - 派生密钥并验证解密到 `Zeroizing<Vec<u8>>`；
  - 默认输出路径：若输入以 `.enc` 结尾则剥离 `.enc`，否则追加 `.decrypted`；
  - 严格以 `0o600` 写入磁盘后擦除明文缓冲。

### 2.2 通用文件免密自检（`yacrypt_core::workflow`）

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgpgInfo {
    pub blob_type: Option<String>,
    pub fingerprint: Option<String>,
    pub mem_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub ciphertext_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectedFile {
    Pubenc(PubencInfo),
    Sgpg(SgpgInfo),
}

pub fn inspect_file(path: &Path) -> Result<InspectedFile, CryptError>;
```
- 根据文件头魔数自动分派：若以 `SCFv1` 开头则调用 `inspect_pubenc_file` 返回 `InspectedFile::Pubenc`；若以 `SGPGv1` 开头则调用 `unpack_encrypted_blob` 解析 AAD 与 Argon2 参数返回 `InspectedFile::Sgpg`。

---

## 3. CLI 与 TUI 交互设计

1. **`Commands::Inspect { file: PathBuf }`**：
   - 调用 `inspect_file(&file)` 与 `scan_keystore(Path::new("keystore"))`；
   - 打印文件格式、加密套件、签名状态或 Argon2 参数，以及本地 `keystore/` 是否存在匹配指纹的密钥对。
2. **`Commands::KeyList`（`#[command(visible_alias = "keys")]`）**：
   - 调用 `scan_keystore(Path::new("keystore"))`，输出密钥对总数、每把密钥的 64 位指纹及 Ed25519/X25519 公私钥文件状态。
3. **`Commands::Encrypt` 新增 `#[arg(short = 'c', long)] symmetric: bool`**：
   - 当 `symmetric = true` 时，通过 `prompt_password_confirm` 读取口令并调用 `encrypt_file_symmetric`。
4. **`Commands::Decrypt` 将 `private_key` 改为 `Option<PathBuf>` 并新增 `#[arg(short = 'c', long)] symmetric: bool`**：
   - 若 `symmetric = true` 或 `inspect_file(input)` 识别为 `InspectedFile::Sgpg`（`type=file`），无需 `--private-key`，直接读取口令并调用 `decrypt_file_symmetric`；
   - 若为 `SCFv1`（`.pubenc`）文件，则要求提供 `--private-key` 并执行原有混合解密与验签流程。
5. **TUI 联动**：
   - `Encrypt` 面板：`Recipient Key` 选择器支持 `<🔐 Symmetric Password Only (.enc)>` 模式。
   - `Decrypt` 面板：输入路径时通过 `inspect_file` 实时识别 `SCFv1` 或 `SGPGv1`，若为 `SGPGv1 (type=file)` 则直接弹窗输入口令执行对称解密。
