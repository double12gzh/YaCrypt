# YaCrypt

[ZH](README.md)|[EN](README_EN.md)

## 简介

`YaCrypt` 是一个安全的文件加密/解密命令行工具与交互式终端工作台（TUI），基于现代密码学原语构建，采用 `yacrypt-core`（纯数据驱动核心库）+ `yacrypt`（CLI & Ratatui TUI 双前端）架构。

**技术栈：**
- **密钥派生**: Argon2id (抗 GPU/ASIC)
- **对称加密**: XChaCha20-Poly1305 (AEAD, 24 字节 nonce)
- **密钥交换**: X25519 ECDH + HKDF-SHA256
- **数字签名**: Ed25519
- **交互前端**: Clap CLI + Ratatui / Crossterm TUI
- **内存保护**: zeroize + mlockall (Linux)

## 系统要求

- Rust 1.70+ (Edition 2021)
- Linux / macOS

## 安装

### 从源码构建

```bash
git clone https://github.com/double12gzh/YaCrypt.git
cd YaCrypt
cargo build --release

# 二进制文件位于
target/release/yacrypt
```

### 安装到系统路径（可选）

```bash
cargo install --path .
```

---

## 交互式 TUI 工作台（4 合 1）

直接运行无参数 `yacrypt`（或 `yacrypt tui`）即可进入全屏交互式终端工作台：

```bash
yacrypt
# 或
yacrypt tui
```

包含 4 个核心工作视图（支持数字键 `1`-`4` 或 `Tab` / `Shift+Tab` 切换，`q` / `Esc` 安全退出并擦除口令缓冲）：
- **`[1] Keyring`**：自动扫描 `keystore/` 目录，展示所有密钥对指纹、Ed25519/X25519 公私钥完备状态；按 `n` / `Enter` 弹窗生成新密钥对，按 `r` 刷新。
- **`[2] Encrypt`**：支持 **自动生成新密钥对并签名加密**、**选择已有公钥加密（可选签名）** 以及 **纯口令对称加密（`.enc` / `SGPGv1`）** 三种模式；在文件路径栏按 `f` / `Ctrl+O` 唤起内置文件浏览器弹窗，编辑路径时按 `Tab` 自动补全。
- **`[3] Decrypt & Verify`**：输入或通过 `f` / `Ctrl+O` 选择路径后实时调用免口令密文头透视（自动识别 `.pubenc` 或 `.enc`），自动匹配本地私钥与签名者指纹信任锚，解密前强制完成验签。
- **`[4] Password Gen`**：实时调节口令长度（`←` / `→`），按 `Enter` / `g` 基于拒绝采样生成无模偏差的高熵随机口令。

---

## 快速开始：加密 → 解密 完整流程

以下是最常见的端到端使用流程。

### Step 1: 加密文件

```bash
yacrypt encrypt secret.txt "Alice" "alice@example.com"
```

输出示例：
```
🔐 Step 1/2: Generating keypair and encrypting keys...
? Auto-generate backup encryption password? (y/N) › no
? Enter backup encryption password › (input hidden)
? Confirm password › (input hidden)
👤 Key owner: Alice <alice@example.com> (not stored in any file — keep your own record)
✅ Keys generated and encrypted. Fingerprint: A1B2C3D4...
🔐 Step 2/2: Signing and encrypting file...
✅ File encrypted with public key: secret.pubenc
✅ Complete encryption workflow finished!

📦 Generated files:
   - Encrypted file:       secret.pubenc
   - Public key:           keystore/x25519_public_A1B2C3D4.asc
   - Encrypted private key: keystore/x25519_private_A1B2C3D4.asc.enc
   - Fingerprint:          A1B2C3D4...

📋 To decrypt this file, run:
   yacrypt decrypt secret.pubenc \
       --private-key keystore/x25519_private_A1B2C3D4.asc.enc

⚠️  Keep your encryption password safe! It is required for decryption.
```

### Step 2: 解密文件

直接复制上一步输出的命令：

```bash
yacrypt decrypt secret.pubenc \
    --private-key keystore/x25519_private_A1B2C3D4.asc.enc
```

输入加密时生成（或设置）的私钥备份密码，即可解密并在落盘前自动校验 Ed25519 签名与签名者公钥指纹。

---

## 所有命令

### 1. `tui`（或无参数运行）— 启动交互式终端工作台

```bash
yacrypt
# 或
yacrypt tui
```

### 2. `encrypt` — 加密文件（推荐）

一键完成：生成密钥对 → 加密密钥 → 签名 → 加密文件（输出 `<file>.pubenc`）：

```bash
yacrypt encrypt <file> [name] [email] [--output <out>] [--force]
```

使用已有公钥加密（跳过密钥生成，可选传入 `--sign-key` 进行签名）：

```bash
yacrypt encrypt <file> --key keystore/x25519_public_<fingerprint>.asc [--sign-key keystore/private_<signer_fp>.asc.enc] [--force]
```

使用纯口令对称加密（`SGPGv1` 格式，无需公私钥，默认输出 `<file>.enc`）：

```bash
yacrypt encrypt <file> -c [--output <out.enc>] [--force]
```

### 3. `decrypt` — 解密文件（推荐）

解密公钥混合加密文件（`.pubenc`：解密私钥 → 解密文件 → 验证签名与签名者指纹信任锚）：

```bash
yacrypt decrypt <file.pubenc> \
    --private-key <x25519_private_*.asc.enc> \
    [--signer <64-hex-fingerprint-or-public_fp.asc>] \
    [--require-signature] \
    [--output <out>] \
    [--force]
```

解密纯口令对称加密文件（`.enc`：自动检测 `SGPGv1` 头部，无需 `--private-key`）：

```bash
yacrypt decrypt <file.enc> [-o <out>] [--force]
```

### 4. `inspect` — 免口令透视加密文件或密钥备份

免口令解析 `.pubenc`（`SCFv1`）或 `.enc` / `.asc.enc`（`SGPGv1`）头部元数据、算法套件、Argon2id 参数及内嵌签名者指纹，并自动比对本地 `keystore/`：

```bash
yacrypt inspect <file.pubenc | file.enc | keystore/private_*.asc.enc>
```

### 5. `key-list`（别名 `keys`）— 列出本地密钥环

扫描并展示本地 `keystore/` 目录下所有密钥对指纹及 Ed25519 / X25519 公私钥文件状态：

```bash
yacrypt key-list
# 或
yacrypt keys
```

### 6. `gen-keypair` — 生成密钥对

```bash
yacrypt gen-keypair "Your Name" "your.email@example.com"
```

生成的文件：

| 文件 | 说明 |
|------|------|
| `keystore/public_<fp>.asc` | Ed25519 公钥（签名验证用） |
| `keystore/x25519_public_<fp>.asc` | X25519 公钥（加密用） |
| `keystore/private_<fp>.asc.enc` | 加密的 Ed25519 私钥 |
| `keystore/x25519_private_<fp>.asc.enc` | 加密的 X25519 私钥 |
| `keystore/recovery_instructions_<fp>.txt` | 恢复说明（含解密命令） |

### 7. `gen-password` — 生成强密码

```bash
yacrypt gen-password [--length 32]
```

生成指定长度的随机密码（默认 32 字符），使用拒绝采样消除模偏差。

### 8. `encrypt-file-with-key` — 使用已有公钥直接加密

```bash
yacrypt encrypt-file-with-key \
    --input document.txt \
    --public-key keystore/x25519_public_<fp>.asc \
    [--sign-key keystore/private_<signer_fp>.asc.enc] \
    [--output document.pubenc] \
    [--force]
```

### 9. `decrypt-private-key` — 导出原始 Ed25519 私钥

```bash
yacrypt decrypt-private-key keystore/private_<fp>.asc.enc [-o output.der] [--force]
```

---

## 安全设计

- 加密文件（`.pubenc`）与口令加密容器（`.enc` / `.asc.enc`）均包含独立 magic header + 版本号，并通过 AAD `type` 字段（`type=file`、`type=ed25519`、`type=x25519`）严格做密码学域分离，防止格式或用途混淆
- AAD 仅绑定协议必需的安全关键字段（`flags`、临时公钥 `ephemeral_pub`、签名公钥 `sig_vk`、密钥指纹 `fp`、载荷类型 `type`），任何头部篡改或签名剥离均导致 AEAD 解密认证失败；AAD 不携带任何文件名/身份元数据（含其摘要——低熵摘要可被字典还原，已整体移除，2026-10-18 复审 M-3 收口）
- Ed25519 签名验证与签名者指纹信任锚核验在写入磁盘**之前**执行，验证失败或签名者指纹不匹配则立即中止并拒绝输出任何数据
- 所有敏感内存在使用后立即通过 `zeroize` 清零（含 TUI 口令输入缓冲与 CLI 临时口令）
- 输出与私钥文件默认使用 `create_new` + `O_NOFOLLOW` + `0o600` 权限写入，拒绝跟随符号链接、非普通文件与静默覆盖既有文件
- 跨不可信渠道接收文件时，建议使用 `--require-signature` 强制要求签名，并用 `--signer <指纹>` 固定预期签名者
