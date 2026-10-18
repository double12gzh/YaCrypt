# YaCrypt

[ZH](README.md)|[EN](README_EN.md)

## 简介

`YaCrypt` 是一个安全的文件加密/解密命令行工具，基于现代密码学原语构建。

**技术栈：**
- **密钥派生**: Argon2id (抗 GPU/ASIC)
- **对称加密**: XChaCha20-Poly1305 (AEAD, 24 字节 nonce)
- **密钥交换**: X25519 ECDH + HKDF-SHA256
- **数字签名**: Ed25519
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

### 1. `encrypt` — 加密文件（推荐）

一键完成：生成密钥对 → 加密密钥 → 签名 → 加密文件：

```bash
yacrypt encrypt <file> [name] [email] [--output <out>] [--force]
```

使用已有公钥加密（跳过密钥生成，可选传入 `--sign-key` 进行签名）：

```bash
yacrypt encrypt <file> --key keystore/x25519_public_<fingerprint>.asc [--sign-key keystore/private_<signer_fp>.asc.enc] [--force]
```

### 2. `decrypt` — 解密文件（推荐）

解密私钥 → 解密文件 → 验证签名与签名者指纹信任锚：

```bash
yacrypt decrypt <file.pubenc> \
    --private-key <x25519_private_*.asc.enc> \
    [--signer <64-hex-fingerprint-or-public_fp.asc>] \
    [--require-signature] \
    [--output <out>] \
    [--force]
```

### 3. `gen-keypair` — 生成密钥对

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

### 4. `gen-password` — 生成强密码

```bash
yacrypt gen-password [--length 32]
```

生成指定长度的随机密码（默认 32 字符），使用拒绝采样消除模偏差。

### 5. `encrypt-file-with-key` — 使用已有公钥直接加密

```bash
yacrypt encrypt-file-with-key \
    --input document.txt \
    --public-key keystore/x25519_public_<fp>.asc \
    [--sign-key keystore/private_<signer_fp>.asc.enc] \
    [--output document.pubenc] \
    [--force]
```

### 6. `decrypt-private-key` — 导出原始 Ed25519 私钥

```bash
yacrypt decrypt-private-key keystore/private_<fp>.asc.enc [-o output.der] [--force]
```

---

## 安全设计

- 加密文件（`.pubenc`）与私钥备份（`.asc.enc`）均包含独立 magic header + 版本号，防止格式混淆
- AAD 仅绑定协议必需的安全关键字段（`flags`、临时公钥 `ephemeral_pub`、签名公钥 `sig_vk`、密钥指纹 `fp`、密钥类型 `type`），任何头部篡改或签名剥离均导致 AEAD 解密认证失败；AAD 不携带任何文件名/身份元数据（含其摘要——低熵摘要可被字典还原，已整体移除，2026-10-18 复审 M-3 收口）
- Ed25519 签名验证与签名者指纹信任锚核验在写入磁盘**之前**执行，验证失败或签名者指纹不匹配则立即中止并拒绝输出任何数据
- 所有敏感内存在使用后立即通过 `zeroize` 清零
- 输出与私钥文件默认使用 `create_new` + `O_NOFOLLOW` + `0o600` 权限写入，拒绝跟随符号链接、非普通文件与静默覆盖既有文件
- 跨不可信渠道接收文件时，建议使用 `--require-signature` 强制要求签名，并用 `--signer <指纹>` 固定预期签名者
