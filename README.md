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
Enter backup password: ********
Confirm password: ********
✅ Keys generated and encrypted. Fingerprint: A1B2C3D4...
🔐 Step 2/2: Signing and encrypting file...
✅ Complete encryption workflow finished!

📦 Generated files:
   - Encrypted file:       secret.txt.pubenc
   - Public key:           keystore/x25519_public_A1B2C3D4.asc
   - Encrypted private key: keystore/x25519_private_A1B2C3D4.asc.enc
   - Fingerprint:          A1B2C3D4...

📋 To decrypt this file, run:
   yacrypt decrypt secret.txt.pubenc \
       --private-key keystore/x25519_private_A1B2C3D4.asc.enc

⚠️  Keep your encryption password safe! It is required for decryption.
```

### Step 2: 解密文件

直接复制上一步输出的命令：

```bash
yacrypt decrypt secret.txt.pubenc \
    --private-key keystore/x25519_private_A1B2C3D4.asc.enc
```

输入加密时设置的密码，即可解密并自动验证签名。

---

## 所有命令

### 1. `encrypt` — 加密文件（推荐）

一键完成：生成密钥对 → 加密密钥 → 签名 → 加密文件：

```bash
yacrypt encrypt <file> <name> [email] [--output <out>]
```

使用已有密钥加密（跳过密钥生成，无签名）：

```bash
yacrypt encrypt <file> --key keystore/x25519_public_<fingerprint>.asc
```

### 2. `decrypt` — 解密文件（推荐）

解密密钥 → 解密文件 → 验证签名：

```bash
yacrypt decrypt <file.pubenc> --private-key <x25519_private_*.asc.enc> [--output <out>]
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

生成指定长度的随机密码（默认 32 字符），使用字母、数字和特殊字符。

### 5. `encrypt-file-with-key` — 使用已有公钥加密

```bash
yacrypt encrypt-file-with-key \
    --input document.txt \
    --public-key keystore/x25519_public_<fp>.asc \
    [--output document.txt.pubenc]
```

### 6. `decrypt-file-with-key` — 使用已有私钥解密

```bash
yacrypt decrypt-file-with-key \
    --input document.txt.pubenc \
    --private-key keystore/x25519_private_<fp>.asc.enc \
    [--output document.txt]
```

### 7. `decrypt-private-key` — 导出原始私钥

```bash
yacrypt decrypt-private-key keystore/private_<fp>.asc.enc [-o output.der]
```

---

## 安全设计

- 加密文件（`.pubenc`）包含 magic header + 版本号，防止格式混淆
- Ed25519 签名嵌入加密文件内部，与密文密码学绑定
- 签名验证在写入文件**之前**执行，验证失败则拒绝输出
- 所有敏感内存在使用后立即 zeroize
- 私钥文件以 `0o600` 权限写入，避免 TOCTOU 竞态
