# YaCrypt

[EN](./README.md)|[ZH](./README_CN.md)

超安全的加密/解密工具，基于 Rust 构建。通过内存锁定、敏感数据清零和严格文件权限实现零密钥泄露。

## 功能特性

- **Ed25519** 签名密钥对（PKCS#8 私钥存储）
- **X25519** 加密密钥对（混合加密）
- **Argon2id** 密钥派生，参数可配置
- **XChaCha20-Poly1305** AEAD 加密，24 字节 nonce
- **HKDF** 带 salt 的密钥派生，增强密钥独立性（SGPGv2 格式）
- **内存保护** 通过 `mlockall`（Linux）
- **严格文件权限**（0o600），原子创建无 TOCTOU 竞态
- **Zeroize** 使用后清零所有敏感数据
- **AAD**（关联认证数据）存储在文件头中
- **数字签名** 使用 Ed25519 验证文件完整性

## 系统要求

- Rust 1.70+（Edition 2021）
- Linux / macOS

## 安装

### 从源码构建

```bash
git clone https://github.com/double12gzh/YaCrypt.git
cd YaCrypt

# 构建发布版本
cargo build --release

# 二进制文件位于
target/release/YaCrypt
```

### 安装到系统路径（可选）

```bash
cargo install --path .
```

### 使用 Makefile

```bash
make build      # 构建发布版本
make test       # 运行测试
make clippy     # 运行 lint 检查
make security   # 安全审计
make all        # 完整流程: fmt + clippy + test + security + rebuild
```

## 使用方法

### 1. 生成密钥对

生成 Ed25519（签名）+ X25519（加密）密钥对，并创建加密的私钥备份：

```bash
YaCrypt gen-keypair "Your Name" "your.email@example.com"
```

创建的文件：

| 文件 | 说明 |
|------|------|
| `keystore/public_<fp>.asc` | Ed25519 公钥（Base64） |
| `keystore/x25519_public_<fp>.asc` | X25519 公钥（Base64） |
| `keystore/private_<fp>.asc.enc` | 加密的 Ed25519 私钥 |
| `keystore/x25519_private_<fp>.asc.enc` | 加密的 X25519 私钥 |
| `keystore/recovery_instructions_<fp>.txt` | 恢复说明 |

使用 `--keystore-dir` 指定自定义 keystore 路径：

```bash
YaCrypt --keystore-dir /path/to/keystore gen-keypair "Your Name" "email@example.com"
```

### 2. 生成强密码

生成加密安全的强密码（默认 32 字节，Base64 编码）：

```bash
YaCrypt gen-password [--length 48]
```

### 3. 加密文件（完整流程）

一条命令完成：生成密钥对 → 加密密钥 → 签名文件 → 加密文件：

```bash
YaCrypt encrypt document.txt "Your Name" "your.email@example.com" [-o output.pubenc]
```

执行步骤：

1. 生成 Ed25519 和 X25519 密钥对
2. 使用密码加密私钥并保存到 keystore
3. 使用 Ed25519 私钥对文件签名
4. 使用 X25519 公钥加密文件（混合加密：X25519 + XChaCha20-Poly1305）

### 4. 解密文件（完整流程）

一条命令完成：解密密钥 → 解密文件 → 验证签名：

```bash
YaCrypt decrypt document.txt.pubenc -p keystore/x25519_private_<fp>.asc.enc [-o document.txt]
```

如果签名验证失败，解密后的文件会被自动删除，防止使用被篡改的数据。

### 5. 解密私钥备份

将加密的私钥备份解密为明文 DER 格式：

```bash
YaCrypt decrypt-private-key keystore/private_<fp>.asc.enc [-o private_key.der]
```

## 文件格式（SGPGv2）

### 加密密钥 Blob

```
MAGIC           6 字节   "SGPGv2"
mem_kib         4 字节   Argon2 内存开销（大端序）
t_cost          4 字节   Argon2 时间开销（大端序）
p_cost          4 字节   Argon2 并行度（大端序）
salt_len        1 字节
salt            N 字节
nonce_len       1 字节
nonce           N 字节   （XChaCha20 为 24 字节）
aad_len         2 字节   （大端序）
aad             N 字节
ciphertext_len  8 字节   （大端序）
ciphertext      N 字节
```

### 加密文件（`.pubenc`）

```
ephemeral_pub   32 字节  X25519 临时公钥
nonce           24 字节  XChaCha20 nonce
aad_len         2 字节   （大端序）
aad             N 字节
ciphertext_len  8 字节   （大端序）
ciphertext      N 字节   XChaCha20-Poly1305 AEAD
```

## 安全设计

| 特性 | 实现方式 |
|------|---------|
| 密钥派生 | Argon2id（64 MiB, 2 次迭代） |
| 对称加密 | XChaCha20-Poly1305（AEAD） |
| 密钥交换 | X25519 ECDH + HKDF-SHA256（带 salt） |
| 签名 | Ed25519 |
| 内存保护 | Linux 上的 `mlockall` |
| 密钥清理 | 所有敏感数据使用 `zeroize` |
| 文件权限 | 原子创建 0o600（无 TOCTOU） |
| 参数校验 | Argon2 参数上限限制，防止 DoS |
| 低阶点防护 | X25519 共享密钥全零校验 |

## 许可证

MIT