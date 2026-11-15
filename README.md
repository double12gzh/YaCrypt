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

- Rust 1.88+ (Edition 2021)
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

包含 4 个核心工作视图与全局快捷键（支持数字键 `1`-`4` 或 `Tab` / `Shift+Tab` 切换，按 `?` / `F1` 打开内置文件作用、受众、保密等级与跨电脑说明手册，按 `Shift+L` / `F2` 实时切换 **中文 / English** 并自动记住偏好，`q` / `Ctrl+C` 安全退出并擦除口令缓冲，`Esc` 关闭弹窗或退出编辑态）：
- **`[1] Keyring`**：自动扫描 `keystore/` 目录，展示所有密钥对指纹、本地别名及 5 类关联文件的**用途与保密级别标注**（公钥可分享 / 私钥 `.asc.enc` 绝密需备份）；非空密钥环按 `Enter` 选中当前高亮密钥作为加密接收方并切换到 `[2] Encrypt`，按 `n` 可随时弹窗生成新密钥对（密钥环为空时按 `Enter` 亦可新建），按 `l` 设置/清除本地密钥别名，按 `p` 轮换本地私钥备份口令，按 `r` 刷新。
- **`[2] Encrypt`**：支持 **自动生成新密钥对并签名加密**、**选择已有公钥加密（可选签名）** 以及 **纯口令对称加密（`.enc` / `SGPGv2`）** 三种模式；新生成的 `.pubenc` (`SCFv2`) 默认将 Ed25519 签名隐入 AEAD 密文内层，且 `.pubenc` (`SCFv2`) 与 `.enc` (`SGPGv2`) 默认启用长度混淆填充；加密完成后弹出居中完成摘要弹窗（展示输出文件、签名/密钥指纹与保密及跨机携带提示）；在文件路径栏按 `f` / `Ctrl+O` 唤起内置文件浏览器弹窗，编辑路径时按 `Tab` 自动补全。
- **`[3] Decrypt & Verify`**：输入或通过 `f` / `Ctrl+O` 选择路径后实时调用免口令密文头透视（自动兼容识别 `SCFv2`/`SCFv1` `.pubenc` 与 `SGPGv2`/`SGPGv1` `.enc`），比对本地密钥环并固定预期签名者指纹信任锚（绝不盲信未认证密文头自动篡改选钥），对 `.pubenc` 默认在落盘前强制完成验签，解密完成后同样弹出居中结果与验签摘要弹窗。
- **`[4] Password Gen`**：实时调节口令长度（`←` / `→`），按 `Enter` / `g` 基于拒绝采样生成无模偏差的高熵随机口令（`v` 切换遮蔽/明文，`c` 擦除内存）。

---

## 快速开始：加密 → 解密 完整流程

以下是最常见的端到端使用流程。

### Step 1: 加密文件

```bash
yacrypt encrypt secret.txt --label alice
```

输出示例（默认生成匿名随机文件名以隐藏原文件名，默认不写 `.decrypt.txt`，并默认推荐自动生成高熵备份口令）：
```
🔐 Step 1/2: Generating keypair and encrypting keys...
? Auto-generate backup encryption password? (Y/n) › yes
✅ Backup password generated:
   ...
🏷️  Local key label: [alice] (stored only in local 0600 keystore index)
✅ Keys generated and encrypted. Fingerprint: A1B2C3D4...
🔐 Step 2/2: Signing and encrypting file...
✅ File encrypted with public key: 8f3a1c90e4b27d15.pubenc
✅ Complete encryption workflow finished!

📦 Generated files:
   - Encrypted file:        8f3a1c90e4b27d15.pubenc
   - Public key:            ~/.yacrypt/keystore/x25519_public_A1B2C3D4....asc
   - Encrypted private key: ~/.yacrypt/keystore/x25519_private_A1B2C3D4....asc.enc
   - Fingerprint:           A1B2C3D4...

📋 To decrypt this file, run:
   yacrypt decrypt 8f3a1c90e4b27d15.pubenc \
       --private-key ~/.yacrypt/keystore/x25519_private_A1B2C3D4....asc.enc

⚠️  Keep your encryption password safe! It is required for decryption.
```

### Step 2: 解密文件

直接使用本地别名（或私钥备份路径/`>=16` 位指纹前缀）解密并指定输出文件名还原 `secret.txt`：

```bash
yacrypt decrypt 8f3a1c90e4b27d15.pubenc --private-key alice -o secret.txt
```

输入加密时设置的私钥备份密码，即可在落盘前自动强制校验 Ed25519 签名与签名者公钥指纹，并还原 `secret.txt`。

---

## 所有命令

> 支持全局 `--keystore-dir <DIR>` 与环境变量 `YACRYPT_KEYSTORE`（若当前目录已存在 `./keystore` 则优先兼容读写，否则默认使用 `0700` 权限的 `~/.yacrypt/keystore`）。

### 1. `tui`（或无参数运行）— 启动交互式终端工作台

```bash
yacrypt
# 或
yacrypt tui
```

### 2. `encrypt` — 加密文件（推荐）

一键完成：生成密钥对 → 加密密钥 → 签名 → 加密文件（默认输出匿名 `<16hex>.pubenc`，且默认不生成 `.decrypt.txt`）：

```bash
yacrypt encrypt <file> [--label <alias>] [--output <out>] [--instructions] [--force]
```

使用已有接收方公钥/本地别名加密（交互式 TTY 下省略 `--key` 或 `--sign-key` 的参数值时可列表选钥；可选传入自有 `--sign-key` 进行签名）：

```bash
yacrypt encrypt <file> --key [x25519_public.asc | label | fp_prefix] [--sign-key [private.asc.enc | label | fp_prefix]] [--output <out>] [--instructions] [--force]
```

使用纯口令对称加密（`-c` / `--symmetric`，`SGPGv2` 格式，带长度混淆填充，无需公私钥，默认输出匿名 `<16hex>.enc`）：

```bash
yacrypt encrypt <file> -c [--output <out.enc>] [--force]
```

### 3. `decrypt` — 解密文件（推荐）

解密公钥混合加密文件（`.pubenc`：支持 `SCFv2` 与遗留 `SCFv1`；默认要求有效 Ed25519 签名，无签名文件需显式传 `--allow-unsigned`；交互式 TTY 下省略 `--private-key` 或省略其参数值时可从本地密钥环列表选钥；`--require-signature` 为 `.pubenc` 默认行为，并可显式拒绝无签名的 `.enc` 对称文件）：

```bash
yacrypt decrypt <file.pubenc> \
    [--private-key [x25519_private_*.asc.enc | label | fp_prefix]] \
    [--signer <64-hex-fingerprint | label | public_<fp>.asc>] \
    [--require-signature] \
    [--allow-unsigned] \
    [--output <out>] \
    [--force]
```

解密纯口令对称加密文件（`.enc`：自动检测 `SGPGv2` / 遗留 `SGPGv1` 头部，无需 `--private-key`；若传入 `--require-signature` 将拒绝解密无签名的 `.enc` 文件）：

```bash
yacrypt decrypt <file.enc> [-c] [-o <out>] [--force]
```

### 4. `inspect` — 免口令透视加密文件或密钥备份

免口令解析 `.pubenc`（`SCFv2`/`SCFv1`）或 `.enc` / `.asc.enc`（`SGPGv2`/`SGPGv1`）头部元数据、算法套件、长度填充开关、Argon2id 参数及遗留 `SCFv1` 内嵌签名者指纹（`SCFv2` 签名隐藏于 AEAD 内层，外层不暴露），并自动比对本地 `keystore/`：

```bash
yacrypt inspect <file.pubenc | file.enc | keystore/private_*.asc.enc>
```

### 5. `key-list`（别名 `keys`）— 列出本地密钥环

扫描并展示本地 `keystore/` 目录下所有密钥对指纹、本地别名及 Ed25519 / X25519 公私钥文件状态：

```bash
yacrypt key-list
# 或
yacrypt keys
```

### 6. `gen-keypair` — 生成密钥对

```bash
yacrypt gen-keypair [--label <alias>]
```

生成的文件：

| 文件 | 说明 |
|------|------|
| `keystore/public_<fp>.asc` | Ed25519 公钥（签名验证用） |
| `keystore/x25519_public_<fp>.asc` | X25519 公钥（加密用） |
| `keystore/private_<fp>.asc.enc` | 加密的 Ed25519 私钥 |
| `keystore/x25519_private_<fp>.asc.enc` | 加密的 X25519 私钥 |
| `keystore/recovery_instructions_<fp>.txt` | 恢复说明（含解密命令） |
| `keystore/labels.tsv` | 本地密钥别名索引（指定 `--label` 时写入，`0600` 权限，绝不写入密文） |

### 7. `key-label` — 设置或清除本地密钥别名

设置或清除仅存于本地 `keystore/labels.tsv`（`0600` 权限，绝不写入密文或导出公钥包）的密钥别名（`<key>` 支持现有别名、`>=16` 位指纹前缀或密钥文件路径）：

```bash
yacrypt key-label <key> [label] [--clear]
```

### 8. `key-export`（别名 `export-key`）— 导出自签名合并公钥包

使用本地 Ed25519 私钥对 Ed25519 + X25519 公钥生成自签名绑定包（默认输出 `yacrypt_pubkey_<FP16>.asc`；`[key]` 支持本地别名、`>=16` 位指纹前缀或密钥文件路径，交互式 TTY 下省略时可列表选钥）：

```bash
yacrypt key-export [key] [-o <bundle.asc>] [--force]
# 或
yacrypt export-key [key] [-o <bundle.asc>] [--force]
```

### 9. `key-import`（别名 `import-key`）— 验证并导入对端公钥包

校验 Ed25519 自签名绑定与 X25519 低阶点后，将对端公钥导入本地 `keystore/`（可选通过 `--label` 绑定本地别名）：

```bash
yacrypt key-import <bundle.asc> [--label <alias>] [--force]
# 或
yacrypt import-key <bundle.asc> [--label <alias>] [--force]
```

### 10. `change-key-password` — 轮换本地私钥备份口令

使用全新随机 salt 与 nonce 同步轮换本地 Ed25519 与 X25519 加密私钥备份的保护口令（`[key]` 支持本地别名、`>=16` 位指纹前缀或密钥文件路径，交互式 TTY 下省略时可列表选钥）：

```bash
yacrypt change-key-password [key]
```

### 11. `gen-password` — 生成强密码

```bash
yacrypt gen-password [--length 32]
```

生成指定长度的随机密码（默认 32 字符），使用拒绝采样消除模偏差。

### 12. `encrypt-file-with-key` — 使用已有公钥直接加密

`--public-key` 与 `--sign-key` 支持传入密钥文件路径、本地别名或 `>=16` 位指纹前缀；在交互式 TTY 下省略 `--public-key`（或省略 `--sign-key` 的参数值）均可从本地密钥环列表选钥（默认在输入文件同目录输出匿名随机 `<16hex>.pubenc`，采用 `SCFv2` 长度混淆填充容器）：

```bash
yacrypt encrypt-file-with-key \
    --input document.txt \
    [--public-key [x25519_public_*.asc | label | fp_prefix]] \
    [--sign-key [private_*.asc.enc | label | fp_prefix]] \
    [--output <out.pubenc>] \
    [--force]
```

### 13. `decrypt-private-key` — 导出原始 Ed25519 私钥

解密本地 Ed25519 私钥备份并导出 PKCS#8 DER 文件（支持传入 `.asc.enc` 路径、本地别名或 `>=16` 位指纹前缀，交互式 TTY 下省略时可列表选钥）：

```bash
yacrypt decrypt-private-key [keystore/private_<fp>.asc.enc | label | fp_prefix] [-o output.der] [--force]
```

### 14. `completions` — 生成 Shell 自动补全脚本

向标准输出生成对应 Shell 的自动补全脚本（`powershell` 亦支持别名 `pwsh`）：

```bash
yacrypt completions <bash|zsh|fish|powershell>
```

---

## 安全设计

- 加密文件（`.pubenc`：`SCFv2`/遗留 `SCFv1`）与口令加密容器（`.enc` / `.asc.enc`：`SGPGv2`/`SGPGv1`）均包含独立 magic header + 版本号，并通过 AAD `type` 字段（`type=file`、`type=ed25519`、`type=x25519`）严格做密码学域分离，防止格式或用途混淆
- **防已知明文离线比对（`SCFv2`）**：新建 `.pubenc` 默认保留 Ed25519 数字签名，但将签名数据与签名者公钥整体移入 AEAD 密文内层（Sign-then-Encrypt，绑定临时公钥、接收者公钥与明文摘要），外层 `flags` 恒为 `0x00`、不暴露任何可验证签名或签名者指纹，无接收者私钥的外部观察者无法做离线候选原文验签比对
- **默认隐藏精确字节数**：`SCFv2`（`.pubenc`）与 `SGPGv2`（`.enc`）默认在加密内层施加最小底线 + `OsRng` 随机抖动 + Padmé 对齐的长度混淆填充，使外部无法通过密文文件大小反推原文件精确字节数
- AAD 仅绑定协议必需的安全关键字段（`v`、临时公钥 `ephemeral_pub`、密钥指纹 `fp`、载荷类型 `type`，以及遗留 `SCFv1` 的 `flags`/`sig_vk`），任何头部篡改均导致 AEAD 解密认证失败；AAD 不携带任何文件名/身份元数据（含其摘要——低熵摘要可被字典还原，已整体移除，2026-10-18 复审 M-3 收口）
- Ed25519 签名验证与签名者指纹信任锚核验在写入磁盘**之前**执行，验证失败或签名者指纹不匹配则立即中止并拒绝输出任何数据
- 所有敏感内存在使用后立即通过 `zeroize` 清零（含 TUI 口令输入缓冲与 CLI 临时口令）
- 输出与私钥文件默认使用 `create_new` + `O_NOFOLLOW` + `0o600` 权限写入，拒绝跟随符号链接、非普通文件与静默覆盖既有文件
- `.pubenc` 解密默认强制验证 Ed25519 数字签名（处理不可信来源输入时切勿传入 `--allow-unsigned`）；跨不可信渠道接收文件时，建议使用 `--signer <64-hex-fingerprint | label | public_<fp>.asc>` 固定预期签名者信任锚，当密文容器类型同样不可信时，可额外传入 `--require-signature` 明确拒绝无签名的纯口令对称 `.enc` 文件
