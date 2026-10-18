# YaCrypt 安全与产品审计报告

- **审计日期**：2026-10-18
- **审计对象**：`double12gzh/YaCrypt` —— Rust 编写的文件加解密命令行工具（约 1,650 行，10 个源文件）
- **被审版本**：git `12f5258`（构建与全部实测所使用的版本）。审计期间仓库新增 `b778200`（rustfmt 格式化）、`3ba41bc`、`1a0f7be`（Agent 配置/文档）三个提交；经逐文件 diff 确认**源代码无功能变化**，本报告全部结论同样适用于当前 HEAD `1a0f7be`。
- **审计方式**：全量源码审查 + 静态分析 + 隔离环境构建（rustc 1.99.1 / aarch64 Linux）+ 28 个单元测试 + clippy + 端到端黑盒实测 20 项（含攻击 PoC）+ RustSec 依赖审计（cargo-deny 0.20.2）+ 独立第二审计员对抗性复核。
- **配套材料**：本报告关键证据与复现脚本位于仓库内 `security-audit-2026-10-18/` 目录（PoC、测试套件、日志、原始工件）。

> **修订注记（2026-10-18 复审后）**：本仓库随后经历一次 `git filter-branch` 历史重写（为统一 Gemini 署名邮箱）。文中提交哈希映射：`b778200→58d3590`、`3ba41bc→29167d1`、`1a0f7be→f92c5ae`（`12f5258` 未变）；修复相关旧哈希 `14e7460→52948ca`、`2fd82e9→860a077`，详见 `SECURITY-AUDIT-2026-10-18-FIX-VERIFICATION.md` §七-3。报告正文保留撰写时原貌。

---

## 0. 结论速览

**总体判断：密码学原语选型与主路径实现纪律总体良好，但当前状态不适合对外发布。** 存在两个发布阻断级问题："数字签名"功能目前不提供任何真实性保证（可被完全伪造，已复现）；Linux 常见默认配置下 `gen-keypair` / `encrypt` 主流程会直接崩溃，且可能留下会导致文件永久无法解密的半成品密钥状态（已复现）。此外供应链门禁（cargo-deny / Cargo.lock）实际处于失效状态。

| 编号 | 级别 | 问题 | 一句话影响 |
|------|------|------|------------|
| **H-1** | 高 | 签名验证无信任锚（`workflow.rs` 验签使用文件自带公钥） | 任何知道收件人公钥的人都能伪造出显示"签名验证成功"的文件（PoC 已复现） |
| **H-2** | 高 | `mlockall(MCL_CURRENT\|MCL_FUTURE)` 导致 Argon2 64MiB 分配失败（Linux 常见 memlock 配置） | `gen-keypair`/`encrypt` 崩溃中止（SIGABRT），留下"只有公钥、没有私钥"的半成品状态，可致加密文件永久无法解密 |
| **M-1** | 中 | 签名块可被整体剥离，解密降级为"无签名，跳过验证"且成功输出 | 无法依赖"文件是否被签名"作为判断依据，无强制签名策略 |
| **M-2** | 中 | 两处解析器缺陷导致 panic/abort（nonce 长度未校验；ct_len 整数溢出） | 恶意构造的密钥备份或 `.pubenc` 文件可使程序中止（DoS），发布配置 `panic=abort` 放大了后果 |
| **M-3** | 中 | AAD 以明文存储于 blob，泄漏元数据 | 密文文件泄漏原始文件名与签名者公钥；加密私钥备份泄漏用户姓名与邮箱 |
| **M-4** | 中 | 输出写入不防覆盖、不防符号链接、不收紧既有文件权限 | 可静默覆盖已有文件（数据丢失）；明文可能被写入 0644 权限的既有文件；符号链接会被跟随写入 |
| **M-5** | 中 | 依赖供应链门禁实际失效 | `Cargo.lock` 未入库（构建不可复现）；`Cargo-deny.toml` 文件名与 schema 双重失效，从未真正生效；CI 无依赖审计；lockfile 中 `rand 0.8.5` 命中 RUSTSEC-2026-0097 |
| L-1 ~ L-6 | 低 | X25519 未做全零共享密钥检查、Argon2 上限过宽、零化缺口、AAD 超长截断、解密路径不锁内存、全文件读入内存 | 见 §3.7 |
| I-1 ~ I-2 | 提示 | 解析器容忍尾随字节/未知 flag、Argon2 工作内存未擦除、文档与实现不符 | 见 §3.8、§5 |

---

## 1. 审计范围与方法

**做过的验证：**

1. **全量源码通读**：`main.rs` / `cli.rs` / `crypto.rs` / `file_ops.rs` / `keystore.rs` / `workflow.rs` / `password.rs` / `utils.rs` / `constants.rs` / `error.rs`，以及 `Cargo.toml`、`Cargo.lock`、CI 配置、Makefile、pre-commit、README 双语版、项目技能文件。
2. **构建与静态检查**：`cargo build`（debug/release 均通过）、`cargo test`（**28/28 通过**）、`cargo clippy --all-targets --all-features -- -D warnings`（**零告警**）。Release 产物约 641 KiB（已 strip、LTO、panic=abort）。
3. **端到端黑盒实测**（隔离 Linux VM，对 release 二进制执行，共 20 项）：完整加密/解密往返（有签名/无签名）、密文篡改、签名剥离、**公钥伪造 PoC**、损坏输入（垃圾数据、超长/畸形长度字段）、错误口令、空文件、含 `|`/空格/中文文件名、文件权限与符号链接行为、默认 memlock 下崩溃复现与数据丢失链复现、32MB 大文件内存占用。全部日志见 `security-audit-2026-10-18/evidence/`。
4. **依赖审计**：cargo-deny 0.20.2 + RustSec 数据库（2026-10-18 拉取）。被审 `Cargo.lock` 指纹 `sha256:826b7abd62f04be42238e853ac68d4c9…`。
5. **独立复核**：第二审计员在独立环境中对全部 10 条主要结论做对抗性验证（全部确认），并独立扫描发现补充问题（见 §3.7 L-2/L-3/L-4/L-5 中标注"复核补充"的条目）。

**范围与限制：** 未做形式化验证；未覆盖 Windows；未审计 crates.io 已发布包与 GitHub Release 二进制供应链；环境相关行为（如 H-2）已标注典型系统配置下的推演。作为安全产品，正式 1.0 发布前建议再做一次第三方专业密码学审计。

---

## 2. 做得好的地方

作为平衡，以下方面经审查与实测确认可靠，值得保持：

- **原语选型正确且参数合理**：XChaCha20-Poly1305（24 字节随机 nonce）、HKDF-SHA256（RFC 5869）、X25519 ECDH（每文件临时密钥）、Ed25519、Argon2id（64 MiB / t=2 默认值处于当代合理区间）；两类 blob 的 magic（`SGPGv1` / `SCFv1`）互不混淆。
- **"先验签、后落盘"不变量成立**：实测篡改密文一个字节后，解密以统一错误信息 "Decryption failed — wrong password or file tampered" 失败、退出码 1、**未写出任何输出文件**；AEAD 失败信息不区分"口令错"与"被篡改"，不留 oracle。
- **密钥落盘权限正确**：新文件一律 `0600`、keystore 目录 `0700`（实测确认）；签名/密钥材料的 zeroize 覆盖了主路径；`ed25519-dalek`、`x25519-dalek` 的 `zeroize` 特性经 `cargo tree` 确认启用（drop 自动清零）。
- **解析器负面路径有单元测试**（28 个用例覆盖了坏 magic、截断、参数上限等），错误全部走 `Result`（除 §3.6 所列两处）。
- **工程细节有意识**：release 采用 `panic=abort` + LTO + strip；CI 覆盖 fmt/clippy/build/test 与三平台产物；发布流程包含 SHA-256 校验和与 **Sigstore 签名**（意识优于多数同类项目，执行细节见 §4）。
- **密码生成无模偏差**：拒绝采样实现正确（`256 / 69 * 69 = 207` 拒绝阈值，69 字符集，默认 32 位 ≈ 192 bit 熵）。

---

## 3. 安全发现详述

### 3.1 【H-1｜高】签名验证无信任锚：知道公钥的任何人都能伪造"已验证"文件

**位置**：`src/workflow.rs:233-242`（`cmd_decrypt_workflow`）；关联 `src/file_ops.rs:57-64`、`src/cli.rs`（`decrypt` 无签名者参数）。

**问题**：解密时，Ed25519 验签所用的公钥（`verifying_key`）直接取自被解密文件自身携带的 `vk` 字段，**没有任何比对环节**——不比对预期指纹、不查询 keystore、不提供 `--signer` 之类参数，连"本次验签用的是谁的公钥"都不会打印给用户。

由于 `SCFv1` 格式的文件本来就是"任何人拿收件人 X25519 公钥即可加密"，攻击者完全可以：用受害者**公开**的 X25519 公钥做一次正常的 ECDH，用自己新生成的 Ed25519 密钥签名，把 `vk+sig` 塞进文件——受害者解密时 AEAD 通过、签名"验证成功"、明文照常写入。

**实测证据**（`evidence/t6.log`，攻击者从未接触受害者私钥或口令）：

```
$ python3 poc/poc_forge.py keystore/x25519_public_<FP>.asc forged.pubenc "FORGED CONTENT: attacker payload"
[forge] wrote forged.pubenc: 382 bytes; attacker vk=931f72c4b671a468...
$ yacrypt decrypt forged.pubenc --private-key keystore/x25519_private_<FP>.asc.enc
✅ Private key decrypted
✅ File signature verified successfully      ← 对攻击者伪造的内容
✅ Complete decryption workflow finished!
$ cat forged
FORGED CONTENT: attacker payload
```

**影响**：对任何依赖"✅ File signature verified successfully"来相信文件来源/完整性的用户，这是**真实性与来源认证的完全失效**（CWE-345）。AEAD 层面的机密性与内容完整性未被突破（攻击者无法读取或改动他人文件），被破坏的是产品承诺的"数字签名"安全属性本身。注意：即使在正常自用流程（加密给自己）中，被验签的公钥也只是"加密者自己的公钥"，签名在本工具的产品化用法里没有任何能锚定到第三方的路径。

**修复方向**（任选其一并配套文案修正）：
1. `decrypt` 增加 `--signer-fingerprint <64位hex>`（必填或可选），验签通过后再比对 `SHA256(vk)`；自用流程可默认与私钥 blob AAD 中记录的指纹交叉比对。
2. 无法比对时，输出改为明确的"签名自洽但**不可信**（未指定预期签名者）"，并同步修正 README 中"签名"相关表述。
3. 无论哪种方案，都应在验签成功时打印签名者指纹，供用户带外核对。

### 3.2 【H-2｜高】Linux 默认 memlock 配置下主流程崩溃 + 半成品密钥导致不可恢复数据

**位置**：`src/utils.rs:8-24`（`try_mlockall`，使用 `MCL_CURRENT | MCL_FUTURE`）；`src/keystore.rs:40-209`（`generate_and_store_keys` 的调用时机与写盘顺序）。

**问题（机制）**：`mlockall(MCL_CURRENT | MCL_FUTURE)` 的效果是"把当前及**未来所有**内存分配锁定在 `RLIMIT_MEMLOCK` 限额之内"。当限额为有限值 F 且满足"进程当前 RSS < F < RSS + 64MiB"时：`mlockall` **静默成功**（不打印任何警告），随后 Argon2id 默认 64 MiB 工作内存的分配因超出剩余额度而 **ENOMEM 失败**，Rust 分配失败直接 `abort()`。

本审计环境（memlock = 8 MiB，Ubuntu 桌面常见默认区间 8–64 MiB）实测复现，并用 15 行 C 复现文件（`poc/ml_repro.c`，`evidence/mlockall-mechanism-repro.txt`）锁定因果链：

```
mlockall(MCL_CURRENT|MCL_FUTURE) rc=0 (errno=0)      ← 静默成功
malloc(64 MiB) -> NULL (failed) (errno=12)           ← Argon2 所需分配失败
----------- lowered memlock (256 KiB): --------------
mlockall(MCL_CURRENT|MCL_FUTURE) rc=-1 (errno=12)    ← 失败反而无害
malloc(64 MiB) -> OK (errno=0)
```

在真实二进制上（`evidence/t19.log`）：

```
✅ Backup password generated:
   fBacdcZiBqL0CVNclgBYVbk3GOb40gjJVdYZ6vk5iwYLgmpyWlWZi9vCcPrFjamx
memory allocation of 67108864 bytes failed
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
Aborted                                            ← SIGABRT / 退出码 134
```

**问题（后果链）**：`generate_and_store_keys` 的写盘顺序是"先写两个公钥文件 → 再提示口令 → 再派生 Argon2 密钥并加密私钥"。崩溃点恰好落在公钥已落盘、私钥未落盘之间，于是 `keystore/` 留下**孤儿公钥**（无对应私钥、无恢复说明）。实测继续利用该公钥加密一个文件后（`evidence/t20 段`）：

```
$ yacrypt encrypt-file-with-key --input f3.txt --public-key <孤儿公钥>
✅ File encrypted with public key: f3.pubenc
$ yacrypt decrypt f3.pubenc --private-key keystore/x25519_private_<FP>.asc.enc
Error: "Private key file not found: ..."           ← 该文件永久无法解密
```

**触发条件与影响面**：Linux 上 memlock 为任意"有限且大于进程启动 RSS"的配置（典型默认 8 MiB / 64 MiB 均落入区间）→ `gen-keypair` 与推荐流程 `encrypt` **必崩**。仅在 memlock 为 unlimited（部分发行版/root）时正常；memlock 极小（mlockall 直接失败）时反而正常（打印警告后继续，实测 256 KiB 情形全流程通过）；macOS 分支为空操作，不受影响——这解释了为何项目 CI（只跑 256 KiB 参数的单元测试、且从不调用 mlockall）与本地 macOS 开发都未发现该问题。

**修复方向**：
1. 去掉 `MCL_FUTURE`（仅 `MCL_CURRENT`），或整个移除 mlockall 改用对关键缓冲区的定向 `mlock`；无论如何不要把"未来全部分配"置于 memlock 限额之下。
2. 调整写盘顺序与原子性：先完成全部密钥派生与加密（含 Argon2），全部成功后再一次性写盘（临时目录 + 原子重命名），杜绝中间态。
3. 崩溃绝不应留下可用（但实际不可用）的公钥；至少应在恢复说明与公钥文件名上带状态标记。
4. CI 增加一条 Linux 端到端冒烟测试（gen-keypair → encrypt → decrypt 往返），可直接抓住此问题。

### 3.3 【M-1｜中】签名剥离降级：可去掉签名块，解密静默"跳过验证"

**位置**：`src/crypto.rs:244-273`（打包）与 `src/crypto.rs:276-361`（解析）；`src/workflow.rs:233-248`（验签分支）。

**问题**：`flags` 字节与 96 字节的 `vk+sig` 数据块**不在 AAD 覆盖范围内**（AAD 里只有 `sig_vk=<hex>` 字符串，而工具从不比对它与 flags 的一致性）。攻击者删掉签名块、把 flags 置 0，文件其余部分不动——AEAD 校验依然通过（AAD 原文未变），解密照常输出，只是提示从"签名验证成功"变为"ℹ️ No signature embedded, skipping verification"。

**实测证据**（`evidence/t5.log`）：363 字节的已签名文件被裁成 267 字节后：

```
ℹ️  No signature embedded in encrypted file, skipping verification
✅ Complete decryption workflow finished!          ← 正常解密输出
```

**影响**：签名存在与否可被无条件篡改，且工具没有任何"必须签名"的策略（`--key` 路径本就无签名，`decrypt` 也无 `--require-signature`）。配合 H-1，"签名"体系从存在到验证都不可依赖。

**修复方向**：把 `flags` 字节（及版本号）纳入 AAD（或把签名块哈希纳入 AAD）；校验"flags 与 AAD 中 sig_vk 的一致性"（不一致即拒绝）；提供 `--require-signature` 或 `--signer` 强制策略。

### 3.4 【M-2｜中】两处畸形输入导致 panic / abort

**位置**：
- (a) `src/crypto.rs:143-148`（解析时接受任意 `nonce_len`）→ `src/crypto.rs:209` 附近 `XNonce::from_slice(nonce)` 在长度 ≠ 24 时 panic；
- (b) `src/crypto.rs:355` `idx + ct_len`（`ct_len` 来自文件、u64）溢出，`src/crypto.rs:358` 切片越界 panic；`src/crypto.rs:179-182` 同一模式。

**实测证据**（release 二进制，`evidence/t7.log`、`t8.log`）：

```
(a) thread 'main' panicked at .../generic-array-0.14.7/src/lib.rs:572:
      left: 23   right: 24                       → SIGABRT（退出信号 6）
(b) thread 'main' panicked at src/crypto.rs:358:
      slice index starts at 72 but ends at 71     → SIGABRT（退出信号 6）
```

由于 release 配置 `panic = "abort"`，两处都表现为直接中止（非正常报错退出）。触发路径面向攻击者可控输入：伪造的"加密私钥备份"文件（`decrypt-private-key` / `decrypt --private-key`）与伪造的 `.pubenc` 文件。Rust 内存安全未被破坏，属拒绝服务与健壮性缺陷（CWE-20），但对一个安全工具而言"喂恶意文件即崩溃"不可接受。

**修复方向**：解析层显式校验 `nonce_len == 24`；所有"索引 + 长度"改用 `checked_add` 或 `data.get(start..end)` 模式；为两个解析函数配置 `cargo-fuzz` 模糊测试靶子并纳入 CI 冒烟。

### 3.5 【M-3｜中】AAD 明文存储，泄漏元数据

**位置**：`src/crypto.rs:84-86`、`265-267`（AAD 原样写入 blob）；`src/file_ops.rs:85-101`（pubenc 的 AAD 含文件名）；`src/keystore.rs:123-124`、`143-144`（私钥备份的 AAD 含姓名/邮箱/指纹）。

AAD 只提供完整性，不提供保密性——这是 AEAD 的基本性质，但本实现把**敏感元数据放进了明文 AAD**。实测（`evidence/aad-cleartext-leak.txt`）：

```
$ strings f2.pubenc
file=f2.txt|ephemeral_pub=de0673…|sig_vk=11bc7e…     ← 原始文件名 + 签名者公钥全部明文可读

$ strings keystore/private_<FP>.asc.enc
name=Alice|email=alice@example.com|fp=5D5559…        ← 加密私钥的备份文件中
                                                        姓名与邮箱明文可读
```

**影响**：加密文件泄漏原始文件名（隐私/关联分析）；签名者公钥在密文层可全局关联；**加密私钥的备份文件（本应最敏感）泄漏用户姓名与邮箱**——即"把加密备份发给别人保管"这一常见场景下，元数据先于内容泄漏。

**修复方向**：元数据移入密文载荷（AEAD 的 msg 部分）而非 AAD；AAD 仅保留格式常量或哈希值；属格式变更，建议借 `v2` magic 版本升级并写明迁移说明。

### 3.6 【M-4｜中】输出文件写入语义不安全：可覆盖、可跟随符号链接、既有权限不收紧

**位置**：`src/utils.rs:31-40`（`write_file_strict`）；所有调用点（加密输出、解密输出、密钥与说明文件）。

**问题**：`OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)`——
1. **无 `create_new`**：静默覆盖任何已存在的同名文件（无 `--force` 保护），加密时可能覆盖旧的（甚至旧密钥加密的）密文；解密时可覆盖用户原文件。
2. **`mode(0o600)` 仅在创建时生效**：覆盖一个既有的 0644 文件后，其权限**保持 0644**——解密出的明文会进入一个同组/其他用户可读的文件。
3. **无 `O_NOFOLLOW`**：输出路径是符号链接时按链接目标写入，目标文件被替换。

**实测证据**（`evidence/` 对应日志）：

```
[0644 的既有文件] decrypt … --output dec_target → 写入明文后权限仍为 644
[符号链接]       encrypt … --output link_out.bin（→real_out.bin）
                 → real_out.bin 内容被替换为 "SCFv1…" blob（链接被跟随）
```

**修复方向**：默认 `create_new(true)`（存在即报错，提供显式 `--force`/`--overwrite` 才允许截断）；`custom_flags(libc::O_NOFOLLOW)`；创建/打开后对文件描述符 `fchmod(0o600)` 兜底；写入前检查目标不是目录。

### 3.7 【L 级｜低】其余安全发现

| 编号 | 位置 | 说明 |
|------|------|------|
| L-1 | `src/file_ops.rs:69-73`、`src/workflow.rs:210` | X25519 共享密钥未做全零（低阶点）检查（未调用 `was_contributory()`）。对本场景（公钥加密天然对任何知道公钥者"可伪造"）直接影响有限，见 H-1；但作为密码学卫生与未来协议演进（双向交换/握手）必须补齐，一行修复。 |
| L-2 | `src/constants.rs:13-15`、`src/crypto.rs:18-43` | Argon2 上限（4 GiB × t=100）仍过宽：恶意 blob 可强制巨大内存/算力（"prevents OOM"注释过度承诺）；建议收紧（如 ≤ 256 MiB、t ≤ 16）并单独记录"自身生成参数的合理下限"。 |
| L-3 | `src/keystore.rs:256-268` 等 | 零化缺口：`cmd_decrypt_backup` 导出的私钥明文未 zeroize；部分错误路径（写盘失败、prompt 失败）会直接 drop 敏感数据；`password.rs` 中 `password_str` 克隆未清零；`dialoguer` 内部口令缓冲不可控（属于库限制，文档注明）。 |
| L-4 | `src/crypto.rs:84` `aad.len() as u16` | 当 AAD 超过 65,535 字节（如超长 name/email 参数）时长度字段被静默截断，写出**自身解析器无法读取**的私钥备份（密钥仍在 blob 里但官方工具解不开，需人工修复长度字段）。建议直接拒绝超长输入。 |
| L-5 | `src/keystore.rs:232-277` | `decrypt-private-key` 无载荷类型校验：X25519 私钥 blob（AAD 中 `type=x25519` 标记从未被读取）也能被导出成 `.der` 并提示成功。建议校验 AAD 标记。 |
| L-6 | `src/utils.rs:8` 调用点、全体 I/O | `try_mlockall` 只在密钥生成路径调用——**解密流程**（恰是长期私钥与明文同时驻留内存的进程）完全不锁内存；且全部加解密为"整文件读入内存"（32 MB 输入实测峰值 RSS ≈ 98 MB，约 3 倍膨胀）。大文件场景建议流式（分块 AEAD）并评估内存上限。 |

### 3.8 【I 级｜提示】

- 解析器容忍密文后的尾随字节、忽略未知 flags 高位——建议拒绝非精确消费，为未来版本扩展留严格性。
- Argon2id 的 64 MiB 工作内存由库分配、用后释放但不擦除（`argon2` crate 未启用/无相应 zeroize 能力）；属纵深防御项，可在文档中如实说明。
- `Cargo.toml` 描述与 `--help` 文案宣称 "using Rust + libsodium"——实际未使用 libsodium（纯 Rust RustCrypto 栈），对外发布前必须修正（元数据不实对安全产品是信任问题）。

---

## 4. 依赖与供应链审计（M-5 详情）

**结论：项目的"供应链安全门禁"整体处于失效状态，且 lockfile 中确有 1 条未修复预警。**

### 4.1 Cargo.lock 未纳入版本控制

`.gitignore` 第 3 行忽略了 `Cargo.lock`（`git ls-files` 确认未跟踪）。对**二进制应用**这是反模式：不同时间/机器构建出不同依赖版本，发布产物不可复现，安全审计无固定基线；配合 CI 中缺失的 `--locked`，每次发布实际都在"随缘"解析依赖。修复：`git add Cargo.lock` 并移出 `.gitignore`，CI/发布统一 `--locked`。

### 4.2 cargo-deny 配置"三重失效"

- **文件名错**：仓库中的 `Cargo-deny.toml` 不会被自动发现（cargo-deny 只认 `deny.toml`）。实测 `cargo deny check` 输出 `[WARN] unable to find a config path, falling back to default config`——即作者预期的策略（licenses 白名单、sources deny 等）**从未生效过**；回退默认配置后甚至会因许可证策略大面积误报。
- **schema 过期**：显式 `--config Cargo-deny.toml` 时，cargo-deny 0.20.2 直接解析失败：`unmaintained = "warn"` 取值非法、`ignore-fixes` 为不存在字段、`[bans] highlight` 类型错误——说明该配置写于早期版本、从未针对当前版本跑通。
- **无效忽略项**：`ignore-fixes` 中想忽略的 `RUSTSEC-2020-0001` 实为 **trust-dns-server**（CVE-2020-35857）的漏洞，与本项目依赖树毫无关系（cargo-deny 报 `advisory was not detected`），属从其他项目复制残留。

### 4.3 依赖树中的真实预警：rand 0.8.5

用"意图等价"配置跑出的完整结果（`deny/3-fixed-config-results.txt`）：

```
error[unsound]: Rand is unsound with a custom logger using `rand::rng()`
  ID: RUSTSEC-2026-0097   rand v0.8.5
  仅当 log + thread_rng 特性启用、且存在访问 rand::rng() 的自定义 logger 时触发
  Solution: Upgrade to >=0.8.6
advisories FAILED   bans ok, licenses ok, sources ok
```

**实际影响评估（低）**：本项目依赖树中不存在 `log` crate、代码未使用 `thread_rng`，触发条件不成立；且由于 4.1（lock 未入库），全新解析构建实际上会拿到 0.8.6+ 修复版。但从"发布基线"的角度：**当前 lockfile 会带着这条预警过审计**，应立即 `cargo update -p rand` 并提交 lock。其余依赖（curve25519-dalek 4.1.3、chacha20poly1305 0.10.1、argon2 0.5.3、ed25519-dalek 2.2.0、x25519-dalek 2.0.1、zeroize 1.8.2 等）均为当前健康版本，无已知漏洞。

### 4.4 CI / 发布流程

- CI（`.github/workflows/cicd.yml`）仅运行 fmt/clippy/build/test，**没有** cargo-audit/cargo-deny 步骤；`.pre-commit-config.yaml` 中 audit 钩子被注释；audit/deny 只存在于手动 Makefile 目标与本地脚本——即"门禁"全靠人记得去拉。
- 发布构建 `cargo build --release --target …` 未带 `--locked`（叠加 4.1，产物不可复现）。
- Sigstore 签名步骤 `... || echo "Failed to sign $f, continuing..."` **吞掉签名失败**——安全产品的发布流水线不应允许"签名与否都发布"静默通过；建议失败即终止并给产物打不可用标记。
- 修复清单：lock 入库 → deny.toml 改名并重写为 0.20 schema（配套最小示例见附录 B）→ 钉住 cargo-deny 版本 → CI 增加 `check advisories licenses bans sources` 与 `--locked` 构建。

---

## 5. 产品与工程视角

### 5.1 核心功能命题需要重新审视：签名子系统

当前 CLI 里**不存在**"A 用自己的 Ed25519 身份给发给 B 的文件签名、B 能验证是 A 签的"这条链路：`encrypt` 整流程生成新密钥对并加密给**自己**；`encrypt --key` 明确不签名。于是 Ed25519 签名在所有真实用法中要么验证者=签名者（无意义），要么可被任意伪造（H-1 已复现）。**建议二选一**：

1. **补齐为真功能**：增加"加密给收件人 + 用发送者身份签名"的流程，`decrypt` 强制/可选 `--signer <指纹>`，验签后展示并比对签名者身份指纹；配套密钥分发指引与威胁模型文档。
2. **砍掉签名**：删除签名相关代码与宣发口径（README"与密文密码学绑定"等表述），把定位收敛为"加密+完整性"工具（AEAD 本身保证）。

无论哪条路，README 中"Ed25519 签名嵌入加密文件内部，与密文密码学绑定"应改为与实现一致的表述（签名只覆盖明文、经 AAD 绑定签名者公钥，见 §3.3/§3.5）。

### 5.2 可用性与体验

- **H-2 是当前最刺眼的体验问题**：Linux 用户第一次运行 `gen-keypair`/`encrypt` 就崩溃，且崩溃前刚打印了"请保存好这个密码"——用户会保存一个无用的密码并可能继续用孤儿公钥加密数据。
- **输出命名与文档不符**：默认输出把扩展名**替换**而非追加（`secret.txt → secret.pubenc`），而 README 示例写的是 `secret.txt.pubenc`；解密 `foo.pubenc` 得到的是去掉扩展名的 `foo`，无法恢复原文件名（原文件名就在 AAD 里却没有被使用来命名输出，反而作为元数据泄漏了——两处应一起改）。
- **README 存在幽灵命令**：第 6 节文档化了 `decrypt-file-with-key` 子命令，实际 CLI 中不存在（历史已删除，文档未同步）；快速开始示例展示"输入自定义口令"流程，与实际的"自动生成密码（默认回车）"提示不符。
- **keystore 使用相对路径 `./keystore`**：在哪个目录运行就在哪里新建密钥库，容易产生"密钥去哪了"的困惑；恢复说明里保存的也是相对路径。建议提供全局 keystore 路径（如 `~/.yacrypt/`）或显式 `--keystore`，并在说明中固化绝对路径。
- 其余小项：`--help` 文案含 libsodium 误述（§3.8）；错误信息为英文（与中文为主的 UI 文案混合）；`email` 默认值 `secure@example.com` 会进入 AAD 与恢复说明，属噪音。

### 5.3 功能缺口（产品路线图）

密钥管理基本为零：没有 `list-keys`/`import`/`export`/`rotate`/`revoke`/`change-password`；无多收件人加密；无流式/分块大文件支持（L-6）；无 `--quiet`/机器可读输出；无 Windows 目标（README 已如实声明 Linux/macOS）。每次 `encrypt` 生成新密钥对并堆积 keystore 文件的设计对普通用户不友好，建议默认使用已有密钥、显式 `--new-key` 才新建。

### 5.4 工程质量

测试结构良好（28 个单元测试覆盖解析器与加密负面路径，clippy `-D warnings` 干净），但 `tests/` 目录为空——**没有一条真正的端到端/集成测试**，这正是 H-2 与 M-2 得以存活的直接原因；建议：3 条 e2e 冒烟（往返、篡改拒绝、畸形输入不崩溃）+ `cargo-fuzz` 两个解析器靶子 + CI 挂载。文档侧建议补齐：格式规范（FORMAT.md，含测试向量）、威胁模型（谁防谁、防止什么、不防什么）、SECURITY.md（漏洞报告渠道）。发布工具链（cliff/changelog、Sigstore、校验和）基础不错，修好 §4 的细节后可作为亮点。

### 5.5 修复优先级路线图

| 优先级 | 项 | 说明 |
|--------|----|------|
| **P0（发布阻断）** | H-2 | 移除/降级 `MCL_FUTURE`；密钥写盘原子化；CI 加 Linux e2e 冒烟 |
| **P0** | H-1 | 引入预期签名者指纹（`--signer` 或 keystore 交叉校验）；修正签名相关文案 |
| **P0** | M-5 | 提交 Cargo.lock；重写 deny.toml 并接入 CI；`cargo update -p rand`；发布构建 `--locked` |
| **P0** | M-2 | 校验 nonce 长度、checked 长度运算；补畸形输入回归测试 |
| **P1（1.0 之前）** | M-1 / M-3 / M-4 | flags 入 AAD + 强制签名选项；元数据移入密文（v2 格式）；写入语义（`create_new`/`O_NOFOLLOW`/`fchmod`/`--force`） |
| **P1** | 文档与体验 | README 修正（幽灵命令、输出命名、密码流程、签名表述）；威胁模型/SECURITY.md；keystore 路径策略 |
| **P2（持续）** | L-1 ~ L-6、fuzz、流式、密钥管理功能、第三方审计 | 按 §5.3/§5.4 推进；1.0 前完成一次外部密码学审计 |

---

## 6. 结论

YaCrypt 的密码学"地基"是好的：原语选择正确、主路径的失败处理克制、密钥落盘权限与主路径零化纪律都在水准之上；28 个单元测试与干净的 clippy 也说明作者有能力把这个项目做好。真正的问题集中在**三个层面**：一是"签名"这一核心卖点目前没有信任模型支撑（H-1，且可被整体剥离 M-1），需要产品层面重新设计或如实降级；二是 Linux 上 mlockall 的误用使主流程在常见配置下崩溃并制造不可恢复的数据风险（H-2），这是纯工程问题、修复路径清晰；三是供应链门禁从未真正生效（M-5）。**修复 P0 四项后可以进入 beta；补齐 P1 并完成一次外部审计后再打 1.0 标签是合适的节奏。** 当前版本号 0.0.1 是诚实的——保持这个诚实，把 README 里的过度承诺也一并改掉。

---

## 附录 A：关键实测环境与复现方法

**环境**：Ubuntu 22.04 (aarch64) 隔离 VM；rustc 1.99.1；PyNaCl 1.6.2；cargo-deny 0.20.2；release 二进制 SHA-256 见 `evidence/version-info.txt`；RLIMIT_MEMLOCK = 8 MiB（典型默认值区间）。

**复现入口**（详见 `security-audit-2026-10-18/`）：

```bash
# 1) 伪造"签名验证通过"的文件（仅需受害者公钥）
python3 poc/poc_forge.py keystore/x25519_public_<FP>.asc forged.pubenc "payload"
yacrypt decrypt forged.pubenc --private-key keystore/x25519_private_<FP>.asc.enc
#    → "✅ File signature verified successfully"（见 evidence/t6.log）

# 2) 签名剥离降级
python3 poc/poc_strip.py signed.pubenc stripped.pubenc
#    → 解密成功且提示 "No signature embedded … skipping"（见 evidence/t5.log）

# 3) mlockall 机制复现（C）
cc -O0 poc/ml_repro.c -o ml_repro && ./ml_repro        # 默认 memlock: rc=0 后 malloc 64MiB 失败
bash -c 'ulimit -Sl 256; ./ml_repro'                   # 降低后: mlockall 失败、分配正常

# 4) 端到端测试套件（含 20 项用例）
bash harness/suite-a.sh && bash harness/suite-b.sh
```

**修复参考（cargo-deny 0.20 最小可用配置）**：

```toml
# deny.toml（注意文件名）
[advisories]
unmaintained = "workspace"
ignore = []          # 不要保留与依赖树无关的条目
[licenses]
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Zlib", "Unicode-3.0"]
[bans]
multiple-versions = "allow"
[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

## 附录 B：证据清单（`security-audit-2026-10-18/`）

| 路径 | 内容 |
|------|------|
| `poc/poc_forge.py` | H-1 公钥伪造 PoC（仅用受害者公钥，生成"验签通过"文件） |
| `poc/poc_strip.py` | M-1 签名剥离 PoC |
| `poc/ml_repro.c` | H-2 mlockall/MCL_FUTURE 机制 C 复现 |
| `harness/drive.py`、`suite-a.sh`、`suite-b.sh` | 20 项端到端实测套件（pexpect 驱动） |
| `evidence/t1–t19.log` | 各用例完整日志（含 t6 伪造、t7/t8 panic、t19 崩溃） |
| `evidence/crash 早期日志` | 首次发现崩溃的原始日志（suite1-crash-logs） |
| `evidence/aad-cleartext-leak.txt` | AAD 明文泄漏的 strings 输出 |
| `evidence/mlockall-mechanism-repro.txt` | C 复现输出 |
| `evidence/version-info.txt` | 被审版本、Cargo.lock 与二进制哈希 |
| `deny/1–3-*.txt` | cargo-deny 三组输出（默认配置/原配置/修正配置） |

## 附录 C：免责声明

本报告基于对上述版本的静态审查与黑盒实测，不构成形式化安全证明或法律意见；环境相关行为已尽可能标注触发条件。作为计划对外发布的密码学产品，建议在 1.0 前委托独立第三方进行完整审计（尤其是自定义文件格式与协议设计）。
