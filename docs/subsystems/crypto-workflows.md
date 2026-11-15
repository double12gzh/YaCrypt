# 密码学与工作流

## 职责和入口

[crypto.rs](../../crates/yacrypt-core/src/crypto.rs) 提供 KDF、AEAD 和容器打包/解析；
[constants.rs](../../crates/yacrypt-core/src/constants.rs) 是格式及参数边界的来源。
[file_ops.rs](../../crates/yacrypt-core/src/file_ops.rs) 处理文件加密及对称解密；
[workflow.rs](../../crates/yacrypt-core/src/workflow.rs) 组合密钥、信任锚、验签和输出。
终端交互由 CLI/TUI 负责，core API 接收数据和路径。

## 运行路径与约束

- SGPGv2（新加密默认）与 SGPGv1（私钥备份与遗留文件）：Argon2id 派生密钥，再用 XChaCha20-Poly1305；解析与派生检查参数边界。
  - 纯口令对称文件加密默认输出 `SGPGv2`：AAD 为 `type=file|v=2`，并在 AEAD 加密前套用长度混淆填充（`inner_version(1B=0x02) + plaintext_len(8B BE) + raw_plaintext + OsRng 随机填充`，结合最小底线 1024B、随机抖动与 Padmé 对齐），隐藏原文件精确字节数；
  - `decrypt_file_symmetric` 兼容解密 `SGPGv2`（校验 `type=file` 且 `v=2` 后解填充）与遗留 `SGPGv1`（仅 `type=file`，无填充）；私钥备份维持 `SGPGv1`（`type=ed25519` / `type=x25519`）。对称 `SGPGv1`/`SGPGv2` 无内嵌签名，若调用方开启签名要求（`--require-signature`）或指定 `--signer` 则在提示口令前立即拒绝。
- SCFv2（新公钥加密默认）与 SCFv1（遗留文件）：每文件临时 X25519 密钥 → 共享秘密 → HKDF → AEAD；
  - 新生成 `.pubenc` 默认使用 `SCFv2`：外层仅含 `MAGIC("SCFv2") + flags(1B=0x00) + ephemeral_pub(32B) + nonce(24B) + AAD("v=2|ephemeral_pub=...") + ct_len + ciphertext`（不暴露 `sig_vk`、签名者指纹或是否签名）；HKDF 绑定接收方公钥 `recipient_pub`；
  - Ed25519 签名默认开启且转移至 AEAD 密文内层（Sign-then-Encrypt），签名为绑定 `ephemeral_pub || recipient_pub || SHA256(plaintext)` 的固定长度转录本（防跨文件/跨接收者签名移植与剥离），内层载荷同步执行随机抖动 + Padmé 长度混淆填充，彻底阻止无接收者私钥的已知完整原文件离线签名比对并隐藏精确字节数；
  - 默认加密输出统一为输入文件同目录下的随机匿名文件名（`<16位小写hex>.pubenc` / `<16位小写hex>.enc`），绝不沿用原文件名或扩展名；显式传入 `--output` 时按调用方路径落盘；解密 `default_decrypt_output_path` 剥离 `.pubenc` / `.enc`（非匹配后缀追加 `.decrypted`）。
  - `preflight_validate_recipient_pubkey` 拦截误传 Ed25519 `public_<FP>.asc`（及重命名副本）、
    未导入的合并公钥包与 L-1 低阶点。
  - `decrypt_workflow_with_password_in_dir` 同时支持 `SCFv2` 与遗留 `SCFv1`：读取 X25519 私钥备份、认证解密内容，分别通过 `verify_pubenc_v2_signature` / `verify_pubenc_aad_and_signature` 校验 Ed25519 签名与信任锚后才写明文；共享秘密必须具有贡献性。
- 签名信任锚优先使用显式 `signer`（支持完整 64 位 hex 指纹、当前有效本地密钥环别名或 `public_<FP>.asc`，
  拒绝短 hex 前缀、孤立残留别名、未导入公钥包与 `x25519_public_*.asc`），否则取私钥备份身份指纹。
  有签名时校验签名及信任锚；无签名时仅在未要求签名且 AAD 没有剥离迹象时接受。
- `inspect_file` 与 `inspect_pubenc_file` 通过 `O_NONBLOCK` 仅打开普通文件，流式只读容器头部与 `aad_len`，
  支持 `SCFv1`、`SCFv2`、`SGPGv1` 与 `SGPGv2`：校验头部与 AAD 一致性（含 `SCFv1` M-1 签名剥离检测及 `SCFv2` `flags=0x00`/禁用外层签名字段检测），结合文件长度核算 `ciphertext_len` 并校验截断/尾随字节，
  不读取密文体亦不验证内容真实性；对于 `SCFv2`，外层透视显示签名已随密文内层隐藏（`has_signature = None`），输出的遗留 `SCFv1` 签名指纹亦非信任证明。
- 伴生 `.decrypt.txt` 默认**不生成**（`write_instructions = false`，防止误随密文发出导致密钥指纹与文件名关联泄露）；仅当显式开启 `write_instructions = true`（CLI `--instructions` 或 TUI 取消勾选跳过）时才追加在密文输出路径后（`<output>.decrypt.txt`），且内容仅含 `file_name()`。
- 错误密码、算法类型误传、同文件 `(dev, ino)` 冲突、篡改、签名/信任锚失败必须在明文写入之前返回错误。

## 兼容性与验证

- **向后兼容**：保留 `SCFv1`（含已签名/无签名 `.pubenc`）与 `SGPGv1`（`type=file` `.enc` 与私钥备份 `.asc.enc`）的免密 `inspect_file` 与完整解密/验签路径；私钥备份 (`ed25519`/`x25519`) 仍保持 `SGPGv1` 且严禁与 `type=file` (`v1`/`v2`) 混用。
- **新密文隐私特性**：新加密 `.pubenc` 统一写入 `SCFv2`，新对称 `.enc` 统一写入 `SGPGv2`，默认隐藏签名存在性/指纹/可验证签名数据与原文件精确字节数；注意 `SCFv2` / `SGPGv2` 无法被未升级的旧版 YaCrypt 读取。
- **验证覆盖**：crypto 单测覆盖 Padmé/随机长度混淆填充、参数边界、截断、尾随字节、篡改及 `SCFv2`/`SGPGv2` 打包解包；workflow / file_ops / keystore 测试覆盖算法防呆、内层签名防移植/信任锚、遗留 `v1` 兼容、流式透视与域隔离；[CLI E2E](../../tests/cli_e2e.rs) 检查端到端 PTY 与攻击回归。完整命令见 [验证](../verification.md)。
- 这些测试不是密码学安全证明；变更加密格式或信任规则需要明确授权与独立审查。
