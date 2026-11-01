# 密码学与工作流

## 职责和入口

[crypto.rs](../../crates/yacrypt-core/src/crypto.rs) 提供 KDF、AEAD 和容器打包/解析；
[constants.rs](../../crates/yacrypt-core/src/constants.rs) 是格式及参数边界的来源。
[file_ops.rs](../../crates/yacrypt-core/src/file_ops.rs) 处理文件加密及对称解密；
[workflow.rs](../../crates/yacrypt-core/src/workflow.rs) 组合密钥、信任锚、验签和输出。
终端交互由 CLI/TUI 负责，core API 接收数据和路径。

## 运行路径与约束

- SGPGv1：Argon2id 派生密钥，再用 XChaCha20-Poly1305；解析与派生检查参数边界。
  AAD 的 `type=file` 与私钥备份的 `ed25519` / `x25519` 区分用途。
- SCFv1：每文件临时 X25519 密钥 → 共享秘密 → HKDF → AEAD，可携带 Ed25519 签名。
  `decrypt_workflow_with_password` 读取 X25519 私钥备份、解密内容，调用
  `verify_pubenc_aad_and_signature` 后才写明文；共享秘密必须具有贡献性。
- 签名信任锚优先使用显式 `signer`，否则取私钥备份身份指纹。
  有签名时校验签名及信任锚；无签名时仅在未要求签名且 AAD 没有剥离迹象时接受。
- `inspect_file` 识别并解析容器元数据，不验证内容真实性；输出的签名指纹不是信任证明。
- 错误密码、篡改、签名/信任锚失败必须在明文写入之前返回错误。

## 兼容性与验证

格式变更必须列出旧文件读取、新文件读取和域隔离影响；不能只验证新版本自我往返。
现有 crypto 单测覆盖参数边界、截断、尾随字节和篡改，workflow 测试覆盖信任与流程；
[CLI E2E](../../tests/cli_e2e.rs) 检查端到端结果。完整命令见 [验证](../verification.md)。
这些测试不是密码学安全证明；变更加密格式或信任规则需要明确授权与独立审查。
