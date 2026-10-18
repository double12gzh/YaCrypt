# AGENTS.md

本文件为所有在此仓库工作的 AI 编程助手（Antigravity / Gemini、Claude Code、Codex / GPT、Cursor 等）提供统一的架构指引、安全红线及工程与 Git 规范。

---

## 1. 项目架构与开发指南

### 1.1 构建、测试与质量门禁命令

```bash
cargo build                              # Debug 构建
cargo build --release                    # Release 构建（opt-level="z", LTO, strip, panic=abort）
cargo test                               # 运行所有单元测试与集成测试
cargo test crypto::tests::               # 仅运行 crypto 模块测试
cargo test <test_name>                   # 运行单个指定测试
cargo clippy --all-targets -- -D warnings # Clippy 静态检查（将警告视为错误）
cargo fmt -- --check                     # 检查代码格式
cargo deny check                         # 依赖许可证与安全漏洞审计
make all                                 # 一键执行 fmt + clippy + test + security + rebuild
```

> **质量门禁**：`pre-commit` 钩子会自动执行 `cargo fmt -- --check`、`cargo clippy -- -D warnings` 和 `cargo test`。任何代码变更在提交前必须确保上述检查全部通过。

### 1.2 模块依赖流

```text
src/main.rs (CLI 路由分发 + try_mlockall 内存锁)
  ├── src/cli.rs        — Clap CLI 参数与子命令定义 (Commands enum)
  ├── src/workflow.rs   — 高层加解密工作流编排
  │     ├── src/file_ops.rs   — X25519 混合公钥文件加密 + Ed25519 签名与验签
  │     └── src/keystore.rs   — 密钥对生成、基于口令的私钥加密存储与恢复
  ├── src/crypto.rs     — 核心密码学原语 (Argon2id + XChaCha20-Poly1305, SGPGv1 格式)
  ├── src/password.rs   — 拒绝采样高熵随机口令生成
  └── src/utils.rs      — 安全 I/O 辅助函数、公钥指纹计算、AAD 转义与解析
```

### 1.3 两种加密模式与数据格式

* **口令加密模式（`SGPGv1` blob）**：
  * **算法**：Argon2id KDF → XChaCha20-Poly1305 AEAD。
  * **用途**：加密保护落盘存储的本地私钥文件。
  * **二进制格式**：`MAGIC("SGPGv1", 6B) + Argon2 params(12B) + salt + nonce + AAD + ciphertext`。
* **公钥混合加密模式（`SCFv1` / `.pubenc` blob）**：
  * **算法**：X25519 ECDH（每文件生成临时密钥对）+ HKDF-SHA256 → XChaCha20-Poly1305 AEAD，内嵌可选的 Ed25519 签名。
  * **用途**：业务文件加密传输与存储，无需保存长期对称加密密钥。
  * **二进制格式**：`MAGIC("SCFv1", 5B) + flags(1B) + [ed25519_vk(32B) + sig(64B)] + ephemeral_pub(32B) + nonce(24B) + AAD + ciphertext`。

### 1.4 密钥生成流

`generate_and_store_keys()` 会同时生成两套密钥对并存入 `keystore/` 目录（目录权限 `0700`）：
* **Ed25519**：用于文件数字签名；私钥经口令加密后落盘，公钥以 Base64 存储。
* **X25519**：用于 ECDH 文件加密；私钥经同一口令加密后落盘，公钥以 Base64 存储。
* **密钥指纹（Fingerprint）**：取 `SHA256(Ed25519 公钥原始字节)` 的大写十六进制字符串。

### 1.5 密码学与安全不变量（Security Invariants，强制遵守）

修改任何涉及加解密、密钥管理或文件 I/O 的代码时，**严禁破坏**以下安全红线：
1. **先验签、后落盘**：解密文件时，Ed25519 签名验证**必须**在向磁盘写入任何明文之前完成；验签失败必须立即中止并拒绝输出任何数据。
2. **敏感数据即时擦除**：所有口令、私钥、派生密钥、共享密钥等敏感材料必须使用 `zeroize::Zeroize`（或 `Zeroizing` 包装器），在使用完毕后立即清零。
3. **最小权限与原子同步**：私钥与敏感输出文件写入必须显式设置权限 `mode(0o600)` 并调用 `sync_all()`，防止 TOCTOU（检查时与使用时）竞态条件或权限泄露。
4. **Argon2 参数硬上限校验**：从外部密文解析 Argon2 参数（内存成本 `m_cost`、迭代次数 `t_cost`、并行度 `p_cost`）时，必须在派生前严格校验硬上限，防止恶意构造的密文头触发 OOM 拒绝服务。
5. **AAD 元数据强绑定**：文件名、时间戳、发送方身份等元数据必须注入 AEAD 的 AAD（Associated Authenticated Data）；任何元数据篡改必须导致 AEAD 解密认证直接失败。
6. **防 Swap 内存锁定**：在 Linux 环境下保持启动时调用 `try_mlockall()`，防止敏感内存页被交换到磁盘。

### 1.6 CLI 子命令入口对照表

| 子命令 | 对应实现函数 | 功能说明 |
| :--- | :--- | :--- |
| `encrypt` | `workflow::cmd_encrypt_workflow` | 完整加密流程：生成密钥对（或通过 `--key` 复用已有公钥）→ 加密文件 → 签名 |
| `decrypt` | `workflow::cmd_decrypt_workflow` | 完整解密流程：口令解密私钥 → 解密文件 → 校验签名 → 安全写入明文 |
| `gen-keypair` | `keystore::cmd_generate_protected_key` | 生成受口令保护的 Ed25519 + X25519 密钥对 |
| `gen-password` | `password::cmd_generate_strong_password` | 基于拒绝采样生成无模偏差的高强度随机口令 |
| `encrypt-file-with-key` | `file_ops::cmd_encrypt_file_with_key` | 使用已有的 X25519 公钥直接加密文件 |
| `decrypt-private-key` | `keystore::cmd_decrypt_backup` | 解密并导出原始私钥 DER 数据 |

---

## 2. Git 提交与 Shell 命令规范（所有 Agent 强制遵守）

### 2.1 严禁裸用 `cat` 命令（防 alias 装饰符污染）

* **背景**：用户本地终端环境将 `cat` 别名（alias）为了 `bat`。直接使用裸 `cat` 会附带输出行号和 `STDIN ─────────` 装饰框。
* **强制规则**：
  1. **严禁**使用 `cat <<'EOF'` 或 `cat` 管道生成/写入 commit message 或文件内容，否则会导致提交日志或文件充斥 `STDIN ─────────` 脏字符！
  2. 编写 `git commit` 时，必须组织为**标准 3 段结构**（共 3 个 `-m`：第 1 段为标题，第 2 段为正文变更列表，第 3 段为署名尾注）。**严禁为每条变更点单独分配一个 `-m`**（Git 会在每个 `-m` 之间自动插入空行导致列表稀疏）；所有变更要点必须合并在同一个 `-m` 参数内换行（或使用 `$'...'` 转义换行）。
  3. 读取文件内容时，**必须优先使用 Agent 自带的专用读文件工具**（如 `view_file` / `Read`），禁止在 Shell 中使用裸 `cat` 读取。若在 Shell 脚本或命令中确需调用原版 `cat`，必须使用转义形式 `\cat` 或绝对路径 `/bin/cat`。

### 2.2 Git 身份归属与 AI 协同署名规范（人类主权 + AI 审计）

* **背景与权责划分**：
  * 为保障代码责任终身追溯、`git blame` 精准定位、团队合规以及人类贡献度（GitHub 绿格子正常计入），**代码的最终责任人与主所有者永远是当前操作的人类开发者**。
  * AI Agent 作为结对编程助手（Pair Programmer），其协同贡献统一通过业界标准的 `Co-Authored-By` 尾注进行审计追踪。
* **强制规则**：
  1. **Author & Committer 归属人类**：执行 `git commit` 时，必须直接继承并使用当前操作者本地配置的个人身份（`user.name` 与 `user.email`），**严禁**通过 `--author`、环境变量或 `git config` 篡改或抹除人类主责任人。
  2. **AI 协同署名（强制附加）**：提交信息第 3 段（末尾）**必须显式附加** `Co-Authored-By: <Model> <noreply@...>` 尾注。
  3. **模型名称规范**：仅使用简明的大类模型名字，**严禁携带版本号与子型号细节**（如仅使用 `Gemini`、`Claude`、`GPT`、`DeepSeek` 等；严禁使用 `Gemini 3.8 Flash`、`Claude 3.7 Sonnet`、`GPT-4o` 等）。
  4. **邮箱格式规范**：使用对应模型厂商的官方无回复域名：
     * Anthropic Claude 系列：`Co-Authored-By: Claude <noreply@anthropic.com>`
     * Google Gemini 系列：`Co-Authored-By: Gemini <noreply@google.com>`
     * OpenAI GPT / Codex 系列：`Co-Authored-By: GPT <noreply@openai.com>`
     * DeepSeek 系列：`Co-Authored-By: DeepSeek <noreply@deepseek.com>`
  5. **命令执行标准模板**：
     ```bash
     git commit -m "<type>(<scope>): <subject>" \
       -m "- <变更点 1>
     - <变更点 2>" \
       -m "Co-Authored-By: <Model> <noreply@domain.com>"
     ```

### 2.3 Commit Message 格式对齐（联动 `cliff.toml`）

* 统一遵循 Conventional Commits 格式：`<type>(<scope>): <subject>`（涉及全局的跨模块变更可省略 `(<scope>)`）。
* **`type` 取值范围**（与仓库根目录 `cliff.toml` 的 Changelog 解析规则严格对齐）：
  * `feat`: 新增功能
  * `fix`: 修复 bug
  * `refactor`: 重构（非新增功能亦非 bug 修复）
  * `perf`: 性能优化
  * `docs`: 文档变更
  * `style`: 格式、样式微调（不影响代码逻辑）
  * `test`: 增加或修改测试用例
  * `build`: 构建系统或外部依赖变更（如 `Cargo.toml`、`Makefile`）
  * `ci`: 持续集成配置或脚本变更（如 `.github/`）
  * `chore`: 辅助工具、Agent 规则/技能配置或日常维护变动
  * `revert`: 回滚历史提交
* **本项目 `scope` 推荐取值**：
  * **代码模块**：`crypto`、`keystore`、`file_ops`、`workflow`、`cli`、`password`、`utils`
  * **工程维护**：`deps`、`ci`、`doc`、`agent`、`release`

### 2.4 独立功能变更与 Worktree 隔离

* 在进行跨模块实验性特性开发、大型重构或未经用户显式要求在主工作区直接修改的独立功能时，必须优先使用 `git worktree` 创建隔离工作区与分支：
  ```bash
  git worktree add ../feature-{name} -b feature/{YYYYMMDDHHmmss}-{name}
  ```
