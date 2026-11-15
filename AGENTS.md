# AGENTS.md

本文件为所有在此仓库工作的 AI 编程助手（Antigravity 2.0 / `agy` CLI、Claude Code、Oh-My-Pi (`omp`)、Codex / GPT、Cursor 等）提供统一的架构指引、安全红线及工程与 Git 规范。

---

修改前读取 [工程规范](docs/code-standards.md)、[近期教训](LESSONS.md)，
并按 [子系统索引](docs/subsystems/README.md) 阅读受影响契约和链接源码。
执行任务时按 [协作流程](docs/agent-workflow.md) 建立任务卡、独立验收和复盘记录。
接口、状态、失败或兼容性行为改变时，同一变更更新对应子系统文档。

## 1. 项目架构与开发指南

### 1.1 构建、测试与质量门禁命令

完整门禁统一运行 `bash scripts/verify.sh`（或 `make verify` / `make all`）。
依赖、分项调试命令及证据格式见 [验证说明](docs/verification.md)。
`/check`、CI、原生 hook 和 pre-commit 配置均调用这个入口。
提交前运行完整门禁；单项 Cargo 命令用于定位问题，不能替代完整验收。

### 1.2 模块依赖流（Hybrid Cargo Workspace）

```text
YaCrypt (Workspace Root — Binary Package `yacrypt`)
  ├── src/main.rs           — 入口：try_mlockall 内存锁 + CLI/TUI 路由分发（无参或 `tui` 启动 TUI）
  ├── src/cli.rs            — Clap CLI 参数定义、dialoguer 终端密码提示与打印回显
  ├── src/tui/              — Ratatui + Crossterm 4 合 1 交互式终端工作台
  │     ├── mod.rs          — Raw Mode 终端守卫、panic 恢复钩子与事件循环
  │     ├── app.rs          — 4 标签页状态机（Keyring / Encrypt / Decrypt & Verify / Password Gen）与口令缓冲即时擦除
  │     └── ui.rs           — 响应式布局渲染、弹窗组件与 TestBackend 无头渲染测试
  └── crates/yacrypt-core/  — 纯数据驱动核心密码学库（零终端 I/O、零 println!/dialoguer）
        ├── src/lib.rs      — 公共 API 导出
        ├── src/constants.rs— 算法与协议常量（Argon2id 成本上下限、口令长度边界等）
        ├── src/workflow.rs — 高层工作流编排（加解密、新增密钥回滚、免口令密文头透视 inspect_file）
        ├── src/file_ops.rs — X25519 混合公钥加解密 (SCFv1/SCFv2) + 纯口令对称文件加解密 (SGPGv1/SGPGv2) + Ed25519 签名验签
        ├── src/keystore.rs — 密钥对生成、基于口令的私钥加密存储与恢复、本地密钥环扫描 (scan_keystore)
        ├── src/crypto.rs   — 核心密码学原语 (Argon2id + XChaCha20-Poly1305, SGPGv1/SGPGv2 与 SCFv1/SCFv2 打包与解包)
        ├── src/password.rs — 拒绝采样高熵随机口令生成
        └── src/utils.rs    — 安全 I/O 辅助函数 (write_file_strict)、公钥指纹计算、AAD 转义与解析
```

### 1.3 两种加密容器与三种业务模式

* **口令加密容器（`SGPGv1` / `SGPGv2` blob）**：
  * **算法**：Argon2id KDF → XChaCha20-Poly1305 AEAD。
  * **用途与域分离（通过 AAD `type` 字段严格隔离）**：
    1. **本地私钥加密备份**（`keystore/*.asc.enc`，维持 `SGPGv1`）：AAD 绑定 `fp=<fingerprint>|type=ed25519` 或 `type=x25519`。
    2. **纯口令对称文件加密**（`<file>.enc`，通过 `yacrypt encrypt -c` 或 TUI 对称模式触发）：新加密默认采用 `SGPGv2`（AAD `type=file|v=2`），在 AEAD 内层施加随机抖动 + Padmé 长度混淆填充以隐藏原文件精确字节数；解密与 `inspect` 同时兼容遗留 `SGPGv1`（`type=file`），严禁与私钥备份混用。
  * **二进制格式**：`MAGIC("SGPGv1" / "SGPGv2", 6B) + Argon2 params(12B) + salt + nonce + AAD + ciphertext`。
* **公钥混合加密容器（`SCFv2` / 遗留 `SCFv1` / `.pubenc` blob）**：
  * **算法**：X25519 ECDH（每文件生成临时密钥对）+ HKDF-SHA256 → XChaCha20-Poly1305 AEAD，默认内嵌 Ed25519 签名。
  * **用途**：业务文件非对称加密传输与存储，无需共享长期对称加密口令。
  * **新加密 `SCFv2` 隐私升级**：将 Ed25519 签名与签名者公钥移入 AEAD 密文内层（Sign-then-Encrypt，转录本绑定 `ephemeral_pub || recipient_pub || SHA256(plaintext)` 防重放与跨接收者移植），外层 `flags` 恒为 `0x00`、AAD 仅含 `v=2|ephemeral_pub=<hex>`，并对内层载荷施加随机抖动 + Padmé 长度混淆填充；彻底阻止无密钥的已知完整原文件离线比对并隐藏签名者指纹及精确字节数。同时完整保留遗留 `SCFv1` 文件的免密 `inspect` 与先验签后落盘解密。
  * **二进制格式**：
    * `SCFv2`（默认）：`MAGIC("SCFv2", 5B) + flags(1B=0x00) + ephemeral_pub(32B) + nonce(24B) + AAD + ciphertext`。
    * `SCFv1`（遗留兼容）：`MAGIC("SCFv1", 5B) + flags(1B) + [ed25519_vk(32B) + sig(64B)] + ephemeral_pub(32B) + nonce(24B) + AAD + ciphertext`。

### 1.4 密钥生成流

`generate_and_store_keys_in_dir()` 会同时生成两套密钥对并存入 `keystore/` 目录（目录权限 `0700`）：
* **Ed25519**：用于文件数字签名；私钥经口令加密后落盘，公钥以 Base64 存储。
* **X25519**：用于 ECDH 文件加密；私钥经同一口令加密后落盘，公钥以 Base64 存储。
* **密钥指纹（Fingerprint）**：取 `SHA256(Ed25519 公钥原始字节)` 的大写十六进制字符串。

### 1.5 密码学与安全不变量（Security Invariants，强制遵守）

修改任何涉及加解密、密钥管理、TUI 状态或文件 I/O 的代码时，**严禁破坏**以下安全红线：
1. **先验签、后落盘**：解密文件时，Ed25519 签名验证**必须**在向磁盘写入任何明文之前完成；验签失败必须立即中止并拒绝输出任何数据。
2. **敏感数据即时擦除**：所有口令（含 TUI 口令输入缓冲区 `Zeroizing<String>`）、私钥、派生密钥、共享密钥等敏感材料必须使用 `zeroize::Zeroize`（或 `Zeroizing` 包装器），在用毕、弹窗关闭或报错后立即清零。
3. **最小权限与同步写入**：私钥与敏感输出文件写入必须通过 `write_file_strict` 显式设置权限 `mode(0o600)`、`O_NOFOLLOW` 并调用 `sync_all()`，限制符号链接跟随与权限泄露。当前为直接写入；`sync_all()` 不构成崩溃原子替换保证，详见 [存储契约](docs/subsystems/storage.md)。
4. **Argon2 参数硬上限校验**：从外部密文解析 Argon2 参数（内存成本 `m_cost`、迭代次数 `t_cost`、并行度 `p_cost`）时，必须在派生前严格校验硬上限，防止恶意构造的密文头触发 OOM 拒绝服务。
5. **AAD 最小暴露绑定与域分离**：AAD 仅绑定解密必需的安全关键字段（如 `fp`、`type`、`v`、`ephemeral_pub`，以及遗留 `SCFv1` 的 `flags`/`sig_vk`），这些字段的篡改或跨类型混用（如拿私钥备份当普通对称文件解密）必须导致失败；`SCFv2` 严禁在明文外层 AAD 暴露 `sig_vk` 或签名标志位；**严禁**将低熵个人信息（姓名、邮箱、文件名等）或其明文哈希写入 AAD——低熵摘要可被字典还原（2026-10-18 复审 M-3 收口）。
6. **防 Swap 内存锁定**：在 Linux 环境下保持启动时调用 `try_mlockall()`，尝试锁定当前内存页；失败会告警，不能据此承诺全部敏感内存永不交换。
7. **默认最高保密与元信息防泄密（Privacy-by-Default，绝对不可静默降级）**：
   - **默认加密容器**：非对称加密默认且仅生成 `SCFv2`（Sign-then-Encrypt，Ed25519 签名与签名者公钥移入 AEAD 内层，外层 `flags` 恒为 `0x00`），纯口令对称加密默认且仅生成 `SGPGv2`；已淘汰以 `SCFv1` 或未填充 `SGPGv1` 写入新业务文件，旧格式仅保留兼容解密与 `inspect`。
   - **长度混淆填充**：`SCFv2` / `SGPGv2` 默认启用 Padmé + 随机抖动填充（`PADDING_MIN_FLOOR_BYTES = 1024`、`PADDING_MIN_JITTER_BYTES = 64`、`PADDING_MAX_JITTER_CAP_BYTES = 4 * 1024 * 1024`），掩盖原文件精确字节数（尤其是小文件与 tar 包特征）。严禁调小这些下限/上限或关闭默认填充。
   - **匿名输出文件名**：未显式指定 `--output` 时，默认生成同目录随机 16 位十六进制匿名文件名（`<16hex>.pubenc` / `<16hex>.enc`），**严禁**恢复 `<原文件名>.pubenc` / `<原文件名>.enc` 默认命名。
   - **默认不写伴生明文指引**：CLI（需显式 `--instructions` 才写出）与 TUI（`enc_no_instructions = true`）默认跳过 `.decrypt.txt`，避免残留原文件、密钥指纹或使用痕迹。
   - **禁止身份信息入参/入头与弱口令默认**：`gen-keypair` 已永久移除 `name`/`email` 参数（防 Shell 历史与密文关联）；CLI 与 TUI 新建密钥备份默认自动生成高熵随机口令。
   - **默认强制验签**：CLI 与 TUI 对 `.pubenc` 解密默认强制验证 Ed25519 签名（CLI 仅在显式传入 `--allow-unsigned` 时豁免）。
8. **受保护安全测试与降级阻断条款**：[tests/security_invariants.rs](tests/security_invariants.rs) 为受保护红线测试，任何 Agent **严禁擅自删改或放宽其断言**。若用户需求以“方便/UX”为由要求放宽第 1~7 条任意默认约束，Agent **必须先停止改动、向用户明确指出保密降级与泄密风险并请求显式确认**。

### 1.6 CLI 子命令入口对照表

| 子命令 | 对应实现函数 | 功能说明 |
| :--- | :--- | :--- |
| *(无参数)* / `tui` | `tui::run` | 启动 4 合 1 交互式终端工作台（非 TTY 无参运行自动回退输出帮助信息） |
| `inspect` | `cli::cmd_inspect_file` | 流式免口令透视 `.pubenc`（SCFv1/SCFv2）与 `.enc` / `.asc.enc`（SGPGv1/SGPGv2）容器头、填充/签名状态及 Argon2 参数 |
| `key-list` (别名 `keys`) | `cli::cmd_key_list` | 扫描并列出本地 keystore 下所有 Ed25519 + X25519 密钥对指纹、本地别名及完备状态 |
| `key-label` | `cli::cmd_key_label` | 设置或清除本地 `0600` 密钥别名（`labels.tsv`，绝不写入密文） |
| `key-export` (别名 `export-key`) | `cli::cmd_key_export` | 导出附带 Ed25519 自签名绑定的 Ed25519 + X25519 合并公钥包 |
| `key-import` (别名 `import-key`) | `cli::cmd_key_import` | 验证自签名与 L-1 低阶点并导入对端合并公钥包（可选 `--label`） |
| `change-key-password` | `cli::cmd_change_key_password` | 同步轮换本地 Ed25519 + X25519 加密私钥备份的口令 |
| `encrypt` | `cli::cmd_encrypt_workflow` | 加密流程：默认生成密钥对并签名加密（`SCFv2`，输出 `<16hex>.pubenc`，可选 `--label` / `--instructions`）；`--key` 复用公钥/别名；`-c / --symmetric` 纯口令对称加密（`SGPGv2`，输出 `<16hex>.enc`） |
| `decrypt` | `cli::cmd_decrypt_workflow` | 解密流程：支持 `.pubenc`（默认强制验签 + 解密，支持别名/指纹前缀选钥，可选 `--allow-unsigned`）与 `.enc`（自动识别 `SGPGv1`/`SGPGv2` `type=file` 或 `-c` 纯口令解密） |
| `gen-keypair` | `cli::cmd_generate_protected_key` | 生成受口令保护的 Ed25519 + X25519 密钥对（可选 `--label`） |
| `gen-password` | `cli::cmd_generate_strong_password` | 基于拒绝采样生成无模偏差的高强度随机口令 |
| `encrypt-file-with-key` | `cli::cmd_encrypt_file_with_key_cli` | 使用已有的 X25519 公钥/别名直接加密文件（可选 `--sign-key`） |
| `decrypt-private-key` | `cli::cmd_decrypt_backup` | 解密并导出原始 Ed25519 私钥 PKCS#8 DER 数据（默认 `<stem>.der`） |
| `completions` | `cli::cmd_completions` | 生成 `bash` / `zsh` / `fish` / `powershell` 自动补全脚本 |

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
  2. **AI 协同署名（强制附加）**：提交信息第 3 段（末尾）**必须显式附加** `Co-Authored-By: <Model> <email>` 尾注。
  3. **模型名称规范**：仅使用实际驱动的**底层基础模型大类名称**，**严禁携带版本号、子型号细节或外层客户端/Harness 名称**（如仅使用 `Gemini`、`Claude`、`GPT`、`DeepSeek` 等；无论通过 `Antigravity`、`agy`、`Oh-My-Pi (omp)` 还是 `Claude Code` 调用，均按当前会话实际所用的底层大模型署名；严禁使用 `Gemini 3.8 Flash`、`Claude 3.7 Sonnet`、`Oh-My-Pi`、`Antigravity` 等）。
  4. **邮箱格式规范**：使用对应模型厂商的官方无回复邮箱（或 GitHub 官方账号绑定的 `users.noreply.github.com` 邮箱以点亮头像）：
     * Anthropic Claude 系列：`Co-Authored-By: Claude <noreply@anthropic.com>`
     * Google Gemini 系列：`Co-Authored-By: Gemini <218195315+gemini-cli@users.noreply.github.com>`
     * OpenAI GPT / Codex 系列：`Co-Authored-By: GPT <noreply@openai.com>`
     * DeepSeek 系列：`Co-Authored-By: DeepSeek <noreply@deepseek.com>`
  5. **命令执行标准模板**：
     ```bash
     git commit -m "<type>(<scope>): <subject>" \
       -m "- <变更点 1>
     - <变更点 2>" \
       -m "Co-Authored-By: <Model> <email>"
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
  * **代码模块**：`core`、`tui`、`crypto`、`keystore`、`file_ops`、`workflow`、`cli`、`password`、`utils`
  * **工程维护**：`deps`、`ci`、`doc`、`agent`、`release`

### 2.4 多 Agent 并发协同与 Worktree 隔离规范

当多个 Agent（Claude Code、Oh-My-Pi `omp`、`agy` CLI、Antigravity 2.0）在同一项目下同时工作时，必须严格遵守以下并发守则：

1. **项目内 Worktree 隔离**：
   * 进行跨模块实验性特性开发、大型重构或多 Agent 并发任务时，必须使用 `git worktree` 在仓库内部的 `.worktrees/` 目录下创建隔离工作区（避免越出项目根目录触发 Antigravity / `agy` 的工作区外文件访问拦截，同时保持桌面整洁）：
     ```bash
     git worktree add .worktrees/{name} -b feat/{YYYYMMDDHHmmss}-{name}
     ```
   * 若使用 Claude Code 原生隔离模式，可直接运行 `claude -w {name}`（对应 `.claude/worktrees/{name}`）。
   * 动手修改代码前，先通过 `git branch --show-current` 确认当前所在分支与分配的任务范围一致。
2. **严禁破坏性构建清理（防 `target/` 踩踏）**：
   * 多 Agent 并发期间，**严禁**执行 `cargo clean`、`make clean` 或 `make rebuild`（否则会直接清空其他正在编译或测试的 Agent 的 `target/` 目录）。
   * 日常质量验证统一按 `/check` 技能顺序执行：`bash scripts/verify.sh`。
3. **模块边界与危险 Git 命令禁令**：
   * 仅修改当前任务分配的模块文件，未经用户明确指示，严禁执行跨模块全局格式化或擅自升级 `Cargo.toml` 依赖。
   * 未经用户显式确认，**严禁**执行 `git reset --hard`、`git clean -fd`、`git checkout -- .`、`git restore .` 或 `git push --force`。

### 2.5 严禁家目录/全盘无界扫描（防 macOS TCC 阻塞与 Watchdog 超时）

* **背景**：在 macOS 后台守护进程（如 Multica daemon、无头 `agy` / `pi` / `omp` 会话）中，对 `~`、`/Users` 或 `/` 执行递归遍历会触碰 `~/Library`、云盘挂载点及受 macOS TCC 隐私保护的目录（如 `~/Desktop`、`~/Documents`、`~/Downloads`），导致无交互终端的子进程永久阻塞，直至触发 2 小时 `idle_watchdog` 被强杀（`exit 137`）。
* **强制规则**：
  1. **严禁**运行 `find ~`、`find /`、`find /Users` 或跨家目录的无界递归搜索（如 `grep -R ~`、`rg ... ~`）。
  2. 代码与配置检索默认严格限制在当前仓库/Worktree 目录内；若确需排查本地工具链或漏洞库缓存（如 Cargo / RustSec `advisory-db`），**必须精确限定到具体缓存子目录**（例如 `~/.cargo`、`~/.cache/cargo-deny`）并显式附加 `-maxdepth` 边界。


