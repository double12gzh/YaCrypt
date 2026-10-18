# YaCrypt 修复验证报告

**——对 2026-10-18 安全审计（`SECURITY-AUDIT-2026-10-18.md`）的回归验证**

- **验证日期**：2026-10-18
- **验证对象**：修复提交 `52948ca`（撰写时记录为 `14e7460`，后因历史重写变更，见 §七-3；fix: remediate security audit findings across crypto, keystore, workflow, and supply chain），相对被审版本 `f92c5ae`（撰写时记录为 `1a0f7be`）净变更 +1,565 / −417 行，覆盖 `crypto / keystore / workflow / file_ops / utils / cli / main / constants / password`、`Cargo.lock`、`deny.toml`、CI、README，新增 `tests/cli_e2e.rs`（463 行）。
- **验证方法**：① 逐文件代码审查（修复是否覆盖根因）；② 独立重建（debug/release 均 `--locked`）；③ 运行全部 49 个测试（44 单元 + 5 集成，含 PTY 交互式攻击回归）；④ clippy `-D warnings`；⑤ cargo-deny 0.20.2 四级检查；⑥ release 二进制独立回归 12 组（V0–V11），运行环境 memlock = 8 MiB——正是旧版必崩的配置；⑦ 独立第二审计员对抗性复核（约 60 个攻击/兼容场景，含新旧版本对照构建与实验）。

---

## 一、结论速览

**上一次审计的全部 15 个编号发现均已处理：14 项完整修复，L-6 的流式化部分按审计建议列为 P2 持续项（见 §七-4）；核心安全属性经实测恢复。** 其中 H-2 有一处低级别残留（工作流层面的"未使用密钥对"残留）；修复改动本身引入 3 个低级别新问题，均修复成本极小。无中/高级残留。

| 编号 | 原问题 | 状态 | 关键实测证据 |
|---|---|---|---|
| **H-1** | 签名验证无信任锚 | ✅ **已解决** | 公钥伪造文件被拒：`untrusted signer fingerprint 2562E4…(expected 1CAF11…)`，无输出文件（V3）；默认锚=私钥 AAD 绑定指纹、`--signer` 可覆盖、无锚 fail-closed；成功时显示签名者指纹（V2/V8b） |
| **H-2** | mlockall 崩溃 + 孤儿公钥 | ✅ **基本解决**（1 项低残留） | `MCL_FUTURE` 已移除（`utils.rs` 仅 `MCL_CURRENT`）；默认 memlock 8 MiB 下 gen-keypair 完整成功（V1，旧版同环境 SIGABRT）；keystore 改为"全内存完成密码学运算 → 批量落盘 → 失败回滚"。残留：`encrypt` 工作流步骤 2 失败会留下完整但未使用的密钥对（§三-2） |
| **M-1** | 签名剥离降级 | ✅ **已解决** | 剥离后拒绝：`Signature stripped — AAD indicates file was signed…`（V4）；新旧格式签名文件均拦截；`--require-signature` 对未签名文件生效（V9） |
| **M-2** | 解析器 panic/abort | ✅ **已解决** | nonce_len=23 → `invalid nonce length: expected 24, got 23`；ct_len=u64::MAX → `ciphertext length overflow`；均 exit 1、**无信号**（V5）；独立复核另测试 16 种畸形输入全部干净报错 |
| **M-3** | AAD 明文元数据泄漏 | ✅ **已解决**（复审后彻底收口，见 §七-1） | blob 字节扫描无明文文件名/姓名/邮箱；摘要方案（V1/V2）后经外部复审以真实 keystore 实锤低熵字典还原，已整体移除 `file_sha256=`/`id_sha256=` 死字段，字典面清零；旧格式历史 blob 兼容性实测通过 |
| **M-4** | 写入语义不安全 | ✅ **已解决** | 默认拒绝覆盖（RC≠0，V6）；`--force` 覆盖既有 0644 文件后权限收紧为 **0600**（V6）；符号链接即使 `--force` 也拒绝且目标文件完好（V6） |
| **M-5** | 供应链门禁失效 | ✅ **已解决** | Cargo.lock 已入库；新 `deny.toml` 在 cargo-deny 0.20.2 下 **advisories/bans/licenses/sources 全绿（exit 0）**；CI 接入 cargo-deny-action + `--locked`；rand 升至 0.8.8（RUSTSEC-2026-0097 消除）；Sigstore 步骤不再吞错（`set -euo pipefail`） |
| **L-1** | X25519 无贡献性检查 | ✅ **已解决** | 加密/解密两侧均 `was_contributory()`；全零公钥加密被拒（V10） |
| **L-2** | Argon2 上限过宽 | ✅ **已解决** | 收紧至 256 KiB–256 MiB、t≤16、p≤16；实测 u32::MAX / 4 GiB / t=100 均干净拒绝 |
| **L-3** | 零化缺口 | ✅ **已解决**（1 处 nit） | `Zeroizing` 覆盖全部口令/密钥/明文含错误路径；nit：`derive_key` 的 `out` 缓冲在极难触达的库错误分支未清零 |
| **L-4** | AAD 长度静默截断 | ✅ **已解决** | `u16::try_from` + 显式报错 + 单元测试 |
| **L-5** | 密钥类型无校验 | ✅ **已解决** | x25519 备份拒导出 DER（V11）；`type=` 标记 + PKCS#8 DER 双重校验 |
| **L-6** | 解密路径不锁内存 / 全文件读入内存 | ✅ **已解决**（锁）/ P2 持续（流式化） | `try_mlockall` 于 `main` 启动即调用，覆盖全部子命令；大文件流式化按审计建议列为 P2 持续项（见 §七-4） |
| **I-1** | 解析器容忍尾随字节/未知 flags | ✅ **已解决** | 尾随字节显式拒绝（`unexpected trailing bytes…`）、未知 pubenc flags 拒绝（`unsupported pubenc flags: 0x..`），均有单元测试覆盖 |
| **I-2** | 元数据误称 libsodium | ✅ **已解决** | `Cargo.toml` 描述与 `--help` 均已修正，新增断言测试 |

---

## 二、关键实测记录（release 二进制，默认 memlock = 8192 KiB）

```
V1  gen-keypair（默认 memlock，旧版必崩环境）→ drive_RC=0，keystore 5/5 文件齐全
V3  伪造（仅受害者公钥）→ Error: "❌ Signature verification FAILED — untrusted signer
    fingerprint 2562E4B2…（expected 1CAF1109…）。Decrypted content NOT written to disk."
V4  签名剥离 → Error: "❌ Signature stripped — AAD indicates file was signed, but
    signature block is missing! …NOT written to disk."
V5  nonce_len=23 → "Format error: invalid nonce length: expected 24, got 23"；exit 1
    ct_len=u64::MAX → "Format error: ciphertext length overflow"；exit 1（无 SIGABRT）
V6  无 --force 二次写入 → RC=1；--force 覆盖 0644 → 权限 600；符号链接 --force → RC=1，目标完好
V7  旧版格式签名文件 + 旧 keystore → "✅ verified successfully (signer fingerprint:
    92DECFBD…)"，内容与原件逐字节一致（向后兼容通过）
V8  跨用户：B 签名加密给 A → A 默认锚拒收（untrusted signer 7DC9BE… expected 1CAF11…）；
    A 加 --signer <B指纹> → 验证成功并显示 B 指纹
V9  --require-signature 拒绝未签名文件；不加时提示 "No signature embedded…" 后正常解密
V10 全零 X25519 公钥加密 → "non-contributory / low-order point" 拒绝，无输出
V11 x25519 私钥备份导出 DER → "Cannot export 'x25519' key…" 拒绝
另：49/49 测试通过（44 单元 + 5 集成 PTY 攻击回归）；clippy 零告警；
    cargo-deny 0.20.2: "advisories ok, bans ok, licenses ok, sources ok"
```

---

## 三、修复改动引入的新问题（均为低级别，建议顺手修复）

1. **[低] `--signer` 十六进制可被同名文件遮蔽**（`workflow.rs` `resolve_signer_fingerprint`）：函数先检查 `Path::exists()`，再判断 64-hex。若攻击者能在用户的工作目录放置一个文件名恰好等于目标指纹（64 字符 hex）的恶意公钥文件，用户键入的 `--signer <指纹>` 会被解析为该文件路径，显式信任锚被遮蔽（默认锚路径不受影响；实际签名者指纹仍会打印）。修复：先判断 64-hex 再按路径解析（一行顺序调整），或要求路径以 `.asc` 结尾。
2. **[低] `encrypt` 工作流失败残留**（`workflow.rs:97-108`）：步骤 1 生成并写入整套密钥对后，步骤 2（加密+签名文件）失败（如输出已存在、说明文件冲突）会以非零退出，但留下**完整但未被使用**的密钥对及已打印的口令。非危险形态（私钥存在，不会产生不可解密文件），但状态混乱。修复：步骤 2 失败时清理本次生成的 5 个 keystore 文件（指纹为本次新生成，无删除用户文件风险）。
3. **[低] 非普通文件输出路径可致阻塞**（`utils.rs:37-69`）：既有检查只拒绝目录与符号链接；`--force` 下若输出路径是 FIFO（命名管道），`open(O_TRUNC)` 会永久阻塞（实测挂起）。修复：将检查扩展为"必须是普通文件"（`!file_type().is_file()` 即拒绝）。附带两个 info 级：`O_TRUNC` 在 `fchmod` 之前存在极短权限窗口；`O_NOFOLLOW` 仅保护路径末段（父目录为符号链接时不设防）。
4. **[提示] `parse_aad_map` 重复键取后者、键名大小写敏感**：无安全影响（经 AEAD 认证的 AAD 不可能含重复键；攻击者自建文件本就无需绕过），可作防御性加固（拒绝重复键）。
5. **[提示] 默认仍接受未签名文件**（有显式提示，`--require-signature`/`--signer` 可强制）——属设计取舍；建议在文档中明确"跨渠道接收文件建议加 `--require-signature`"。
6. **[提示] `file_sha256` / `id_sha256` 为低熵哈希**：能防 `strings` 直读，但不能防字典确认（怀疑某文件名/姓名时可枚举比对）。彻底方案是元数据加密进密文载荷（未来 v2 格式）。**（2026-10-18 复审收口：该提示被外部复审实锤复现，已改为直接移除两个死哈希字段，见 §七-1；若未来需可核验元数据，仍走 v2 加密进密文载荷方案。）**
7. **[杂项] ** `main` 与 `keystore` 中两次 `try_mlockall`（无害）；CI clippy 步骤未加 `--locked`（装饰性）；`.pre-commit-config.yaml` 的 audit 钩子仍注释（CI 已有门禁，可接受）。

---

## 四、向后兼容

**通过，无需迁移。** 新二进制成功解密并验签由旧版二进制生成的**真实历史工件**（旧 AAD 格式 `name=…|email=…|fp=…[|type=x25519]` 与 `file=…|ephemeral_pub=…[|sig_vk=…]`）：签名验证通过、签名者指纹正确、内容逐字节一致（V7）；独立复核另用一套历史工件复验同样通过；旧未签名文件默认接受、`--require-signature` 下拒绝；旧 ed25519 备份可正常导出 DER，旧 x25519 备份被正确拒绝导出。

## 五、总评与后续建议

上一次审计的 P0 四项全部清零：**伪造不再可能（H-1）、Linux 主流程稳定不再崩溃（H-2）、供应链门禁真实生效（M-5）、恶意输入不再导致崩溃（M-2）**，且修复不是"打补丁"式的：解析器整体重写为 checked 风格、信任锚模型明确化（默认锚+显式覆盖+fail-closed）、写入语义统一收口、新增 49 个测试（含将原始攻击 PoC 固化为回归测试）。剩余问题全部为**低/提示级**，建议按 §三 的顺序处理第 1–3 项（合计约一天工作量），并在 1.0 前完成一次第三方外部审计。**当前状态：可进入 beta。**

验证证据：`security-audit-2026-10-18/fix-verification/`（V0–V11 全套脚本与日志、构建哈希）。

---

## 六、后续补丁（同日追加）

§三 所列 3 项低级问题及 2 项杂项 nit 已于同日修复并提交：**`860a077`**（撰写时记录为 `2fd82e9`，后因历史重写变更，见 §七-3；fix: resolve residual findings from post-remediation fix-verification，含 Co-Authored-By 署名）。

| 项 | 修复内容 | 回归验证 |
|----|----------|----------|
| ① `--signer` 遮蔽 | 先解析 64-hex 指纹，再按路径解析（`resolve_signer_fingerprint`） | 新增 2 个单元测试；同名文件遮蔽攻击实测**失败关闭**（错误信息中 expected 显示所输十六进制而非文件公钥） |
| ② `encrypt` 残留 | 步骤 2 失败时回滚本次生成的 5 个 keystore 文件；说明文件写入失败降级为警告（不再在产物已产生后中止） | 新增集成测试（失败后 keystore 计数不变）；全量 e2e 无回归 |
| ③ FIFO/特殊文件 | 写入前拒绝非普通文件（前置检查 + `O_NONBLOCK` + fd 复核）；`--force` 先收紧权限再截断，消除混写窗口 | 新增单元测试（mkfifo）；实测 FIFO 快速失败（无阻塞）、`/dev/null` 拒绝 |
| nit | `derive_key` 错误路径零化输出缓冲；CI clippy 加 `--locked`；双语 README 补充"跨不可信渠道建议 `--require-signature`" | fmt ✅ clippy(-D warnings) ✅ |

**补丁后质量门禁全绿**：`cargo fmt --check` ✅ · `cargo clippy --locked --all-targets --all-features -D warnings` ✅ · **53/53 测试**（47 单元 + 6 集成）✅ · `cargo deny check` 四级 ✅ · V0–V11 端到端回归 ✅（release 二进制，默认 memlock 8 MiB）。至此 §三 清单清零，剩余仅"低熵元数据哈希"与"默认接受未签名文件"两个已记录的**设计取舍/未来项**（属 v2 格式与文档层面）。**（2026-10-18 复审收口轮补充：低熵哈希项已彻底解决——AAD 不再携带可字典还原的字段，旧格式历史 blob 兼容性实测通过；仅剩"默认接受未签名文件"一项设计取舍。详见 §七。）**

---

## 七、外部复审收口轮（2026-10-18 追加）

本文档与审计报告经一次外部复审（对方独立实机复现 8 项修复、全部通过；并对本文档与代码逐项核验）。针对复审提出的有效项，同日完成收口：代码/测试见提交 `f5138cc`，Agent 规则/技能见 `3ac7507`，文档与证据入库为本节所在提交。

1. **M-3 彻底收口（字典攻击面清零）**：复审用真实 keystore 实锤低熵摘要可被字典还原（`sha256("Bob|bob@example.com")` 一次命中、完全还原；本次已再次独立复算确认逐字符一致）。经全仓排查，`file_sha256`/`id_sha256` 从未被解密端消费（只写不读），已从 keystore/pubenc 新版 AAD 中整体移除，并删除 `escape_aad_field`/`hash_metadata_field` 及对应单测；`recovery_instructions_*.txt` 不再写入明文姓名/邮箱（name/email 仅回显供用户自留记录）。**旧版历史 blob 解密不受影响**：已用现场构造的真实旧格式工件实测——含 `id_sha256=` 的 keystore blob 成功解密并导出原始种子、含 `file_sha256=` 的 pubenc 逐字节还原、旧 AAD 被篡改时仍被完整认证拒绝；脚本与日志见 `security-audit-2026-10-18/review-closure/`。复审建议的 `HMAC-SHA256(fingerprint, …)` 经评估**未采纳**：指纹公开且位于同一 AAD 内，不提供保密性；如未来需"可核验但不泄漏"的元数据，按审计原计划以 v2 加密进密文载荷。
2. **备份口令 stdout 暴露面（复审指出项）**：`gen-keypair`/`encrypt` 的自动备份口令改为**默认关闭**（回车即用户自设口令，默认路径不再向 stdout 输出任何口令）；显式选择自动生成时仍打印一次并保留强提醒。集成测试锁定"默认不打印口令"与"显式自动生成仍可用"两条路径。
3. **提交哈希修正说明**：本文档撰写后，仓库为统一 Gemini 署名邮箱执行过一次 `git filter-branch` 历史重写（reflog 可证），映射：`1a0f7be→f92c5ae`、`14e7460→52948ca`、`2fd82e9→860a077`（另 `b778200→58d3590`、`3ba41bc→29167d1`；`12f5258` 未变）。**本次已将审计报告、本文档及证据目录整体提交入库**，杜绝证据链再次漂移。
4. **口径修正**：审计共 15 个编号发现（H-1/H-2、M-1~M-5、L-1~L-6、I-1~I-2），现已全部处理：14 项完整修复；L-6 的"解密路径不锁内存"已随 H-2 修复（`try_mlockall` 启动即调用，覆盖全部子命令），"整文件读入内存→流式化"仍为审计建议的 P2 持续项。表一已补充 L-6、I-1 两行。
5. **门禁复核（含复审未能复现的 cargo-deny 项）**：`cargo fmt --check` ✅ · `cargo clippy --locked --all-targets --all-features -D warnings` ✅ · **51/51 测试**（45 单元 + 6 集成；较上轮减少 2 项系 `escape_aad_field` 测试随函数删除）✅ · **`cargo deny 0.20.2` 独立复跑四级全绿（exit 0）**，日志见 `security-audit-2026-10-18/review-closure/deny-check.log` ✅。回归套件 `suite4.sh` 已按新默认交互同步（`DRIVE_EXPECTS` 显式回答 `y`，保留自动路径覆盖）；`/check` 技能补充 cargo-deny 缺装回退说明（`make security` 自动安装）。pre-commit 的 audit 钩子维持注释状态（`language: system` 钩子会阻塞未安装工具的协作者；CI 已兜底）。
