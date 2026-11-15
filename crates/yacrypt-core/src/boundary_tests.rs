//! SGPGv1 / SCFv1 畸形输入与解密侧对抗性回归矩阵（JEFF-186）。
//!
//! 来源：2026-11-01 安全巡检（JEFF-185）的一次性探针 `parser_patrol.rs`。
//! 本模块把该探针的覆盖固化为常规回归测试，并把“拒绝路径必须不落盘”的
//! 安全后果作为断言主体，而不是依赖具体英文错误文案。
//!
//! 覆盖矩阵：
//! 1. SGPGv1 与 SCFv1（有/无签名）每个 strict prefix 截断；
//! 2. salt / nonce 长度字段错误、AAD 声明长度与实际可用字节不匹配、
//!    ciphertext 长度 u64 溢出 / 普通不匹配 / 尾随字节、全部未支持 flags、
//!    短于 16 字节 AEAD tag；AAD 65535 正例与 65536 打包拒绝；
//! 3. 恶意 Argon2 参数经真实文件解密、私钥备份解密与公钥解密工作流入
//!    （不只直接调用 `derive_key`）；
//! 4. 解密侧低阶 ephemeral_pub、独立无效 Ed25519 签名、AAD/头部不一致、
//!    必须签名却无签名、签名块被剥离；
//! 5. 每个拒绝路径都断言“无输出文件”与 `force=true` 时既有 sentinel 不变。
//!
//! 约束：只用低成本合成 fixture（Argon2 m=256 KiB, t=1, p=1），
//! 绝不为边界测试运行有效的高成本 KDF；敏感缓冲使用 `Zeroizing`。

use crate::constants::{
    MAGIC, MAX_ARGON_M_COST_KIB, MAX_ARGON_P_COST, MAX_ARGON_T_COST, MIN_ARGON_M_COST_KIB,
    PUBENC_MAGIC, SALT_LEN, XNONCE_LEN,
};
use crate::crypto::{
    decrypt_with_aad, derive_key, derive_symmetric_key_from_shared_secret, encrypt_with_aad,
    pack_encrypted_blob, pack_pubenc_blob, unpack_encrypted_blob, unpack_pubenc_blob,
    PubencSignature,
};
use crate::error::CryptError;
use crate::file_ops::decrypt_file_symmetric;
use crate::keystore::decrypt_backup_with_password;
use crate::utils::parse_aad_map;
use crate::workflow::{decrypt_workflow_with_password, DecryptOutcome};
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// 满足 `MIN_PASSWORD_LENGTH` 的测试口令
const TEST_PASSWORD: &str = "boundary-pass-1234";
/// 合成 fixture 的 Argon2 成本：足够低以保持测试快速，且不低于最小允许值
const CHEAP_M_COST: u32 = 256;
const CHEAP_T_COST: u32 = 1;
const CHEAP_P_COST: u32 = 1;

// ── fixture 辅助 ───────────────────────────────────────

/// 临时目录守卫：`Drop` 时无条件清理，因此断言失败 panic 也不会在系统临时目录
/// 残留私钥/明文 fixture。不引入第三方依赖。
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new(tag: &str) -> Self {
        // 同一进程内并行的测试可能复用 tag，用原子序号保证目录唯一
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "yacrypt_boundary_{}_{}_{}",
            tag,
            std::process::id(),
            seq
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create scratch dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// 用最便宜的合法 Argon2 参数合成一个 SGPGv1 容器
fn sgpg_fixture(aad: &str, plaintext: &[u8]) -> Vec<u8> {
    let salt = [0x31u8; SALT_LEN];
    let nonce = [0x32u8; XNONCE_LEN];
    let key = Zeroizing::new(
        derive_key(TEST_PASSWORD, &salt, CHEAP_M_COST, CHEAP_T_COST, CHEAP_P_COST).unwrap(),
    );
    let ciphertext = encrypt_with_aad(&key, &nonce, plaintext, aad.as_bytes()).unwrap();
    pack_encrypted_blob(
        CHEAP_M_COST,
        CHEAP_T_COST,
        CHEAP_P_COST,
        &salt,
        &nonce,
        aad.as_bytes(),
        &ciphertext,
    )
    .unwrap()
}

/// 合成一个 X25519 私钥备份（SGPGv1，AAD 绑定 `fp=<FP>|type=x25519`）
fn x25519_backup_fixture(secret: &[u8; 32], owner_fp: &str) -> Vec<u8> {
    let aad = format!("fp={}|type=x25519", owner_fp);
    sgpg_fixture(&aad, secret)
}

/// 合成一个 `.pubenc`（SCFv1）容器：调用方显式给出 AAD 与可选签名块
fn scf_fixture(
    recipient_pub: &X25519PublicKey,
    eph_secret: &StaticSecret,
    aad: &str,
    plaintext: &[u8],
    signature: Option<PubencSignature>,
) -> Vec<u8> {
    let eph_pub = X25519PublicKey::from(eph_secret).to_bytes();
    let shared = eph_secret.diffie_hellman(recipient_pub);
    assert!(shared.was_contributory(), "fixture must use a contributory ephemeral key");
    let sym_key = Zeroizing::new(derive_symmetric_key_from_shared_secret(
        shared.as_bytes(),
        &eph_pub,
        b"yacrypt-file-encryption-v1",
    ));
    let nonce = [0x5Au8; XNONCE_LEN];
    let ciphertext = encrypt_with_aad(&sym_key, &nonce, plaintext, aad.as_bytes()).unwrap();
    pack_pubenc_blob(&eph_pub, &nonce, aad.as_bytes(), &ciphertext, signature.as_ref()).unwrap()
}

fn unsigned_scf_aad(eph_pub: &[u8; 32]) -> String {
    format!("flags=00|ephemeral_pub={}", hex::encode(eph_pub))
}

fn signed_scf_aad(eph_pub: &[u8; 32], vk: &[u8; 32]) -> String {
    format!("flags=01|ephemeral_pub={}|sig_vk={}", hex::encode(eph_pub), hex::encode(vk))
}

/// 断言拒绝路径没有产生任何输出，且 `force=true` 也不会覆盖既有 sentinel
fn assert_no_write_and_sentinel_preserved<T>(
    run: impl Fn(Option<&Path>, bool) -> Result<T, CryptError>,
    dir: &Path,
) {
    let absent = dir.join("must_not_exist.bin");
    assert!(run(Some(&absent), false).is_err(), "hostile input must be rejected");
    assert!(!absent.exists(), "rejected decrypt must not create output");

    let sentinel = dir.join("sentinel.bin");
    fs::write(&sentinel, b"SENTINEL").unwrap();
    assert!(run(Some(&sentinel), true).is_err(), "hostile input must stay rejected with force");
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"SENTINEL",
        "force must never overwrite an existing output after a rejected decrypt"
    );
    fs::remove_file(&sentinel).unwrap();
}

// ── 1. strict prefix 截断矩阵 ──────────────────────────

#[test]
fn sgpg_rejects_every_strict_prefix_truncation() {
    let aad = "type=file";
    let blob = sgpg_fixture(aad, b"truncation matrix payload");

    let mut prefixes = 0usize;
    for end in 0..blob.len() {
        let r = unpack_encrypted_blob(&blob[..end]);
        assert!(
            matches!(r, Err(CryptError::Format(_))),
            "SGPGv1 prefix of {end} bytes must be rejected as a format error"
        );
        prefixes += 1;
    }
    assert_eq!(prefixes, blob.len());

    // 正例对照：完整容器必须仍可解析，避免“一律拒绝”也能通过
    let parsed = unpack_encrypted_blob(&blob).unwrap();
    assert_eq!(parsed.aad, aad.as_bytes().to_vec());
    assert_eq!(parsed.ciphertext.len(), b"truncation matrix payload".len() + 16);
}

#[test]
fn scf_rejects_every_strict_prefix_truncation_signed_and_unsigned() {
    let recipient = StaticSecret::from([0x11u8; 32]);
    let recipient_pub = X25519PublicKey::from(&recipient);
    let eph = StaticSecret::from([0x22u8; 32]);
    let eph_pub = X25519PublicKey::from(&eph).to_bytes();
    let signing_key = SigningKey::from_bytes(&[0x33u8; 32]);
    let vk = signing_key.verifying_key().to_bytes();
    let payload = Zeroizing::new(b"scf truncation payload".to_vec());

    let unsigned_aad = unsigned_scf_aad(&eph_pub);
    let unsigned_blob = scf_fixture(&recipient_pub, &eph, &unsigned_aad, &payload, None);

    let signature =
        PubencSignature { verifying_key: vk, signature: signing_key.sign(&payload).to_bytes() };
    let signed_aad = signed_scf_aad(&eph_pub, &vk);
    let signed_blob = scf_fixture(&recipient_pub, &eph, &signed_aad, &payload, Some(signature));

    for (label, blob, has_signature) in
        [("unsigned", &unsigned_blob, false), ("signed", &signed_blob, true)]
    {
        for end in 0..blob.len() {
            let r = unpack_pubenc_blob(&blob[..end]);
            assert!(
                matches!(r, Err(CryptError::Format(_))),
                "SCFv1 {label} prefix of {end} bytes must be rejected as a format error"
            );
        }
        // 正例对照：完整容器仍可解析，签名块存在性符合预期
        let parsed = unpack_pubenc_blob(blob).unwrap();
        assert_eq!(parsed.signature.is_some(), has_signature);
        assert_eq!(parsed.ephemeral_pub, eph_pub);
    }
}

// ── 2. 长度字段、flags 与 AEAD tag 边界 ─────────────────

#[test]
fn sgpg_rejects_invalid_salt_and_nonce_length_fields() {
    let blob = sgpg_fixture("type=file", b"length fields");
    let salt_len_off = MAGIC.len() + 12;
    let nonce_len_off = salt_len_off + 1 + SALT_LEN;

    for bad_len in [0u8, 15, 17, 255] {
        let mut malformed = blob.clone();
        malformed[salt_len_off] = bad_len;
        assert!(
            matches!(unpack_encrypted_blob(&malformed), Err(CryptError::Format(_))),
            "SGPGv1 salt_len={bad_len} must be rejected"
        );
    }
    for bad_len in [0u8, 23, 25, 255] {
        let mut malformed = blob.clone();
        malformed[nonce_len_off] = bad_len;
        assert!(
            matches!(unpack_encrypted_blob(&malformed), Err(CryptError::Format(_))),
            "SGPGv1 nonce_len={bad_len} must be rejected"
        );
    }
    // 正例对照：未改动的容器仍可解析
    assert!(unpack_encrypted_blob(&blob).is_ok());
}

#[test]
fn sgpg_rejects_declared_length_mismatches_and_trailing_bytes() {
    let aad = "type=file";
    let blob = sgpg_fixture(aad, b"declared length matrix");
    let aad_len_off = MAGIC.len() + 12 + 1 + SALT_LEN + 1 + XNONCE_LEN;
    let ct_len_off = aad_len_off + 2 + aad.len();
    let ct_len = blob.len() - ct_len_off - 8;

    // AAD 声明长度超过实际可用数据
    let mut oversized_aad = blob.clone();
    oversized_aad[aad_len_off..aad_len_off + 2].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(matches!(unpack_encrypted_blob(&oversized_aad), Err(CryptError::Format(_))));

    // ciphertext 声明长度比实际多 1 字节（普通不匹配，非溢出）
    let mut ct_too_long = blob.clone();
    ct_too_long[ct_len_off..ct_len_off + 8].copy_from_slice(&((ct_len + 1) as u64).to_be_bytes());
    assert!(matches!(unpack_encrypted_blob(&ct_too_long), Err(CryptError::Format(_))));

    // ciphertext 声明长度比实际少 1 字节 -> 剩余字节被判定为尾随数据
    let mut ct_too_short = blob.clone();
    ct_too_short[ct_len_off..ct_len_off + 8].copy_from_slice(&((ct_len - 1) as u64).to_be_bytes());
    assert!(matches!(unpack_encrypted_blob(&ct_too_short), Err(CryptError::Format(_))));

    // ciphertext 长度 u64 溢出
    let mut ct_overflow = blob.clone();
    ct_overflow[ct_len_off..ct_len_off + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(matches!(unpack_encrypted_blob(&ct_overflow), Err(CryptError::Format(_))));

    // 尾随字节
    let mut trailing = blob.clone();
    trailing.push(0xFF);
    assert!(matches!(unpack_encrypted_blob(&trailing), Err(CryptError::Format(_))));
}

#[test]
fn scf_rejects_declared_length_mismatches_and_trailing_bytes_both_modes() {
    let recipient = StaticSecret::from([0x11u8; 32]);
    let recipient_pub = X25519PublicKey::from(&recipient);
    let eph = StaticSecret::from([0x22u8; 32]);
    let eph_pub = X25519PublicKey::from(&eph).to_bytes();
    let signing_key = SigningKey::from_bytes(&[0x33u8; 32]);
    let vk = signing_key.verifying_key().to_bytes();
    let payload = Zeroizing::new(b"scf length payload".to_vec());

    let unsigned_aad = unsigned_scf_aad(&eph_pub);
    let unsigned_blob = scf_fixture(&recipient_pub, &eph, &unsigned_aad, &payload, None);
    let signed_aad = signed_scf_aad(&eph_pub, &vk);
    let signed_blob = scf_fixture(
        &recipient_pub,
        &eph,
        &signed_aad,
        &payload,
        Some(PubencSignature {
            verifying_key: vk,
            signature: signing_key.sign(&payload).to_bytes(),
        }),
    );

    for (label, blob, aad_len) in [
        ("unsigned", &unsigned_blob, unsigned_aad.len()),
        ("signed", &signed_blob, signed_aad.len()),
    ] {
        let signed = label == "signed";
        let aad_len_off =
            PUBENC_MAGIC.len() + 1 + if signed { 32 + 64 } else { 0 } + 32 + XNONCE_LEN;
        let ct_len_off = aad_len_off + 2 + aad_len;
        let ct_len = blob.len() - ct_len_off - 8;

        let mut oversized_aad = blob.clone();
        oversized_aad[aad_len_off..aad_len_off + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(
            matches!(unpack_pubenc_blob(&oversized_aad), Err(CryptError::Format(_))),
            "SCFv1 {label} oversized declared AAD must be rejected"
        );

        let mut ct_too_long = blob.clone();
        ct_too_long[ct_len_off..ct_len_off + 8]
            .copy_from_slice(&((ct_len + 1) as u64).to_be_bytes());
        assert!(
            matches!(unpack_pubenc_blob(&ct_too_long), Err(CryptError::Format(_))),
            "SCFv1 {label} declared ciphertext length beyond available bytes must be rejected"
        );

        let mut ct_too_short = blob.clone();
        ct_too_short[ct_len_off..ct_len_off + 8]
            .copy_from_slice(&((ct_len - 1) as u64).to_be_bytes());
        assert!(
            matches!(unpack_pubenc_blob(&ct_too_short), Err(CryptError::Format(_))),
            "SCFv1 {label} declared ciphertext length below available bytes must be rejected"
        );

        let mut ct_overflow = blob.clone();
        ct_overflow[ct_len_off..ct_len_off + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(
            matches!(unpack_pubenc_blob(&ct_overflow), Err(CryptError::Format(_))),
            "SCFv1 {label} u64 ciphertext overflow must be rejected"
        );

        let mut trailing = blob.clone();
        trailing.push(0x00);
        assert!(
            matches!(unpack_pubenc_blob(&trailing), Err(CryptError::Format(_))),
            "SCFv1 {label} trailing bytes must be rejected"
        );

        // 正例对照
        assert!(unpack_pubenc_blob(blob).is_ok());
    }
}

#[test]
fn scf_rejects_every_unsupported_flag_in_both_modes() {
    let recipient = StaticSecret::from([0x11u8; 32]);
    let recipient_pub = X25519PublicKey::from(&recipient);
    let eph = StaticSecret::from([0x22u8; 32]);
    let eph_pub = X25519PublicKey::from(&eph).to_bytes();
    let signing_key = SigningKey::from_bytes(&[0x33u8; 32]);
    let vk = signing_key.verifying_key().to_bytes();
    let payload = Zeroizing::new(b"flag matrix".to_vec());

    let unsigned_blob =
        scf_fixture(&recipient_pub, &eph, &unsigned_scf_aad(&eph_pub), &payload, None);
    let signed_blob = scf_fixture(
        &recipient_pub,
        &eph,
        &signed_scf_aad(&eph_pub, &vk),
        &payload,
        Some(PubencSignature {
            verifying_key: vk,
            signature: signing_key.sign(&payload).to_bytes(),
        }),
    );

    let mut mutations = 0usize;
    for (label, blob) in [("unsigned", &unsigned_blob), ("signed", &signed_blob)] {
        for flag in 2u8..=u8::MAX {
            let mut malformed = blob.clone();
            malformed[PUBENC_MAGIC.len()] = flag;
            assert!(
                matches!(unpack_pubenc_blob(&malformed), Err(CryptError::Format(_))),
                "SCFv1 {label} unsupported flags 0x{flag:02x} must be rejected"
            );
            mutations += 1;
        }
    }
    assert_eq!(mutations, 2 * 254);
}

#[test]
fn aad_length_boundary_accepts_65535_and_rejects_65536() {
    let max_aad = vec![b'a'; u16::MAX as usize];

    // 正例：65535 字节 AAD 在两种容器中均可打包并回读
    let sgpg = pack_encrypted_blob(
        CHEAP_M_COST,
        CHEAP_T_COST,
        CHEAP_P_COST,
        &[0x41u8; SALT_LEN],
        &[0x42u8; XNONCE_LEN],
        &max_aad,
        &[0x43u8; 16],
    )
    .unwrap();
    assert_eq!(unpack_encrypted_blob(&sgpg).unwrap().aad.len(), max_aad.len());

    let scf = pack_pubenc_blob(&[0x44u8; 32], &[0x45u8; XNONCE_LEN], &max_aad, &[0x46u8; 16], None)
        .unwrap();
    assert_eq!(unpack_pubenc_blob(&scf).unwrap().aad.len(), max_aad.len());

    // 负例：65536 字节无法用 u16 长度表达，必须在打包阶段拒绝
    let too_long = vec![b'a'; u16::MAX as usize + 1];
    assert!(matches!(
        pack_encrypted_blob(
            CHEAP_M_COST,
            CHEAP_T_COST,
            CHEAP_P_COST,
            &[0x41u8; SALT_LEN],
            &[0x42u8; XNONCE_LEN],
            &too_long,
            &[0x43u8; 16]
        ),
        Err(CryptError::Format(_))
    ));
    assert!(matches!(
        pack_pubenc_blob(&[0x44u8; 32], &[0x45u8; XNONCE_LEN], &too_long, &[0x46u8; 16], None),
        Err(CryptError::Format(_))
    ));
}

#[test]
fn aead_rejects_ciphertext_shorter_than_authentication_tag() {
    let key = [0x51u8; 32];
    let nonce = [0x52u8; XNONCE_LEN];
    let aad = b"type=file";

    for ct_len in 0..16usize {
        let ct = vec![0u8; ct_len];
        assert!(
            matches!(decrypt_with_aad(&key, &nonce, &ct, aad), Err(CryptError::Crypto(_))),
            "AEAD must reject a {ct_len}-byte ciphertext (shorter than the 16-byte tag)"
        );
    }

    // 正例对照：真实密文必须能解回明文
    let plaintext = Zeroizing::new(b"aead positive control".to_vec());
    let ct = encrypt_with_aad(&key, &nonce, &plaintext, aad).unwrap();
    assert_eq!(decrypt_with_aad(&key, &nonce, &ct, aad).unwrap(), plaintext.to_vec());
}

// ── 3. 恶意 Argon2 参数经真实解密入口 ───────────────────

/// 覆盖全部越界维度：内存上下限、迭代次数、并行度，以及 u32 极值
fn hostile_argon2_cases() -> [(u32, u32, u32); 10] {
    [
        (0, 1, 1),
        (MIN_ARGON_M_COST_KIB - 1, 1, 1),
        (MAX_ARGON_M_COST_KIB + 1, 1, 1),
        (u32::MAX, 1, 1),
        (CHEAP_M_COST, 0, 1),
        (CHEAP_M_COST, MAX_ARGON_T_COST + 1, 1),
        (CHEAP_M_COST, u32::MAX, 1),
        (CHEAP_M_COST, 1, 0),
        (CHEAP_M_COST, 1, MAX_ARGON_P_COST + 1),
        (CHEAP_M_COST, 1, u32::MAX),
    ]
}

#[test]
fn hostile_argon2_header_rejected_by_symmetric_file_entry() {
    let dir = ScratchDir::new("argon2_sym");
    let input = dir.join("hostile.enc");

    for (mem_kib, t_cost, p_cost) in hostile_argon2_cases() {
        let blob = pack_encrypted_blob(
            mem_kib,
            t_cost,
            p_cost,
            &[0x61u8; SALT_LEN],
            &[0x62u8; XNONCE_LEN],
            b"type=file",
            &[0x63u8; 32],
        )
        .unwrap();
        fs::write(&input, &blob).unwrap();

        let out = dir.join(format!("out_{mem_kib}_{t_cost}_{p_cost}.bin"));
        let err = decrypt_file_symmetric(&input, TEST_PASSWORD, Some(&out), false).unwrap_err();
        assert!(
            matches!(err, CryptError::Key(_)),
            "hostile Argon2 ({mem_kib},{t_cost},{p_cost}) must fail the parameter guard"
        );
        assert!(!out.exists(), "rejected Argon2 header must not produce output");
    }

    // force=true 时既有输出必须原样保留
    let sentinel = dir.join("sentinel.bin");
    fs::write(&sentinel, b"SENTINEL").unwrap();
    assert!(decrypt_file_symmetric(&input, TEST_PASSWORD, Some(&sentinel), true).is_err());
    assert_eq!(fs::read(&sentinel).unwrap(), b"SENTINEL");
}

#[test]
fn hostile_argon2_header_rejected_by_private_key_backup_entry() {
    let dir = ScratchDir::new("argon2_backup");
    let input = dir.join("private_hostile.asc.enc");

    for (mem_kib, t_cost, p_cost) in hostile_argon2_cases() {
        let blob = pack_encrypted_blob(
            mem_kib,
            t_cost,
            p_cost,
            &[0x71u8; SALT_LEN],
            &[0x72u8; XNONCE_LEN],
            b"fp=ABCD|type=ed25519",
            &[0x73u8; 32],
        )
        .unwrap();
        fs::write(&input, &blob).unwrap();

        let out = dir.join(format!("der_{mem_kib}_{t_cost}_{p_cost}.der"));
        let err =
            decrypt_backup_with_password(&input, TEST_PASSWORD, Some(&out), false).unwrap_err();
        assert!(
            matches!(err, CryptError::Key(_)),
            "hostile Argon2 ({mem_kib},{t_cost},{p_cost}) must fail the parameter guard"
        );
        assert!(!out.exists(), "rejected Argon2 header must not export a private key");
    }

    let sentinel = dir.join("sentinel.der");
    fs::write(&sentinel, b"SENTINEL").unwrap();
    assert!(decrypt_backup_with_password(&input, TEST_PASSWORD, Some(&sentinel), true).is_err());
    assert_eq!(fs::read(&sentinel).unwrap(), b"SENTINEL");
}

#[test]
fn hostile_argon2_header_rejected_by_pubenc_decrypt_workflow() {
    let dir = ScratchDir::new("argon2_workflow");
    // 被解密的私钥备份本身携带越界 Argon2 参数：必须在 KDF 之前拒绝，
    // 且不得因为后续 .pubenc 解析或写盘路径而泄漏任何输出。
    let key_backup = dir.join("x25519_private_hostile.asc.enc");
    let input = dir.join("document.pubenc");
    fs::write(&input, b"SCFv1 not even parsed").unwrap();

    for (mem_kib, t_cost, p_cost) in hostile_argon2_cases() {
        let blob = pack_encrypted_blob(
            mem_kib,
            t_cost,
            p_cost,
            &[0x74u8; SALT_LEN],
            &[0x75u8; XNONCE_LEN],
            b"fp=EFGH|type=x25519",
            &[0x76u8; 32],
        )
        .unwrap();
        fs::write(&key_backup, &blob).unwrap();

        let out = dir.join(format!("doc_{mem_kib}_{t_cost}_{p_cost}.bin"));
        let err = decrypt_workflow_with_password(
            &input,
            &key_backup,
            TEST_PASSWORD,
            Some(&out),
            None,
            false,
            false,
        )
        .map(|_| ())
        .unwrap_err();
        assert!(
            matches!(err, CryptError::Key(_)),
            "hostile Argon2 ({mem_kib},{t_cost},{p_cost}) must fail the parameter guard"
        );
        assert!(!out.exists(), "rejected Argon2 header must not produce output");
    }

    let sentinel = dir.join("sentinel.bin");
    fs::write(&sentinel, b"SENTINEL").unwrap();
    assert!(decrypt_workflow_with_password(
        &input,
        &key_backup,
        TEST_PASSWORD,
        Some(&sentinel),
        None,
        false,
        true,
    )
    .is_err());
    assert_eq!(fs::read(&sentinel).unwrap(), b"SENTINEL");
}

// ── 4. 解密侧对抗性失败路径 ────────────────────────────

/// 所有 `.pubenc` 解密测试共享的合法 X25519 私钥备份
struct ScfCase {
    dir: ScratchDir,
    recipient_pub: X25519PublicKey,
    eph: StaticSecret,
    key_backup: PathBuf,
}

fn scf_case(tag: &str) -> ScfCase {
    let dir = ScratchDir::new(tag);
    let recipient = StaticSecret::from([0x81u8; 32]);
    let recipient_pub = X25519PublicKey::from(&recipient);
    let key_backup = dir.join("x25519_private_test.asc.enc");
    fs::write(&key_backup, x25519_backup_fixture(&recipient.to_bytes(), &"A".repeat(64))).unwrap();
    ScfCase { dir, recipient_pub, eph: StaticSecret::from([0x82u8; 32]), key_backup }
}

impl ScfCase {
    fn run(
        &self,
        blob: &[u8],
        signer: Option<String>,
        require_signature: bool,
    ) -> impl Fn(Option<&Path>, bool) -> Result<DecryptOutcome, CryptError> + '_ {
        let input = self.dir.join("input.pubenc");
        fs::write(&input, blob).unwrap();
        move |output: Option<&Path>, force: bool| {
            decrypt_workflow_with_password(
                &input,
                &self.key_backup,
                TEST_PASSWORD,
                output,
                signer.as_deref(),
                require_signature,
                force,
            )
        }
    }
}

#[test]
fn pubenc_decrypt_rejects_low_order_ephemeral_pub() {
    let case = scf_case("low_order_eph");
    // 全零临时公钥是低阶点：任何攻击者都能算出“共享密钥”全零，
    // 因此这里连 AEAD 都按该全零密钥正常加密，只有 non-contributory 检查能拒绝它。
    let eph_zero = [0u8; 32];
    let zero_shared = [0u8; 32];
    let sym_key = Zeroizing::new(derive_symmetric_key_from_shared_secret(
        &zero_shared,
        &eph_zero,
        b"yacrypt-file-encryption-v1",
    ));
    let aad = unsigned_scf_aad(&eph_zero);
    let nonce = [0x91u8; XNONCE_LEN];
    let payload = Zeroizing::new(b"forged low-order payload".to_vec());
    let ciphertext = encrypt_with_aad(&sym_key, &nonce, &payload, aad.as_bytes()).unwrap();
    let blob = pack_pubenc_blob(&eph_zero, &nonce, aad.as_bytes(), &ciphertext, None).unwrap();

    assert_no_write_and_sentinel_preserved(case.run(&blob, None, false), case.dir.path());
}

#[test]
fn pubenc_decrypt_rejects_independently_invalid_signature() {
    let case = scf_case("invalid_sig");
    let signing_key = SigningKey::from_bytes(&[0x93u8; 32]);
    let vk = signing_key.verifying_key().to_bytes();
    let eph_pub = X25519PublicKey::from(&case.eph).to_bytes();

    let payload = Zeroizing::new(b"authentic payload".to_vec());
    // 结构合法但签名针对另一段数据：只有签名验证本身能拒绝它
    let wrong_signature = signing_key.sign(b"a different payload").to_bytes();
    let blob = scf_fixture(
        &case.recipient_pub,
        &case.eph,
        &signed_scf_aad(&eph_pub, &vk),
        &payload,
        Some(PubencSignature { verifying_key: vk, signature: wrong_signature }),
    );
    let vk_fp = crate::utils::compute_fingerprint(&vk);

    assert_no_write_and_sentinel_preserved(case.run(&blob, Some(vk_fp), true), case.dir.path());
}

#[test]
fn pubenc_decrypt_rejects_aad_header_ephemeral_mismatch() {
    let case = scf_case("aad_mismatch");
    let payload = Zeroizing::new(b"header mismatch payload".to_vec());

    // AAD 声明的是另一个临时公钥；AEAD 用该 AAD 正常加密，因此只有头部一致性检查能拒绝它
    let forged_aad = unsigned_scf_aad(&[0xEEu8; 32]);
    let blob = scf_fixture(&case.recipient_pub, &case.eph, &forged_aad, &payload, None);

    assert_no_write_and_sentinel_preserved(case.run(&blob, None, false), case.dir.path());
}

#[test]
fn pubenc_decrypt_rejects_missing_required_signature() {
    let case = scf_case("require_sig");
    let eph_pub = X25519PublicKey::from(&case.eph).to_bytes();
    let payload = Zeroizing::new(b"unsigned but valid payload".to_vec());
    let blob =
        scf_fixture(&case.recipient_pub, &case.eph, &unsigned_scf_aad(&eph_pub), &payload, None);

    // 显式要求签名
    assert_no_write_and_sentinel_preserved(case.run(&blob, None, true), case.dir.path());
    // 指定信任锚隐含要求签名
    let anchor = crate::utils::compute_fingerprint(&[0xAAu8; 32]);
    assert_no_write_and_sentinel_preserved(case.run(&blob, Some(anchor), false), case.dir.path());
}

#[test]
fn pubenc_decrypt_rejects_stripped_signature_block() {
    let case = scf_case("stripped_sig");
    let eph_pub = X25519PublicKey::from(&case.eph).to_bytes();
    let payload = Zeroizing::new(b"stripped signature payload".to_vec());
    // AAD 声称 flags=01 且带 sig_vk，但二进制头里签名块被删除
    let lying_aad = signed_scf_aad(&eph_pub, &[0xBBu8; 32]);
    let blob = scf_fixture(&case.recipient_pub, &case.eph, &lying_aad, &payload, None);

    assert_no_write_and_sentinel_preserved(case.run(&blob, None, false), case.dir.path());
}

#[test]
fn pubenc_decrypt_positive_controls_unsigned_and_signed() {
    let case = scf_case("positive_control");
    let eph_pub = X25519PublicKey::from(&case.eph).to_bytes();
    let payload = Zeroizing::new(b"positive control payload".to_vec());

    // 正例 1：无签名文件在未要求签名时必须成功解密并落盘
    let unsigned_blob =
        scf_fixture(&case.recipient_pub, &case.eph, &unsigned_scf_aad(&eph_pub), &payload, None);
    let input = case.dir.join("unsigned.pubenc");
    fs::write(&input, &unsigned_blob).unwrap();
    let out = case.dir.join("unsigned.out");
    let outcome = decrypt_workflow_with_password(
        &input,
        &case.key_backup,
        TEST_PASSWORD,
        Some(&out),
        None,
        false,
        false,
    )
    .unwrap();
    assert_eq!(outcome.verified_signer_fingerprint, None);
    assert_eq!(fs::read(&out).unwrap(), payload.to_vec());

    // 正例 2：签名文件在信任锚匹配时成功解密并返回签名者指纹
    let signing_key = SigningKey::from_bytes(&[0xCCu8; 32]);
    let vk = signing_key.verifying_key().to_bytes();
    let signed_blob = scf_fixture(
        &case.recipient_pub,
        &case.eph,
        &signed_scf_aad(&eph_pub, &vk),
        &payload,
        Some(PubencSignature {
            verifying_key: vk,
            signature: signing_key.sign(&payload).to_bytes(),
        }),
    );
    let signed_input = case.dir.join("signed.pubenc");
    fs::write(&signed_input, &signed_blob).unwrap();
    let signed_out = case.dir.join("signed.out");
    let expected_fp = crate::utils::compute_fingerprint(&vk);
    let outcome = decrypt_workflow_with_password(
        &signed_input,
        &case.key_backup,
        TEST_PASSWORD,
        Some(&signed_out),
        Some(&expected_fp),
        true,
        false,
    )
    .unwrap();
    assert_eq!(outcome.verified_signer_fingerprint, Some(expected_fp));
    assert_eq!(fs::read(&signed_out).unwrap(), payload.to_vec());
}

#[test]
fn sgpg_symmetric_decrypt_rejects_key_backup_and_preserves_existing_output() {
    let dir = ScratchDir::new("sgpg_domain_sep");
    let backup = dir.join("private_test.asc.enc");
    fs::write(&backup, x25519_backup_fixture(&[0xE1u8; 32], &"D".repeat(64))).unwrap();

    let absent = dir.join("must_not_exist.bin");
    let err = decrypt_file_symmetric(&backup, TEST_PASSWORD, Some(&absent), false).unwrap_err();
    assert!(matches!(err, CryptError::Key(_)), "key backup must not decrypt as a regular file");
    assert!(!absent.exists());

    let sentinel = dir.join("sentinel.bin");
    fs::write(&sentinel, b"SENTINEL").unwrap();
    assert!(decrypt_file_symmetric(&backup, TEST_PASSWORD, Some(&sentinel), true).is_err());
    assert_eq!(fs::read(&sentinel).unwrap(), b"SENTINEL");

    // 正例对照：真正的 type=file 容器仍可解密
    let file_blob = sgpg_fixture("type=file", b"symmetric positive control");
    let enc = dir.join("notes.enc");
    fs::write(&enc, &file_blob).unwrap();
    let out = dir.join("notes.out");
    assert_eq!(decrypt_file_symmetric(&enc, TEST_PASSWORD, Some(&out), false).unwrap(), out);
    assert_eq!(fs::read(&out).unwrap(), b"symmetric positive control");
}

// ── 5. AAD 重复键兼容策略（仅记录，不改协议行为）────────

#[test]
fn aad_duplicate_key_policy_is_last_wins_and_aead_binds_raw_bytes() {
    // 兼容策略：重复键被接受，后出现的值覆盖先出现的值（last-wins）
    let map = parse_aad_map(b"type=ed25519|type=file").unwrap();
    assert_eq!(map.get("type").map(String::as_str), Some("file"));

    // 这不是 AEAD 绕过：认证绑定的是原始字节序列，而不是解析后的 map
    let key = [0xF1u8; 32];
    let nonce = [0xF2u8; XNONCE_LEN];
    let duplicated_aad = b"type=file|type=file";
    let single_aad = b"type=file";
    assert_eq!(parse_aad_map(duplicated_aad).unwrap(), parse_aad_map(single_aad).unwrap());

    let plaintext = Zeroizing::new(b"duplicate aad payload".to_vec());
    let ct = encrypt_with_aad(&key, &nonce, &plaintext, duplicated_aad).unwrap();
    assert_eq!(decrypt_with_aad(&key, &nonce, &ct, duplicated_aad).unwrap(), plaintext.to_vec());
    assert!(
        matches!(decrypt_with_aad(&key, &nonce, &ct, single_aad), Err(CryptError::Crypto(_))),
        "identical parsed AAD map with different raw bytes must fail authentication"
    );
}
