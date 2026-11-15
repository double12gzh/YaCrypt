use base64::{engine::general_purpose, Engine as _};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

fn yacrypt_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_yacrypt"))
}

fn isolated_cmd(dir: &Path) -> Command {
    let home = dir.join("_test_home");
    let _ = fs::create_dir_all(&home);
    let mut cmd = Command::new(yacrypt_bin());
    cmd.current_dir(dir).env("HOME", &home).env_remove("YACRYPT_KEYSTORE");
    cmd
}

fn find_single_file_with_ext(dir: &Path, ext: &str) -> PathBuf {
    let matches: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|entry| entry.path()))
        .filter(|p| p.is_file() && p.extension().and_then(|s| s.to_str()) == Some(ext))
        .collect();
    assert_eq!(matches.len(), 1, "expected 1 .{} file in {:?}, got {:?}", ext, dir, matches);
    matches.into_iter().next().unwrap()
}

#[test]
fn cli_gen_password_and_bounds() {
    let out = Command::new(yacrypt_bin()).arg("gen-password").output().unwrap();
    assert!(out.status.success());
    let pw = String::from_utf8(out.stdout).unwrap();
    assert_eq!(pw.trim().len(), 32);

    let out_custom =
        Command::new(yacrypt_bin()).args(["gen-password", "--length", "48"]).output().unwrap();
    assert!(out_custom.status.success());
    assert_eq!(String::from_utf8(out_custom.stdout).unwrap().trim().len(), 48);

    let out_zero =
        Command::new(yacrypt_bin()).args(["gen-password", "--length", "0"]).output().unwrap();
    assert!(!out_zero.status.success());
}

#[test]
fn cli_encrypt_with_key_safe_write_semantics_and_no_cleartext_filename_leak() {
    let dir = std::env::temp_dir().join(format!("yacrypt_cli_e2e_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    // Generate valid X25519 public key
    let secret = StaticSecret::from([0x42u8; 32]);
    let pubkey = X25519PublicKey::from(&secret);
    let pub_path = dir.join("x25519_public_test.asc");
    fs::write(&pub_path, general_purpose::STANDARD.encode(pubkey.to_bytes())).unwrap();

    // Create input file with distinctive name to check M-3 cleartext leak & anonymous output naming
    let input_path = dir.join("confidential_salary_2026.txt");
    fs::write(&input_path, b"top secret payload").unwrap();

    let enc = isolated_cmd(&dir)
        .args([
            "encrypt-file-with-key",
            "--input",
            input_path.to_str().unwrap(),
            "--public-key",
            pub_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(enc.status.success(), "stderr: {}", String::from_utf8_lossy(&enc.stderr));
    let out_pubenc = find_single_file_with_ext(&dir, "pubenc");
    let out_fname = out_pubenc.file_name().unwrap().to_string_lossy();
    assert!(
        !out_fname.contains("confidential")
            && !out_fname.contains("salary")
            && !out_fname.contains("2026"),
        "default pubenc output filename must be anonymous, got: {}",
        out_fname
    );
    assert!(!dir.join("confidential_salary_2026.txt.pubenc").exists());

    // Verify 0600 permissions
    let mode = fs::metadata(&out_pubenc).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    // M-3: Verify cleartext filename is NOT leaked in the .pubenc blob
    let raw_blob = fs::read(&out_pubenc).unwrap();
    let blob_lossy = String::from_utf8_lossy(&raw_blob);
    assert!(
        !blob_lossy.contains("confidential_salary_2026.txt"),
        "cleartext filename leaked in pubenc blob"
    );
    // M-3 复审收口（2026-10-18）：AAD 不再携带 file_sha256/id_sha256 等可被字典还原的低熵摘要
    assert!(!blob_lossy.contains("file_sha256="), "low-entropy metadata digest present in AAD");
    assert!(!blob_lossy.contains("id_sha256="), "low-entropy metadata digest present in AAD");

    // M-4(1): Default refuses to overwrite existing file
    let enc_overwrite = isolated_cmd(&dir)
        .args([
            "encrypt-file-with-key",
            "--input",
            input_path.to_str().unwrap(),
            "--public-key",
            pub_path.to_str().unwrap(),
            "--output",
            out_pubenc.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!enc_overwrite.status.success());

    // M-4(2): --force overwrites existing 0644 file AND tightens permissions to 0600
    let pre_existing_644 = dir.join("pre_existing_644.pubenc");
    fs::write(&pre_existing_644, b"old data").unwrap();
    fs::set_permissions(&pre_existing_644, fs::Permissions::from_mode(0o644)).unwrap();

    let enc_forced = isolated_cmd(&dir)
        .args([
            "encrypt-file-with-key",
            "--input",
            input_path.to_str().unwrap(),
            "--public-key",
            pub_path.to_str().unwrap(),
            "--output",
            pre_existing_644.to_str().unwrap(),
            "--force",
        ])
        .output()
        .unwrap();
    assert!(enc_forced.status.success());
    let forced_mode = fs::metadata(&pre_existing_644).unwrap().permissions().mode() & 0o777;
    assert_eq!(forced_mode, 0o600);

    // M-4(3): Symlink output is refused even with --force
    let real_target = dir.join("real_target.bin");
    fs::write(&real_target, b"DO NOT TOUCH").unwrap();
    let symlink_out = dir.join("symlink_out.pubenc");
    std::os::unix::fs::symlink(&real_target, &symlink_out).unwrap();

    let enc_symlink = isolated_cmd(&dir)
        .args([
            "encrypt-file-with-key",
            "--input",
            input_path.to_str().unwrap(),
            "--public-key",
            pub_path.to_str().unwrap(),
            "--output",
            symlink_out.to_str().unwrap(),
            "--force",
        ])
        .output()
        .unwrap();
    assert!(!enc_symlink.status.success());
    assert_eq!(fs::read(&real_target).unwrap(), b"DO NOT TOUCH");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_rejects_low_order_x25519_public_key_l1() {
    let dir = std::env::temp_dir().join(format!("yacrypt_cli_l1_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    // All-zero X25519 public key (low-order point)
    let zero_pub_path = dir.join("zero_pub.asc");
    fs::write(&zero_pub_path, general_purpose::STANDARD.encode([0u8; 32])).unwrap();

    let input_path = dir.join("input.txt");
    fs::write(&input_path, b"hello").unwrap();
    let out_path = dir.join("out.pubenc");

    let res = isolated_cmd(&dir)
        .args([
            "encrypt-file-with-key",
            "--input",
            input_path.to_str().unwrap(),
            "--public-key",
            zero_pub_path.to_str().unwrap(),
            "--output",
            out_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!res.status.success());
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(stderr.contains("low-order point") || stderr.contains("non-contributory"));
    // Human-readable Display error formatting (no Rust Debug struct dump; allow preceding mlockall warning on Linux)
    assert!(
        stderr.lines().any(|line| line.starts_with("Error: ")),
        "stderr should use Display prefix: {}",
        stderr
    );
    assert!(!out_path.exists());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_help_does_not_claim_libsodium_i2() {
    let out = Command::new(yacrypt_bin()).arg("--help").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.to_lowercase().contains("libsodium"));
}

/// Pure-Rust PTY helper to drive interactive `dialoguer` prompts in E2E tests (with isolated HOME)
fn run_with_pty(
    cwd: &std::path::Path,
    args: &[&str],
    prompts_and_replies: &[(&str, &str)],
) -> (i32, Option<i32>, String) {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::process::{CommandExt, ExitStatusExt};

    let home = cwd.join("_test_home");
    let _ = fs::create_dir_all(&home);

    let mut master_fd: libc::c_int = -1;
    let mut slave_fd: libc::c_int = -1;
    let rc = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty failed");

    let slave_in = unsafe { fs::File::from_raw_fd(libc::dup(slave_fd)) };
    let slave_out = unsafe { fs::File::from_raw_fd(libc::dup(slave_fd)) };
    let slave_err = unsafe { fs::File::from_raw_fd(slave_fd) };

    let mut cmd = Command::new(yacrypt_bin());
    cmd.current_dir(cwd)
        .env("HOME", &home)
        .env_remove("YACRYPT_KEYSTORE")
        .args(args)
        .stdin(slave_in)
        .stdout(slave_out)
        .stderr(slave_err);
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            libc::ioctl(0, libc::TIOCSCTTY as _, 0);
            Ok(())
        });
    }

    let mut child = cmd.spawn().unwrap();
    drop(cmd); // closes slave fds in parent

    let mut master = unsafe { fs::File::from_raw_fd(master_fd) };
    // Set non-blocking read on master_fd
    unsafe {
        let flags = libc::fcntl(master_fd, libc::F_GETFL);
        libc::fcntl(master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let mut transcript = String::new();
    let mut search_offset = 0usize;
    let mut prompt_idx = 0;
    let mut buf = [0u8; 1024];
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > std::time::Duration::from_secs(20) {
            let _ = child.kill();
            panic!(
                "run_with_pty timed out after 20s waiting for prompt {:?}; transcript so far:\n{}",
                prompts_and_replies.get(prompt_idx),
                transcript
            );
        }
        match master.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                transcript.push_str(&String::from_utf8_lossy(&buf[..n]));
                while prompt_idx < prompts_and_replies.len() {
                    let (expected, reply) = prompts_and_replies[prompt_idx];
                    if let Some(rel_pos) = transcript[search_offset..].find(expected) {
                        search_offset += rel_pos + expected.len();
                        std::thread::sleep(std::time::Duration::from_millis(25));
                        let _ = master.write_all(format!("{}\n", reply).as_bytes());
                        let _ = master.flush();
                        prompt_idx += 1;
                    } else {
                        break;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if let Ok(Some(_)) = child.try_wait() {
                    // Drain any remaining bytes
                    while let Ok(n) = master.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        transcript.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(15));
            }
            Err(_) => break,
        }
    }

    let status = child.wait().unwrap();
    (status.code().unwrap_or(-1), status.signal(), transcript)
}

#[test]
fn cli_full_interactive_workflow_and_attack_pocs() {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use hkdf::Hkdf;
    use sha2::Sha256;

    let dir = std::env::temp_dir().join(format!("yacrypt_pty_e2e_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    // 1. Encrypt signed workflow — 默认路径：无 ./keystore 时写入 ~/.yacrypt/keystore (0700)，
    //    显式 --label 仅写入本地 0600 labels.tsv，绝不进入密文或恢复说明 (M-3)
    let f2_path = dir.join("f2.txt");
    fs::write(&f2_path, b"top secret doc 2").unwrap();

    let user_pw = "pty-test-password-1";
    let (code, sig, out) = run_with_pty(
        &dir,
        &["encrypt", "f2.txt", "--label", "BobSecretAlias"],
        &[
            ("Auto-generate backup encryption password", "n"),
            ("Enter backup encryption password", user_pw),
            ("Confirm password", user_pw),
        ],
    );
    assert_eq!(sig, None);
    assert_eq!(code, 0, "encrypt failed: {}", out);
    let pw = user_pw.to_string();
    // 默认路径不得把任何口令打印到 stdout（复审 P2）
    assert!(
        !out.contains("Backup password generated:"),
        "default path must not print a backup password to stdout: {}",
        out
    );

    let fp = out
        .lines()
        .find_map(|l| l.split("Fingerprint:").nth(1).map(|s| s.trim().to_string()))
        .unwrap();
    assert_eq!(fp.len(), 64);

    let default_ks = dir.join("_test_home/.yacrypt/keystore");
    assert_eq!(
        fs::metadata(dir.join("_test_home/.yacrypt")).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(fs::metadata(&default_ks).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(default_ks.join("labels.tsv")).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // M-3: Verify keystore private key blobs and .pubenc do NOT leak label or filename
    let ed_priv_path = default_ks.join(format!("private_{}.asc.enc", fp));
    let x_priv_path = default_ks.join(format!("x25519_private_{}.asc.enc", fp));
    let ed_priv_raw = fs::read(&ed_priv_path).unwrap();
    let ed_priv_str = String::from_utf8_lossy(&ed_priv_raw);
    assert!(!ed_priv_str.contains("BobSecretAlias"));
    assert!(
        !ed_priv_str.contains("id_sha256="),
        "low-entropy identity digest leaked in keystore blob"
    );

    let pubenc_file = find_single_file_with_ext(&dir, "pubenc");
    let pubenc_fname = pubenc_file.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        !pubenc_fname.contains("f2.txt"),
        "default pubenc output filename must be anonymous, got {}",
        pubenc_fname
    );
    assert!(
        !String::from_utf8_lossy(&fs::read(&pubenc_file).unwrap()).contains("BobSecretAlias"),
        "local label must never enter .pubenc"
    );

    // Privacy default: .decrypt.txt is NOT created unless --instructions is passed
    let default_companion = dir.join(format!("{}.decrypt.txt", pubenc_fname));
    assert!(!default_companion.exists(), "default encrypt must NOT write companion .decrypt.txt");

    // Explicit --instructions writes .decrypt.txt recording only file_name(), never local directory paths
    let explicit_pubenc = dir.join("explicit_instr.pubenc");
    let (code_instr, _, out_instr) = run_with_pty(
        &dir,
        &[
            "encrypt",
            "f2.txt",
            "--key",
            "BobSecretAlias",
            "-o",
            explicit_pubenc.to_str().unwrap(),
            "--instructions",
        ],
        &[],
    );
    assert_eq!(code_instr, 0, "encrypt --instructions failed: {}", out_instr);
    let companion_instr = dir.join("explicit_instr.pubenc.decrypt.txt");
    let companion_text = fs::read_to_string(&companion_instr).unwrap();
    assert!(companion_text.contains("explicit_instr.pubenc"));
    assert!(
        !companion_text.contains("_test_home"),
        "companion instructions leaked local directory"
    );

    // Default `decrypt` on unsigned .pubenc MUST fail unless --allow-unsigned is passed
    let unsigned_fail = dir.join("unsigned_fail_out.txt");
    let (c_unsig_fail, _, out_unsig_fail) = run_with_pty(
        &dir,
        &[
            "decrypt",
            explicit_pubenc.to_str().unwrap(),
            "--private-key",
            "BobSecretAlias",
            "-o",
            unsigned_fail.to_str().unwrap(),
        ],
        &[("Enter private key password", &pw)],
    );
    assert_ne!(c_unsig_fail, 0, "unsigned .pubenc must be rejected by default");
    assert!(out_unsig_fail.contains("no embedded signature"));
    assert!(!unsigned_fail.exists());

    let (c_unsig_ok, _, out_unsig_ok) = run_with_pty(
        &dir,
        &[
            "decrypt",
            explicit_pubenc.to_str().unwrap(),
            "--private-key",
            "BobSecretAlias",
            "--allow-unsigned",
            "-o",
            unsigned_fail.to_str().unwrap(),
        ],
        &[("Enter private key password", &pw)],
    );
    assert_eq!(c_unsig_ok, 0, "decrypt --allow-unsigned failed: {}", out_unsig_ok);
    assert_eq!(fs::read(&unsigned_fail).unwrap(), b"top secret doc 2");
    fs::remove_file(&explicit_pubenc).unwrap();
    fs::remove_file(&companion_instr).unwrap();
    fs::remove_file(&unsigned_fail).unwrap();

    // M-3 复审收口：恢复说明文件不再包含明文身份字段，但保留指纹与用法
    let instr_path = default_ks.join(format!("recovery_instructions_{}.txt", fp));
    let instr = fs::read_to_string(&instr_path).unwrap();
    assert!(!instr.contains("BobSecretAlias"));
    assert!(instr.contains(&format!("Fingerprint: {}", fp)));

    // 2. Decrypt valid signed file using local label (--private-key BobSecretAlias) -> succeeds
    let dec_out = dir.join("f2_decrypted.txt");
    let (code, sig, out_dec) = run_with_pty(
        &dir,
        &[
            "decrypt",
            pubenc_file.to_str().unwrap(),
            "--private-key",
            "BobSecretAlias",
            "--output",
            dec_out.to_str().unwrap(),
        ],
        &[("Enter private key password", &pw)],
    );
    assert_eq!(sig, None);
    assert_eq!(code, 0, "decrypt failed: {}", out_dec);
    assert!(out_dec.contains(&format!("signer fingerprint: {}", fp)));
    assert_eq!(fs::read(&dec_out).unwrap(), b"top secret doc 2");

    // 3. Verify SCFv2 outer privacy invariants (hidden signature, hidden signer fingerprint, padded size)
    //    AND preserve explicit legacy SCFv1 roundtrip + M-1 PoC (poc_strip)
    let signed_bytes = fs::read(&pubenc_file).unwrap();
    assert_eq!(&signed_bytes[..5], b"SCFv2");
    assert_eq!(signed_bytes[5], 0x00);
    assert!(signed_bytes.len() > 1024, "SCFv2 should include length-hiding padding");
    assert!(
        !String::from_utf8_lossy(&signed_bytes).contains(&fp),
        "SCFv2 must not leak signer fingerprint in outer blob"
    );
    let ed_pub_b64 = fs::read_to_string(default_ks.join(format!("public_{}.asc", fp))).unwrap();
    let ed_pub_bytes = general_purpose::STANDARD.decode(ed_pub_b64.trim()).unwrap();
    assert!(
        !signed_bytes.windows(32).any(|w| w == ed_pub_bytes.as_slice()),
        "SCFv2 must not expose Ed25519 verifying key in plaintext"
    );

    let insp_v2 =
        isolated_cmd(&dir).args(["inspect", pubenc_file.to_str().unwrap()]).output().unwrap();
    assert!(insp_v2.status.success());
    let insp_v2_out = String::from_utf8_lossy(&insp_v2.stdout);
    assert!(insp_v2_out.contains("SCFv2 (Hybrid Public-Key Encrypted File)"));
    assert!(insp_v2_out.contains("Concealed inside AEAD payload"));
    assert!(insp_v2_out.contains("Enabled (Length-Hiding Random + Padme)"));
    assert!(!insp_v2_out.contains(&fp));

    // Legacy SCFv1 backward-compatibility roundtrip + M-1 PoC (poc_strip)
    let x_pub_b64_v1 =
        fs::read_to_string(default_ks.join(format!("x25519_public_{}.asc", fp))).unwrap();
    let bob_pub_v1: [u8; 32] =
        general_purpose::STANDARD.decode(x_pub_b64_v1.trim()).unwrap().try_into().unwrap();
    let bob_ed_sk = yacrypt_core::keystore::load_signing_key_with_password(
        &default_ks.join(format!("private_{}.asc.enc", fp)),
        &pw,
    )
    .unwrap();
    let v1_eph_sec = StaticSecret::from([0x42u8; 32]);
    let v1_eph_pub = X25519PublicKey::from(&v1_eph_sec);
    let v1_shared = v1_eph_sec.diffie_hellman(&X25519PublicKey::from(bob_pub_v1));
    let v1_sym = yacrypt_core::crypto::derive_symmetric_key_from_shared_secret(
        v1_shared.as_bytes(),
        &v1_eph_pub.to_bytes(),
        b"yacrypt-file-encryption-v1",
    );
    let v1_nonce = [0x19u8; 24];
    let v1_payload = b"legacy scfv1 plaintext";
    let v1_sig = ed25519_dalek::Signer::sign(&bob_ed_sk, v1_payload);
    let v1_vk = bob_ed_sk.verifying_key().to_bytes();
    let v1_aad = format!(
        "flags=01|ephemeral_pub={}|sig_vk={}",
        hex::encode(v1_eph_pub.to_bytes()),
        hex::encode(v1_vk)
    );
    let v1_ct =
        yacrypt_core::crypto::encrypt_with_aad(&v1_sym, &v1_nonce, v1_payload, v1_aad.as_bytes())
            .unwrap();
    let v1_signed_bytes = yacrypt_core::crypto::pack_pubenc_blob(
        &v1_eph_pub.to_bytes(),
        &v1_nonce,
        v1_aad.as_bytes(),
        &v1_ct,
        Some(&yacrypt_core::crypto::PubencSignature {
            verifying_key: v1_vk,
            signature: v1_sig.to_bytes(),
        }),
    )
    .unwrap();
    fs::write(dir.join("legacy_v1.pubenc"), &v1_signed_bytes).unwrap();
    let (code_v1, sig_v1, out_v1) = run_with_pty(
        &dir,
        &[
            "decrypt",
            "legacy_v1.pubenc",
            "--private-key",
            "BobSecretAlias",
            "-o",
            "legacy_v1_out.txt",
        ],
        &[("Enter private key password", &pw)],
    );
    assert_eq!(sig_v1, None);
    assert_eq!(code_v1, 0, "legacy SCFv1 decrypt failed: {}", out_v1);
    assert_eq!(fs::read(dir.join("legacy_v1_out.txt")).unwrap(), v1_payload);

    let mut stripped_bytes = Vec::new();
    stripped_bytes.extend_from_slice(b"SCFv1\x00");
    stripped_bytes.extend_from_slice(&v1_signed_bytes[6 + 96..]);
    fs::write(dir.join("f2strip.pubenc"), &stripped_bytes).unwrap();

    let (code_strip, sig_strip, out_strip) = run_with_pty(
        &dir,
        &["decrypt", "f2strip.pubenc", "--private-key", x_priv_path.to_str().unwrap()],
        &[("Enter private key password", &pw)],
    );
    assert_eq!(sig_strip, None);
    assert_ne!(code_strip, 0, "stripped file should be rejected: {}", out_strip);
    assert!(out_strip.contains("Signature stripped"));
    assert!(!dir.join("f2strip").exists());

    // 4. H-1 PoC (poc_forge): Attacker knows ONLY victim's X25519 public key and signs with attacker's Ed25519 key -> MUST REJECT!
    let x_pub_b64 =
        fs::read_to_string(default_ks.join(format!("x25519_public_{}.asc", fp))).unwrap();
    let victim_pub_bytes: [u8; 32] =
        general_purpose::STANDARD.decode(x_pub_b64.trim()).unwrap().try_into().unwrap();
    let victim_pub = X25519PublicKey::from(victim_pub_bytes);

    let eph_sec = StaticSecret::from([0x55u8; 32]);
    let eph_pub = X25519PublicKey::from(&eph_sec);
    let shared = eph_sec.diffie_hellman(&victim_pub);
    let hk = Hkdf::<Sha256>::new(Some(&eph_pub.to_bytes()), shared.as_bytes());
    let mut sym_key = [0u8; 32];
    hk.expand(b"yacrypt-file-encryption-v1", &mut sym_key).unwrap();

    let attacker_sk = SigningKey::from_bytes(&[0x77u8; 32]);
    let attacker_vk = attacker_sk.verifying_key().to_bytes();
    let forged_payload = b"FORGED CONTENT: attacker payload";
    let attacker_sig = attacker_sk.sign(forged_payload).to_bytes();
    let forged_aad = format!(
        "file=forged.txt|ephemeral_pub={}|sig_vk={}",
        hex::encode(eph_pub.to_bytes()),
        hex::encode(attacker_vk)
    );
    let forged_nonce = [0x33u8; 24];
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&sym_key));
    let forged_ct = cipher
        .encrypt(
            XNonce::from_slice(&forged_nonce),
            chacha20poly1305::aead::Payload { msg: forged_payload, aad: forged_aad.as_bytes() },
        )
        .unwrap();

    let mut forged_blob = Vec::new();
    forged_blob.extend_from_slice(b"SCFv1\x01");
    forged_blob.extend_from_slice(&attacker_vk);
    forged_blob.extend_from_slice(&attacker_sig);
    forged_blob.extend_from_slice(&eph_pub.to_bytes());
    forged_blob.extend_from_slice(&forged_nonce);
    forged_blob.extend_from_slice(&(forged_aad.len() as u16).to_be_bytes());
    forged_blob.extend_from_slice(forged_aad.as_bytes());
    forged_blob.extend_from_slice(&(forged_ct.len() as u64).to_be_bytes());
    forged_blob.extend_from_slice(&forged_ct);
    fs::write(dir.join("forged.pubenc"), &forged_blob).unwrap();

    let (code_forge, sig_forge, out_forge) = run_with_pty(
        &dir,
        &["decrypt", "forged.pubenc", "--private-key", x_priv_path.to_str().unwrap()],
        &[("Enter private key password", &pw)],
    );
    assert_eq!(sig_forge, None);
    assert_ne!(code_forge, 0, "forged file must be rejected: {}", out_forge);
    assert!(out_forge.contains("untrusted signer fingerprint"));
    assert!(!dir.join("forged").exists());

    // 5. M-2(a) & M-2(b): Malformed nonce_len=23 and ct_len=u64::MAX must exit cleanly with code != 0 and NO signal/abort
    let mut bad_nonce = Vec::new();
    bad_nonce.extend_from_slice(b"SGPGv1");
    bad_nonce.extend_from_slice(&256u32.to_be_bytes());
    bad_nonce.extend_from_slice(&1u32.to_be_bytes());
    bad_nonce.extend_from_slice(&1u32.to_be_bytes());
    bad_nonce.push(16);
    bad_nonce.extend_from_slice(&[0u8; 16]);
    bad_nonce.push(23);
    bad_nonce.extend_from_slice(&[0u8; 23]);
    bad_nonce.extend_from_slice(&0u16.to_be_bytes());
    bad_nonce.extend_from_slice(&40u64.to_be_bytes());
    bad_nonce.extend_from_slice(&[0u8; 40]);
    fs::write(dir.join("bad_nonce.enc"), &bad_nonce).unwrap();

    let (code_bn, sig_bn, out_bn) = run_with_pty(
        &dir,
        &["decrypt-private-key", "bad_nonce.enc", "-o", "bn.der"],
        &[("Enter backup password", "anypassword123")],
    );
    assert_eq!(sig_bn, None, "process panicked/aborted on bad_nonce.enc: {}", out_bn);
    assert_ne!(code_bn, 0);

    let mut bad_ctlen = Vec::new();
    bad_ctlen.extend_from_slice(b"SCFv1\x00");
    bad_ctlen.extend_from_slice(&[0u8; 32]);
    bad_ctlen.extend_from_slice(&[0u8; 24]);
    bad_ctlen.extend_from_slice(&0u16.to_be_bytes());
    bad_ctlen.extend_from_slice(&u64::MAX.to_be_bytes());
    bad_ctlen.extend_from_slice(b"JUNK");
    fs::write(dir.join("bad_ctlen.pubenc"), &bad_ctlen).unwrap();

    let (code_bc, sig_bc, out_bc) = run_with_pty(
        &dir,
        &["decrypt", "bad_ctlen.pubenc", "--private-key", x_priv_path.to_str().unwrap()],
        &[("Enter private key password", &pw)],
    );
    assert_eq!(sig_bc, None, "process panicked/aborted on bad_ctlen.pubenc: {}", out_bc);
    assert_ne!(code_bc, 0);

    // 6. L-5 & Phase 3.1: decrypt-private-key rejects X25519 key backup, accepts Ed25519 key backup and defaults to .der (not .asc.der)
    let (code_l5_bad, sig_l5_bad, out_l5_bad) = run_with_pty(
        &dir,
        &["decrypt-private-key", x_priv_path.to_str().unwrap(), "-o", "x.der"],
        &[("Enter backup password", &pw)],
    );
    assert_eq!(sig_l5_bad, None);
    assert_ne!(code_l5_bad, 0);
    assert!(out_l5_bad.contains("Cannot export 'x25519' key as PKCS#8 DER"));
    assert!(!dir.join("x.der").exists());

    let (code_l5_ok, sig_l5_ok, _) = run_with_pty(
        &dir,
        &["decrypt-private-key", ed_priv_path.to_str().unwrap()],
        &[("Enter backup password", &pw)],
    );
    assert_eq!(sig_l5_ok, None);
    assert_eq!(code_l5_ok, 0);
    assert!(dir.join(format!("private_{}.der", fp)).exists());
    assert!(!dir.join(format!("private_{}.asc.der", fp)).exists());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_encrypt_failure_rolls_back_fresh_keypair_and_preflight_blocks_early() {
    let dir = std::env::temp_dir().join(format!("yacrypt_rollback_e2e_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("keystore")).unwrap(); // pre-existing ./keystore takes priority
    fs::write(dir.join("f.txt"), b"rollback test").unwrap();

    // 1. 第一次运行（默认自动生成强口令：直接回车确认默认 true）：成功，./keystore 写入 5 个文件
    let (code1, sig1, out1) = run_with_pty(
        &dir,
        &["encrypt", "f.txt"],
        &[("Auto-generate backup encryption password", "")],
    );
    assert_eq!(sig1, None);
    assert_eq!(code1, 0, "first encrypt failed: {}", out1);
    assert!(out1.contains("Backup password generated:"));
    let count1 = fs::read_dir(dir.join("keystore")).unwrap().count();
    assert_eq!(count1, 5);
    let first_pubenc = find_single_file_with_ext(&dir, "pubenc");

    // 2. 前置冲突预检（Phase 0.4）：指定已存在目标且无 --force 时，必须在提示口令与生成密钥前立即报错拦截！
    let preflight_conflict = isolated_cmd(&dir)
        .args(["encrypt", "f.txt", "-o", first_pubenc.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!preflight_conflict.status.success());
    assert!(String::from_utf8_lossy(&preflight_conflict.stderr).contains("already exists"));
    assert_eq!(fs::read_dir(dir.join("keystore")).unwrap().count(), count1);

    // 3. 步骤 2 失败回滚：目标输出父目录不存在（通过前置 exists 检查，但在步骤 2 落盘时失败），新生成的密钥与 label 均回滚
    let (code2, sig2, out2) = run_with_pty(
        &dir,
        &["encrypt", "f.txt", "--label", "transient-key", "-o", "missing_dir/out.pubenc"],
        &[("Auto-generate backup encryption password", "y")],
    );
    assert_eq!(sig2, None);
    assert_ne!(code2, 0, "second encrypt should fail: {}", out2);
    assert!(out2.contains("rolled back"), "rollback note missing: {}", out2);
    let count2 = fs::read_dir(dir.join("keystore")).unwrap().count();
    assert_eq!(count2, count1, "fresh keypair files or labels.tsv were not rolled back");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_inspect_key_list_and_symmetric_mode() {
    let dir = std::env::temp_dir().join(format!("yacrypt_sym_inspect_e2e_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("keystore")).unwrap();

    // 1. Symmetric encrypt (-c)
    fs::write(dir.join("notes.txt"), b"symmetric payload 2026").unwrap();
    let sym_pw = "sym-pass-12345";
    let (code_enc, sig_enc, out_enc) = run_with_pty(
        &dir,
        &["encrypt", "notes.txt", "-c"],
        &[("Enter encryption password", sym_pw), ("Confirm password", sym_pw)],
    );
    assert_eq!(sig_enc, None);
    assert_eq!(code_enc, 0, "symmetric encrypt failed: {}", out_enc);
    let sym_enc_file = find_single_file_with_ext(&dir, "enc");
    assert!(
        !sym_enc_file.file_name().unwrap().to_string_lossy().contains("notes.txt"),
        "default symmetric output must be anonymous, got {:?}",
        sym_enc_file
    );

    // 2. Inspect symmetric file (passwordless) & verify SGPGv2 length padding
    assert!(fs::metadata(&sym_enc_file).unwrap().len() > 1024);
    let out_insp =
        isolated_cmd(&dir).args(["inspect", sym_enc_file.to_str().unwrap()]).output().unwrap();
    assert!(out_insp.status.success(), "inspect failed: {:?}", out_insp);
    let insp_stdout = String::from_utf8_lossy(&out_insp.stdout);
    assert!(insp_stdout.contains("SGPGv2 (Password-Based Encrypted Container)"));
    assert!(insp_stdout.contains("Symmetric Password-Encrypted File (type=file)"));
    assert!(insp_stdout.contains("Enabled (Length-Hiding Random + Padme)"));

    // 3. Auto-detect symmetric decrypt via `yacrypt decrypt <anon>.enc` (without --private-key)
    let (code_dec, sig_dec, out_dec) = run_with_pty(
        &dir,
        &["decrypt", sym_enc_file.to_str().unwrap(), "-o", "notes_recovered.txt"],
        &[("Enter decryption password", sym_pw)],
    );
    assert_eq!(sig_dec, None);
    assert_eq!(code_dec, 0, "symmetric decrypt failed: {}", out_dec);
    assert_eq!(fs::read(dir.join("notes_recovered.txt")).unwrap(), b"symmetric payload 2026");

    // 3b. Legacy SGPGv1 symmetric file backward compatibility (inspect + decrypt)
    let legacy_salt = [0x61u8; 16];
    let legacy_nonce = [0x72u8; 24];
    let legacy_k = yacrypt_core::crypto::derive_key(sym_pw, &legacy_salt, 256, 1, 1).unwrap();
    let legacy_ct = yacrypt_core::crypto::encrypt_with_aad(
        &legacy_k,
        &legacy_nonce,
        b"legacy sgpgv1 doc",
        b"type=file",
    )
    .unwrap();
    let legacy_blob = yacrypt_core::crypto::pack_encrypted_blob(
        256,
        1,
        1,
        &legacy_salt,
        &legacy_nonce,
        b"type=file",
        &legacy_ct,
    )
    .unwrap();
    fs::write(dir.join("legacy_sym.enc"), &legacy_blob).unwrap();
    let leg_insp = isolated_cmd(&dir).args(["inspect", "legacy_sym.enc"]).output().unwrap();
    assert!(leg_insp.status.success());
    assert!(String::from_utf8_lossy(&leg_insp.stdout)
        .contains("SGPGv1 (Password-Based Encrypted Container)"));
    let (code_leg, sig_leg, out_leg) = run_with_pty(
        &dir,
        &["decrypt", "legacy_sym.enc", "-o", "legacy_sym_recovered.txt"],
        &[("Enter decryption password", sym_pw)],
    );
    assert_eq!(sig_leg, None);
    assert_eq!(code_leg, 0, "legacy SGPGv1 decrypt failed: {}", out_leg);
    assert_eq!(fs::read(dir.join("legacy_sym_recovered.txt")).unwrap(), b"legacy sgpgv1 doc");

    // 4. Generate a keypair with --label and verify `key-list`
    let (code_kp, sig_kp, out_kp) = run_with_pty(
        &dir,
        &["gen-keypair", "--label", "alice-main"],
        &[("Auto-generate backup encryption password", "y")],
    );
    assert_eq!(sig_kp, None);
    assert_eq!(code_kp, 0, "gen-keypair failed: {}", out_kp);

    let out_kl = isolated_cmd(&dir).args(["key-list"]).output().unwrap();
    assert!(out_kl.status.success(), "key-list failed: {:?}", out_kl);
    let kl_stdout = String::from_utf8_lossy(&out_kl.stdout);
    assert!(kl_stdout.contains("1 keypair(s) found"));
    assert!(kl_stdout.contains("[alice-main]"));
    assert!(kl_stdout.contains("pub=✅ priv=✅"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_phase0_to_phase3_guardrails_bundles_password_rotation_and_completions() {
    let dir = std::env::temp_dir().join(format!("yacrypt_phase0_3_e2e_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let alice_ks = dir.join("alice_ks");
    let bob_ks = dir.join("bob_ks");
    let pw1 = "alice-pass-12345";
    let pw2 = "alice-rotated-67890";
    let bob_pw = "bob-pass-1234567";

    // 1. Non-TTY no-arg invocation prints Help and exits 0; explicit `tui` on non-TTY exits != 0
    let no_arg = isolated_cmd(&dir).output().unwrap();
    assert!(no_arg.status.success(), "non-TTY no-arg should print help and exit 0");
    assert!(String::from_utf8_lossy(&no_arg.stdout).contains("Usage:"));

    let explicit_tui = isolated_cmd(&dir).arg("tui").output().unwrap();
    assert!(!explicit_tui.status.success());
    assert!(String::from_utf8_lossy(&explicit_tui.stderr).contains("requires a terminal"));

    // 2. Shell completions generate valid scripts (syntax-checked via bash -n / zsh -n)
    for (sh, checker) in [
        ("bash", Some("/bin/bash")),
        ("zsh", Some("/bin/zsh")),
        ("fish", None),
        ("powershell", None),
    ] {
        let comp = isolated_cmd(&dir).args(["completions", sh]).output().unwrap();
        assert!(comp.status.success(), "completions {} failed", sh);
        assert!(!comp.stdout.is_empty());
        if let Some(bin) = checker {
            if Path::new(bin).exists() {
                let script_path = dir.join(format!("comp.{}", sh));
                fs::write(&script_path, &comp.stdout).unwrap();
                let check = Command::new(bin).arg("-n").arg(&script_path).output().unwrap();
                assert!(
                    check.status.success(),
                    "{} -n failed: {}",
                    bin,
                    String::from_utf8_lossy(&check.stderr)
                );
            }
        }
    }

    // 3. Phase 0.5: Bare extra positional args on `encrypt` are rejected (no silent filename swallowing)
    fs::write(dir.join("a.txt"), b"doc a").unwrap();
    fs::write(dir.join("b.txt"), b"doc b").unwrap();
    let multi_pos = isolated_cmd(&dir).args(["encrypt", "a.txt", "b.txt"]).output().unwrap();
    assert!(!multi_pos.status.success());

    // 4. Generate Alice & Bob keypairs in separate --keystore-dir directories
    let (c_a, _, out_a) = run_with_pty(
        &dir,
        &["--keystore-dir", alice_ks.to_str().unwrap(), "gen-keypair", "--label", "self"],
        &[
            ("Auto-generate backup encryption password", "n"),
            ("Enter backup encryption password", pw1),
            ("Confirm password", pw1),
        ],
    );
    assert_eq!(c_a, 0, "alice gen-keypair failed: {}", out_a);
    let alice_fp = out_a
        .lines()
        .find_map(|l| l.split("Fingerprint:").nth(1).map(|s| s.trim().to_string()))
        .unwrap();

    let (c_b, _, out_b) = run_with_pty(
        &dir,
        &["--keystore-dir", bob_ks.to_str().unwrap(), "gen-keypair", "--label", "self"],
        &[
            ("Auto-generate backup encryption password", "n"),
            ("Enter backup encryption password", bob_pw),
            ("Confirm password", bob_pw),
        ],
    );
    assert_eq!(c_b, 0, "bob gen-keypair failed: {}", out_b);
    let bob_fp = out_b
        .lines()
        .find_map(|l| l.split("Fingerprint:").nth(1).map(|s| s.trim().to_string()))
        .unwrap();

    // 5. Phase 0.1 & Phase 1.4: Algorithm swap guardrails & SGPGv1 key-backup zero-password routing
    let alice_ed_pub = alice_ks.join(format!("public_{}.asc", alice_fp));
    let alice_x_pub = alice_ks.join(format!("x25519_public_{}.asc", alice_fp));
    let alice_ed_priv = alice_ks.join(format!("private_{}.asc.enc", alice_fp));

    let bad_enc = isolated_cmd(&dir)
        .args(["encrypt", "a.txt", "--key", alice_ed_pub.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!bad_enc.status.success());
    let bad_enc_err = String::from_utf8_lossy(&bad_enc.stderr);
    assert!(bad_enc_err.contains("Ed25519 signing public key"));
    assert!(bad_enc_err.contains("x25519_public_"));

    // Same-inode overwrite blocked BEFORE prompting even with --force
    let same_ino = isolated_cmd(&dir)
        .args([
            "encrypt",
            "a.txt",
            "--key",
            alice_x_pub.to_str().unwrap(),
            "-o",
            "a.txt",
            "--force",
        ])
        .output()
        .unwrap();
    assert!(!same_ino.status.success());
    assert!(String::from_utf8_lossy(&same_ino.stderr).contains("same file inode"));
    assert_eq!(fs::read(dir.join("a.txt")).unwrap(), b"doc a");

    // Passing SGPGv1 private key backup to `decrypt` fails immediately WITHOUT password prompt
    let sgpg_priv =
        isolated_cmd(&dir).args(["decrypt", alice_ed_priv.to_str().unwrap()]).output().unwrap();
    assert!(!sgpg_priv.status.success());
    assert!(String::from_utf8_lossy(&sgpg_priv.stderr).contains("decrypt-private-key"));

    // 6. Phase 2.2: key-export / key-import (with self-signature verification) + cross-user signed encrypt/decrypt + --no-instructions
    let bob_bundle = dir.join("bob.bundle.asc");
    let (c_exp, _, out_exp) = run_with_pty(
        &dir,
        &[
            "--keystore-dir",
            bob_ks.to_str().unwrap(),
            "key-export",
            "self",
            "-o",
            bob_bundle.to_str().unwrap(),
        ],
        &[("Enter Ed25519 signing key password", bob_pw)],
    );
    assert_eq!(c_exp, 0, "key-export failed: {}", out_exp);

    // Tampered bundle is rejected by key-import
    let tampered_bundle = dir.join("bob_tampered.bundle.asc");
    let bundle_str = fs::read_to_string(&bob_bundle).unwrap();
    let tampered_str = bundle_str.replacen("x25519_pub=", "x25519_pub=AAAA", 1);
    fs::write(&tampered_bundle, tampered_str).unwrap();
    let bad_imp = isolated_cmd(&dir)
        .args([
            "--keystore-dir",
            alice_ks.to_str().unwrap(),
            "key-import",
            tampered_bundle.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!bad_imp.status.success());

    // Valid import of Bob into Alice's keystore, and Alice into Bob's keystore
    let ok_imp_bob = isolated_cmd(&dir)
        .args([
            "--keystore-dir",
            alice_ks.to_str().unwrap(),
            "key-import",
            bob_bundle.to_str().unwrap(),
            "--label",
            "bob",
        ])
        .output()
        .unwrap();
    assert!(ok_imp_bob.status.success());

    let alice_bundle = dir.join("alice.bundle.asc");
    let (c_exp_a, _, _) = run_with_pty(
        &dir,
        &[
            "--keystore-dir",
            alice_ks.to_str().unwrap(),
            "key-export",
            &alice_fp[..16],
            "-o",
            alice_bundle.to_str().unwrap(),
        ],
        &[("Enter Ed25519 signing key password", pw1)],
    );
    assert_eq!(c_exp_a, 0);
    let ok_imp_alice = isolated_cmd(&dir)
        .args([
            "--keystore-dir",
            bob_ks.to_str().unwrap(),
            "key-import",
            alice_bundle.to_str().unwrap(),
            "--label",
            "alice",
        ])
        .output()
        .unwrap();
    assert!(ok_imp_alice.status.success());

    // Alice encrypts report.pdf TO bob, SIGNED BY self (default: anonymous output + no .decrypt.txt)
    fs::write(dir.join("report.pdf"), b"Q4 financial report").unwrap();
    let (c_enc_ab, _, out_enc_ab) = run_with_pty(
        &dir,
        &[
            "--keystore-dir",
            alice_ks.to_str().unwrap(),
            "encrypt",
            "report.pdf",
            "--key",
            "bob",
            "--sign-key",
            "self",
        ],
        &[("Enter signing private key password", pw1)],
    );
    assert_eq!(c_enc_ab, 0, "cross-user encrypt failed: {}", out_enc_ab);
    let anon_pubenc = find_single_file_with_ext(&dir, "pubenc");
    let anon_fname = anon_pubenc.file_name().unwrap().to_string_lossy().into_owned();
    assert!(!anon_fname.contains("report.pdf"), "default output leaked filename: {}", anon_fname);
    assert!(
        !dir.join(format!("{}.decrypt.txt", anon_fname)).exists(),
        "default encrypt must skip .decrypt.txt"
    );

    // Binary privacy & length-hiding checks on signed SCFv2 pubenc:
    // outer header must not expose Alice's Ed25519 pubkey/fingerprint or 19-byte exact length
    let raw_pubenc = fs::read(&anon_pubenc).unwrap();
    assert!(raw_pubenc.starts_with(b"SCFv2\x00"));
    assert!(
        raw_pubenc.len() > 1024,
        "expected padded SCFv2 > 1024 bytes, got {}",
        raw_pubenc.len()
    );
    let alice_vk_bytes = general_purpose::STANDARD
        .decode(fs::read_to_string(&alice_ed_pub).unwrap().trim())
        .unwrap();
    assert_eq!(alice_vk_bytes.len(), 32);
    assert!(!raw_pubenc.windows(32).any(|w| w == alice_vk_bytes.as_slice()));
    assert!(!String::from_utf8_lossy(&raw_pubenc).to_ascii_uppercase().contains(&alice_fp));

    let insp_ab = isolated_cmd(&dir)
        .args([
            "--keystore-dir",
            bob_ks.to_str().unwrap(),
            "inspect",
            anon_pubenc.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(insp_ab.status.success(), "inspect failed: {:?}", insp_ab);
    let insp_ab_out = String::from_utf8_lossy(&insp_ab.stdout);
    assert!(insp_ab_out.contains("SCFv2"));
    assert!(insp_ab_out.contains("Concealed inside AEAD payload"));
    assert!(insp_ab_out.contains("Enabled (Length-Hiding Random + Padme)"));
    assert!(!insp_ab_out.to_ascii_uppercase().contains(&alice_fp));

    // Passing X25519 pubkey as --signer is rejected BEFORE prompting for Bob's decryption password
    fs::remove_file(dir.join("report.pdf")).unwrap();
    let bob_x_pub_in_ks = bob_ks.join(format!("x25519_public_{}.asc", alice_fp));
    let bad_signer = isolated_cmd(&dir)
        .args([
            "--keystore-dir",
            bob_ks.to_str().unwrap(),
            "decrypt",
            anon_pubenc.to_str().unwrap(),
            "--private-key",
            "self",
            "--signer",
            bob_x_pub_in_ks.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!bad_signer.status.success());
    assert!(
        String::from_utf8_lossy(&bad_signer.stderr).contains("X25519 encryption public key"),
        "stderr was: {}",
        String::from_utf8_lossy(&bad_signer.stderr)
    );
    assert!(!dir.join("report.pdf").exists());

    // Rotate Bob's password via `change-key-password`
    let (c_rot, _, out_rot) = run_with_pty(
        &dir,
        &["--keystore-dir", bob_ks.to_str().unwrap(), "change-key-password", &bob_fp[..16]],
        &[
            ("Enter current password", bob_pw),
            ("Enter new backup password", pw2),
            ("Confirm password", pw2),
        ],
    );
    assert_eq!(c_rot, 0, "change-key-password failed: {}", out_rot);

    // Bob decrypts anon_pubenc (using rotated password pw2, --private-key self, --signer alice, -o report.pdf) -> restores report.pdf!
    let (c_dec_ba, _, out_dec_ba) = run_with_pty(
        &dir,
        &[
            "--keystore-dir",
            bob_ks.to_str().unwrap(),
            "decrypt",
            anon_pubenc.to_str().unwrap(),
            "--private-key",
            "self",
            "--signer",
            "alice",
            "-o",
            "report.pdf",
        ],
        &[("Enter private key password", pw2)],
    );
    assert_eq!(c_dec_ba, 0, "cross-user decrypt failed: {}", out_dec_ba);
    assert_eq!(fs::read(dir.join("report.pdf")).unwrap(), b"Q4 financial report");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_interactive_select_picker_security_bypasses_fifo_and_completions() {
    let dir = std::env::temp_dir().join(format!("yacrypt_picker_sec_e2e_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let ks = dir.join("ks");
    fs::create_dir_all(&ks).unwrap();

    // 1. Empty keystore on interactive PTY `key-export` fails cleanly without hanging
    let (c_empty, sig_empty, out_empty) = run_with_pty(
        &dir,
        &["--keystore-dir", ks.to_str().unwrap(), "key-export", "-o", "unused.bundle.asc"],
        &[],
    );
    assert_eq!(sig_empty, None);
    assert_ne!(c_empty, 0);
    assert!(out_empty.contains("No signable keypair"), "unexpected output: {}", out_empty);

    // 2. Multi-byte UTF-8 <12-char password ("🔑🔑🔑" = 3 chars, 12 bytes) is rejected on PTY,
    //    then re-prompted and accepted with a valid 12-char password
    let pw_alpha = "alpha-pass-1234";
    let pw_beta = "beta-pass-56789";
    let (c_utf8, sig_utf8, out_utf8) = run_with_pty(
        &dir,
        &["--keystore-dir", ks.to_str().unwrap(), "gen-keypair", "--label", "alpha"],
        &[
            ("Auto-generate backup encryption password", "n"),
            ("Enter backup encryption password", "🔑🔑🔑"),
            ("Confirm password", "🔑🔑🔑"),
            ("Password too short; must be >= 12 chars", pw_alpha),
            ("Confirm password", pw_alpha),
        ],
    );
    assert_eq!(sig_utf8, None);
    assert_eq!(c_utf8, 0, "gen-keypair alpha failed: {}", out_utf8);

    let (c_beta, sig_beta, out_beta) = run_with_pty(
        &dir,
        &["--keystore-dir", ks.to_str().unwrap(), "gen-keypair", "--label", "beta"],
        &[
            ("Auto-generate backup encryption password", "n"),
            ("Enter backup encryption password", pw_beta),
            ("Confirm password", pw_beta),
        ],
    );
    assert_eq!(sig_beta, None);
    assert_eq!(c_beta, 0, "gen-keypair beta failed: {}", out_beta);

    // Determine sorted order in `scan_keystore` via `key-list`
    let kl = isolated_cmd(&dir)
        .args(["--keystore-dir", ks.to_str().unwrap(), "key-list"])
        .output()
        .unwrap();
    let kl_str = String::from_utf8_lossy(&kl.stdout);
    let alpha_pos = kl_str.find("[alpha]").expect("alpha in key-list");
    let beta_pos = kl_str.find("[beta]").expect("beta in key-list");
    let (idx0_label, idx0_pw, _idx1_label, idx1_pw) = if alpha_pos < beta_pos {
        ("alpha", pw_alpha, "beta", pw_beta)
    } else {
        ("beta", pw_beta, "alpha", pw_alpha)
    };

    // 3. `encrypt <file> --sign-key <key>` WITHOUT `--key` MUST be rejected by Clap (`requires = "key"`)
    fs::write(dir.join("msg.txt"), b"interactive picker payload").unwrap();
    let sign_without_key = isolated_cmd(&dir)
        .args(["--keystore-dir", ks.to_str().unwrap(), "encrypt", "msg.txt", "--sign-key", "alpha"])
        .output()
        .unwrap();
    assert!(
        !sign_without_key.status.success(),
        "--sign-key without --key must fail instead of silently generating a new keypair"
    );
    assert!(!dir.join("msg.txt.pubenc").exists());

    // 4. Real PTY `dialoguer::Select` navigation:
    //    - `encrypt msg.txt --key --sign-key` (omitting values on both flags!)
    //      Recipient picker: send Down arrow (`\x1b[B`) -> selects index 1
    //      Signing picker: send empty (`""` -> Enter) -> selects index 0
    let (c_pick_enc, sig_pick_enc, out_pick_enc) = run_with_pty(
        &dir,
        &["--keystore-dir", ks.to_str().unwrap(), "encrypt", "msg.txt", "--key", "--sign-key"],
        &[
            ("Select recipient X25519 public key", "\x1b[B"),
            ("Select own Ed25519 signing key", ""),
            ("Enter signing private key password", idx0_pw),
        ],
    );
    assert_eq!(sig_pick_enc, None);
    assert_eq!(c_pick_enc, 0, "PTY picker encrypt failed: {}", out_pick_enc);
    let msg_pubenc = find_single_file_with_ext(&dir, "pubenc");

    //    - `decrypt <msg_pubenc> --signer <idx0_label> -o msg_dec.txt` (signature required by default)
    //      Omitting `--private-key` launches `dialoguer::Select`: send Down arrow (`\x1b[B`) -> selects index 1!
    let (c_pick_dec, sig_pick_dec, out_pick_dec) = run_with_pty(
        &dir,
        &[
            "--keystore-dir",
            ks.to_str().unwrap(),
            "decrypt",
            msg_pubenc.to_str().unwrap(),
            "--signer",
            idx0_label,
            "-o",
            "msg_dec.txt",
        ],
        &[
            ("Select X25519 decryption private key", "\x1b[B"),
            ("Enter private key password", idx1_pw),
        ],
    );
    assert_eq!(sig_pick_dec, None);
    assert_eq!(c_pick_dec, 0, "PTY picker decrypt failed: {}", out_pick_dec);
    assert_eq!(fs::read(dir.join("msg_dec.txt")).unwrap(), b"interactive picker payload");

    //    - `key-export -o picked.bundle.asc` (omitting key!) launches `dialoguer::Select`: index 0
    let (c_pick_exp, sig_pick_exp, out_pick_exp) = run_with_pty(
        &dir,
        &["--keystore-dir", ks.to_str().unwrap(), "key-export", "-o", "picked.bundle.asc"],
        &[
            ("Select own keypair to export signed public key bundle", ""),
            ("Enter Ed25519 signing key password", idx0_pw),
        ],
    );
    assert_eq!(sig_pick_exp, None);
    assert_eq!(c_pick_exp, 0, "PTY picker key-export failed: {}", out_pick_exp);
    assert!(dir.join("picked.bundle.asc").exists());

    // 5. Security regression: symmetric `SGPGv2` (`type=file`) MUST reject `--require-signature` and `--signer`
    //    BEFORE prompting for password and MUST NOT write unsigned plaintext
    fs::write(dir.join("sym.txt"), b"unsigned symmetric data").unwrap();
    let sym_pw = "symmetric-pass-123";
    let (c_sym, _, out_sym) = run_with_pty(
        &dir,
        &["encrypt", "sym.txt", "-c"],
        &[("Enter encryption password", sym_pw), ("Confirm password", sym_pw)],
    );
    assert_eq!(c_sym, 0, "sym encrypt failed: {}", out_sym);
    let sym_enc = find_single_file_with_ext(&dir, "enc");

    let bypass_req_sig = isolated_cmd(&dir)
        .args(["decrypt", sym_enc.to_str().unwrap(), "--require-signature", "-o", "leak_req.txt"])
        .output()
        .unwrap();
    assert!(
        !bypass_req_sig.status.success(),
        "symmetric decrypt with --require-signature MUST fail!"
    );
    assert!(
        String::from_utf8_lossy(&bypass_req_sig.stderr).contains("no Ed25519 signature"),
        "stderr was: {}",
        String::from_utf8_lossy(&bypass_req_sig.stderr)
    );
    assert!(!dir.join("leak_req.txt").exists());

    let bypass_signer = isolated_cmd(&dir)
        .args([
            "--keystore-dir",
            ks.to_str().unwrap(),
            "decrypt",
            sym_enc.to_str().unwrap(),
            "--signer",
            "alpha",
            "-o",
            "leak_signer.txt",
        ])
        .output()
        .unwrap();
    assert!(!bypass_signer.status.success(), "symmetric decrypt with --signer MUST fail!");
    assert!(String::from_utf8_lossy(&bypass_signer.stderr).contains("no Ed25519 signature"));
    assert!(!dir.join("leak_signer.txt").exists());

    // 6. Non-blocking FIFO (`mkfifo`), directory `EISDIR`, and M-1 stripped signature detection in `inspect`
    let fifo_path = dir.join("trap.fifo");
    let c_fifo_path = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_fifo_path.as_ptr(), 0o600) }, 0);

    let fifo_insp = isolated_cmd(&dir).args(["inspect", "trap.fifo"]).output().unwrap();
    assert!(!fifo_insp.status.success());
    assert!(
        String::from_utf8_lossy(&fifo_insp.stderr).contains("non-regular file"),
        "stderr was: {}",
        String::from_utf8_lossy(&fifo_insp.stderr)
    );

    let dir_insp = isolated_cmd(&dir).args(["inspect", ks.to_str().unwrap()]).output().unwrap();
    assert!(!dir_insp.status.success());
    assert!(
        String::from_utf8_lossy(&dir_insp.stderr).contains("non-regular file"),
        "directory inspect must not report bad magic: {}",
        String::from_utf8_lossy(&dir_insp.stderr)
    );

    // Verify `msg_pubenc` is SCFv2 (hides signature & signer identity from outer bytes)
    // AND keep real M-1 signature-stripping attack coverage on an SCFv1 signed container
    let signed_bytes = fs::read(&msg_pubenc).unwrap();
    assert_eq!(&signed_bytes[..5], b"SCFv2");
    assert_eq!(signed_bytes[5], 0x00);

    let bob_pub_path = yacrypt_core::keystore::resolve_recipient_key_arg(&ks, "alpha").unwrap();
    let bob_pub_b64 = fs::read_to_string(&bob_pub_path).unwrap();
    let bob_pub_arr: [u8; 32] =
        general_purpose::STANDARD.decode(bob_pub_b64.trim()).unwrap().try_into().unwrap();
    let alpha_sk = ed25519_dalek::SigningKey::from_bytes(&[0x31u8; 32]);
    let alpha_vk = alpha_sk.verifying_key().to_bytes();
    let m1_eph = StaticSecret::from([0x21u8; 32]);
    let m1_eph_pub = X25519PublicKey::from(&m1_eph).to_bytes();
    let m1_shared = m1_eph.diffie_hellman(&X25519PublicKey::from(bob_pub_arr));
    let m1_sym = yacrypt_core::crypto::derive_symmetric_key_from_shared_secret(
        m1_shared.as_bytes(),
        &m1_eph_pub,
        b"yacrypt-file-encryption-v1",
    );
    let m1_nonce = [0x11u8; 24];
    let m1_sig = ed25519_dalek::Signer::sign(&alpha_sk, b"signed v1 msg");
    let m1_aad = format!(
        "flags=01|ephemeral_pub={}|sig_vk={}",
        hex::encode(m1_eph_pub),
        hex::encode(alpha_vk)
    );
    let m1_ct = yacrypt_core::crypto::encrypt_with_aad(
        &m1_sym,
        &m1_nonce,
        b"signed v1 msg",
        m1_aad.as_bytes(),
    )
    .unwrap();
    let v1_msg_bytes = yacrypt_core::crypto::pack_pubenc_blob(
        &m1_eph_pub,
        &m1_nonce,
        m1_aad.as_bytes(),
        &m1_ct,
        Some(&yacrypt_core::crypto::PubencSignature {
            verifying_key: alpha_vk,
            signature: m1_sig.to_bytes(),
        }),
    )
    .unwrap();

    let mut stripped = Vec::new();
    stripped.extend_from_slice(b"SCFv1\x00");
    stripped.extend_from_slice(&v1_msg_bytes[6 + 96..]);
    fs::write(dir.join("stripped_m1.pubenc"), &stripped).unwrap();

    let m1_insp = isolated_cmd(&dir).args(["inspect", "stripped_m1.pubenc"]).output().unwrap();
    assert!(!m1_insp.status.success(), "inspect must reject M-1 stripped SCFv1 header");
    assert!(
        String::from_utf8_lossy(&m1_insp.stderr).contains("Signature stripped"),
        "stderr was: {}",
        String::from_utf8_lossy(&m1_insp.stderr)
    );

    // `decrypt` on M-1 stripped file must also fail preflight BEFORE prompting for password
    let m1_dec = isolated_cmd(&dir)
        .args([
            "--keystore-dir",
            ks.to_str().unwrap(),
            "decrypt",
            "stripped_m1.pubenc",
            "--private-key",
            "alpha",
        ])
        .output()
        .unwrap();
    assert!(!m1_dec.status.success());
    assert!(String::from_utf8_lossy(&m1_dec.stderr).contains("Signature stripped"));

    // 7. Orphan `labels.tsv` pruning: deleting a key's `.asc` files invalidates its label as `--signer`
    //    and allows reusing that label on `gen-keypair`
    let orphan_ks = dir.join("orphan_ks");
    fs::create_dir_all(&orphan_ks).unwrap();
    let (c_o1, _, _) = run_with_pty(
        &dir,
        &["--keystore-dir", orphan_ks.to_str().unwrap(), "gen-keypair", "--label", "ghost"],
        &[("Auto-generate backup encryption password", "y")],
    );
    assert_eq!(c_o1, 0);
    // Delete all key files in orphan_ks EXCEPT labels.tsv
    for entry in fs::read_dir(&orphan_ks).unwrap() {
        let p = entry.unwrap().path();
        if p.file_name().and_then(|n| n.to_str()) != Some("labels.tsv") {
            fs::remove_file(p).unwrap();
        }
    }
    assert!(orphan_ks.join("labels.tsv").exists());

    // Reusing `--label ghost` succeeds because orphaned labels.tsv entries are pruned
    let (c_o2, _, out_o2) = run_with_pty(
        &dir,
        &["--keystore-dir", orphan_ks.to_str().unwrap(), "gen-keypair", "--label", "ghost"],
        &[("Auto-generate backup encryption password", "y")],
    );
    assert_eq!(c_o2, 0, "reusing orphaned label failed: {}", out_o2);

    // 8. Completions structure & syntax checks (bash -n, zsh -n, fish single --keystore-dir, powershell options)
    let bash_comp = isolated_cmd(&dir).args(["completions", "bash"]).output().unwrap();
    assert!(bash_comp.status.success());
    let bash_src = String::from_utf8_lossy(&bash_comp.stdout);
    assert!(bash_src.contains("pwsh"));
    fs::write(dir.join("comp.bash"), bash_comp.stdout).unwrap();
    assert!(Command::new("/bin/bash")
        .args(["-n", dir.join("comp.bash").to_str().unwrap()])
        .status()
        .unwrap()
        .success());

    let zsh_comp = isolated_cmd(&dir).args(["completions", "zsh"]).output().unwrap();
    assert!(zsh_comp.status.success());
    let zsh_src = String::from_utf8_lossy(&zsh_comp.stdout);
    assert!(zsh_src.contains("--keystore-dir=[") && zsh_src.contains("pwsh"));
    if let Some(zsh_bin) = ["/bin/zsh", "/usr/bin/zsh"].iter().find(|p| Path::new(p).exists()) {
        fs::write(dir.join("comp.zsh"), zsh_comp.stdout).unwrap();
        assert!(Command::new(zsh_bin)
            .args(["-n", dir.join("comp.zsh").to_str().unwrap()])
            .status()
            .unwrap()
            .success());
    }

    let fish_comp = isolated_cmd(&dir).args(["completions", "fish"]).output().unwrap();
    assert!(fish_comp.status.success());
    let fish_src = String::from_utf8_lossy(&fish_comp.stdout);
    assert_eq!(
        fish_src.matches("-l keystore-dir").count(),
        1,
        "duplicate --keystore-dir in fish:\n{}",
        fish_src
    );

    let pwsh_comp = isolated_cmd(&dir).args(["completions", "pwsh"]).output().unwrap();
    assert!(pwsh_comp.status.success());
    let pwsh_src = String::from_utf8_lossy(&pwsh_comp.stdout);
    assert!(
        pwsh_src.contains("'--instructions'")
            && pwsh_src.contains("'--allow-unsigned'")
            && pwsh_src.contains("'--no-instructions'")
            && pwsh_src.contains("'pwsh'")
    );

    let _ = fs::remove_dir_all(&dir);
}
