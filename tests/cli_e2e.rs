use base64::{engine::general_purpose, Engine as _};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

fn yacrypt_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_yacrypt"))
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

    // Create input file with distinctive name to check M-3 cleartext leak
    let input_path = dir.join("confidential_salary_2026.txt");
    fs::write(&input_path, b"top secret payload").unwrap();

    let out_pubenc = dir.join("confidential_salary_2026.pubenc");
    let enc = Command::new(yacrypt_bin())
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
    assert!(enc.status.success(), "stderr: {}", String::from_utf8_lossy(&enc.stderr));

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
    assert!(blob_lossy.contains("file_sha256="));

    // M-4(1): Default refuses to overwrite existing file
    let enc_overwrite = Command::new(yacrypt_bin())
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

    let enc_forced = Command::new(yacrypt_bin())
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

    let enc_symlink = Command::new(yacrypt_bin())
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

    let res = Command::new(yacrypt_bin())
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

/// Pure-Rust PTY helper to drive interactive `dialoguer` prompts in E2E tests
fn run_with_pty(
    cwd: &std::path::Path,
    args: &[&str],
    prompts_and_replies: &[(&str, &str)],
) -> (i32, Option<i32>, String) {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::process::{CommandExt, ExitStatusExt};

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
    cmd.current_dir(cwd).args(args).stdin(slave_in).stdout(slave_out).stderr(slave_err);
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
    let mut prompt_idx = 0;
    let mut buf = [0u8; 1024];

    loop {
        match master.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                transcript.push_str(&String::from_utf8_lossy(&buf[..n]));
                while prompt_idx < prompts_and_replies.len() {
                    let (expected, reply) = prompts_and_replies[prompt_idx];
                    if transcript.contains(expected) {
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

    // 1. Encrypt signed workflow (auto-generates password)
    let f2_path = dir.join("f2.txt");
    fs::write(&f2_path, b"top secret doc 2").unwrap();

    let (code, sig, out) = run_with_pty(
        &dir,
        &["encrypt", "f2.txt", "BobSecretName", "bob_secret@example.com"],
        &[("Auto-generate backup encryption password", "")],
    );
    assert_eq!(sig, None);
    assert_eq!(code, 0, "encrypt failed: {}", out);

    // Extract generated backup password and fingerprint
    let pw = out
        .lines()
        .skip_while(|l| !l.contains("Backup password generated:"))
        .nth(1)
        .unwrap()
        .trim()
        .to_string();
    let fp = out
        .lines()
        .find_map(|l| l.split("Fingerprint:").nth(1).map(|s| s.trim().to_string()))
        .unwrap();
    assert_eq!(fp.len(), 64);

    // M-3: Verify keystore private key blobs do NOT leak cleartext name or email
    let ed_priv_path = dir.join(format!("keystore/private_{}.asc.enc", fp));
    let x_priv_path = dir.join(format!("keystore/x25519_private_{}.asc.enc", fp));
    let ed_priv_raw = fs::read(&ed_priv_path).unwrap();
    let ed_priv_str = String::from_utf8_lossy(&ed_priv_raw);
    assert!(!ed_priv_str.contains("BobSecretName"));
    assert!(!ed_priv_str.contains("bob_secret@example.com"));

    // 2. Decrypt valid signed file -> succeeds and prints verified signer fingerprint
    let dec_out = dir.join("f2_decrypted.txt");
    let (code, sig, out_dec) = run_with_pty(
        &dir,
        &[
            "decrypt",
            "f2.pubenc",
            "--private-key",
            x_priv_path.to_str().unwrap(),
            "--output",
            dec_out.to_str().unwrap(),
        ],
        &[("Enter private key password", &pw)],
    );
    assert_eq!(sig, None);
    assert_eq!(code, 0, "decrypt failed: {}", out_dec);
    assert!(out_dec.contains(&format!("signer fingerprint: {}", fp)));
    assert_eq!(fs::read(&dec_out).unwrap(), b"top secret doc 2");

    // 3. M-1 PoC (poc_strip): Strip signature block from signed f2.pubenc -> MUST REJECT!
    let signed_bytes = fs::read(dir.join("f2.pubenc")).unwrap();
    assert_eq!(&signed_bytes[..5], b"SCFv1");
    assert_eq!(signed_bytes[5] & 1, 1);
    let mut stripped_bytes = Vec::new();
    stripped_bytes.extend_from_slice(b"SCFv1\x00");
    stripped_bytes.extend_from_slice(&signed_bytes[6 + 96..]);
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
        fs::read_to_string(dir.join(format!("keystore/x25519_public_{}.asc", fp))).unwrap();
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

    // 6. L-5: decrypt-private-key rejects X25519 key backup, accepts Ed25519 key backup
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
        &["decrypt-private-key", ed_priv_path.to_str().unwrap(), "-o", "ed.der"],
        &[("Enter backup password", &pw)],
    );
    assert_eq!(sig_l5_ok, None);
    assert_eq!(code_l5_ok, 0);
    assert!(dir.join("ed.der").exists());

    let _ = fs::remove_dir_all(&dir);
}
