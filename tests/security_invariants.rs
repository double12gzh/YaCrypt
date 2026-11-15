//! PROTECTED SECURITY & PRIVACY-BY-DEFAULT RED-LINE TESTS (YC-010)
//!
//! These tests encode non-negotiable cryptographic and metadata-leakage invariants.
//! AI agents MUST NOT delete, skip, or relax assertions in this file without
//! explicit human authorization after warning about the secrecy downgrade.

use std::{
    fs,
    path::{Path, PathBuf},
};
use yacrypt_core::{
    constants::{
        MAGIC_V2, MIN_PASSWORD_LENGTH, PADDING_MAX_JITTER_CAP_BYTES, PADDING_MIN_FLOOR_BYTES,
        PADDING_MIN_JITTER_BYTES, PUBENC_V2_MAGIC,
    },
    file_ops::{encrypt_file_symmetric, encrypt_file_with_key},
    keystore::generate_and_store_keys_in_dir,
    workflow::{decrypt_workflow_with_password_in_dir, encrypt_workflow_with_new_keys},
};

fn temp_test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("yacrypt_sec_inv_{}_{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn assert_is_16_hex_with_ext(path: &Path, expected_ext: &str) {
    assert_eq!(path.extension().and_then(|s| s.to_str()), Some(expected_ext));
    let stem = path.file_stem().and_then(|s| s.to_str()).expect("missing file stem");
    assert_eq!(stem.len(), 16, "anonymous output stem must be 16 hex chars: {}", stem);
    assert!(
        stem.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "anonymous output stem must be lowercase hex: {}",
        stem
    );
}

#[test]
fn invariant_constants_padding_and_password_bounds() {
    const {
        assert!(PADDING_MIN_FLOOR_BYTES >= 1024);
        assert!(PADDING_MIN_JITTER_BYTES >= 64);
        assert!(PADDING_MAX_JITTER_CAP_BYTES >= 4 * 1024 * 1024);
        assert!(MIN_PASSWORD_LENGTH >= 12);
    }
}

#[test]
fn invariant_pubenc_default_is_scfv2_anonymous_padded_no_instructions_and_no_outer_leak() {
    let dir = temp_test_dir("pubenc");
    let ks = dir.join("keystore");
    let input = dir.join("confidential_tar_bundle.tar");
    let keyword = b"TOP_SECRET_MARKER_XYZ_991";
    fs::write(&input, keyword).unwrap();

    let pw = "Strong-Invariant-Pass-1234";
    let outcome = encrypt_workflow_with_new_keys(&ks, &input, Some(pw), None, false).unwrap();

    // 1. Anonymous random filename, no original stem leaked
    assert_is_16_hex_with_ext(&outcome.encrypted_file, "pubenc");
    assert!(!outcome.encrypted_file.to_string_lossy().contains("confidential_tar_bundle"));

    // 2. Companion .decrypt.txt MUST NOT be written by default
    assert!(!outcome.instructions_written);
    assert!(outcome.instructions_skipped);
    assert!(!outcome.instructions_file.exists());

    // 3. SCFv2 container with flags == 0x00, no filename/keyword/fingerprint in raw bytes, and padded length
    let blob = fs::read(&outcome.encrypted_file).unwrap();
    assert!(blob.starts_with(PUBENC_V2_MAGIC), "default .pubenc must use SCFv2");
    assert_eq!(blob[5], 0x00, "SCFv2 outer flags must remain 0x00");
    assert!(blob.len() >= PADDING_MIN_FLOOR_BYTES, "small payload must be padded above floor");
    assert!(
        !blob.windows(b"confidential_tar_bundle".len()).any(|w| w == b"confidential_tar_bundle"),
        "raw ciphertext must never contain input filename"
    );
    assert!(
        !blob.windows(keyword.len()).any(|w| w == keyword),
        "raw ciphertext must never contain plaintext keyword"
    );
    let fp_bytes = outcome.keys.fingerprint.as_bytes();
    assert!(
        !blob.windows(fp_bytes.len()).any(|w| w == fp_bytes),
        "SCFv2 outer blob must not expose signer fingerprint"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn invariant_symmetric_default_is_sgpgv2_anonymous_padded_and_no_filename_leak() {
    let dir = temp_test_dir("sym");
    let input = dir.join("payroll_archive.tar");
    let keyword = b"SYMMETRIC_SECRET_MARKER_882";
    fs::write(&input, keyword).unwrap();

    let out = encrypt_file_symmetric(&input, "Strong-Symmetric-Pass-1234", None, false).unwrap();

    assert_is_16_hex_with_ext(&out, "enc");
    assert!(!out.to_string_lossy().contains("payroll_archive"));

    let blob = fs::read(&out).unwrap();
    assert!(blob.starts_with(MAGIC_V2), "default symmetric .enc must use SGPGv2");
    assert!(blob.len() >= PADDING_MIN_FLOOR_BYTES, "small payload must be padded above floor");
    assert!(
        !blob.windows(b"payroll_archive".len()).any(|w| w == b"payroll_archive"),
        "raw ciphertext must never contain input filename"
    );
    assert!(
        !blob.windows(keyword.len()).any(|w| w == keyword),
        "raw ciphertext must never contain plaintext keyword"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn invariant_unsigned_pubenc_decrypt_fails_closed_when_signature_required() {
    let dir = temp_test_dir("sig_req");
    let ks = dir.join("keystore");
    fs::create_dir_all(&ks).unwrap();

    let pw = "Strong-Sig-Invariant-Pass-1234";
    let keys = generate_and_store_keys_in_dir(&ks, Some(pw)).unwrap();
    let input = dir.join("unsigned_payload.bin");
    fs::write(&input, b"unsigned secret bytes").unwrap();

    // Create an unsigned SCFv2 .pubenc
    let pubenc = encrypt_file_with_key(&input, &keys.x25519_pub_path, None, None, false).unwrap();
    let denied_out = dir.join("should_not_exist.bin");

    // Default signature-required path MUST fail closed and write NO plaintext
    let res = decrypt_workflow_with_password_in_dir(
        &ks,
        &pubenc,
        &keys.x25519_enc_path,
        pw,
        Some(&denied_out),
        None,
        true,
        false,
    );
    assert!(res.is_err(), "unsigned .pubenc must fail when signature is required");
    assert!(!denied_out.exists(), "failed decrypt must never write plaintext output");

    // Explicit opt-out (equivalent to CLI --allow-unsigned) succeeds
    let allowed_out = dir.join("allowed_out.bin");
    decrypt_workflow_with_password_in_dir(
        &ks,
        &pubenc,
        &keys.x25519_enc_path,
        pw,
        Some(&allowed_out),
        None,
        false,
        false,
    )
    .unwrap();
    assert_eq!(fs::read(&allowed_out).unwrap(), b"unsigned secret bytes");

    let _ = fs::remove_dir_all(&dir);
}
