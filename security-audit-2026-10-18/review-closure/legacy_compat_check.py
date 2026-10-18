#!/usr/bin/env python3
"""Legacy-format backward-compatibility check for the 2026-10-18 M-3 review closure.

Builds real OLD-format artifacts (pre-closure AAD layout) and feeds them to the
NEW binary to prove decryption/verification is unaffected by removing the
file_sha256/id_sha256 AAD fields:

  1. Legacy SGPGv1 keystore blob  (AAD: id_sha256=<sha256("Alice|alice@example.com")>|fp=..|type=ed25519)
     -> `decrypt-private-key` must succeed and export the original seed.
  2. Legacy SCFv1 .pubenc unsigned file (AAD: file_sha256=..|flags=00|ephemeral_pub=..)
     -> `decrypt` must succeed with byte-identical output.
  3. Same legacy .pubenc with a single flipped hex char in file_sha256 (AAD tamper)
     -> `decrypt` must FAIL authentication (AAD stays fully MAC-protected).

Usage: python3 legacy_compat_check.py <yacrypt-binary> <workdir>
"""

import base64
import hashlib
import hmac as hmac_mod
import os
import pty
import re
import secrets
import select
import shutil
import struct
import subprocess
import sys
import time

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_scalarmult,
    crypto_scalarmult_base,
)

ANSI_RE = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07")

failures = []


def ok(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        failures.append(name)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac_mod.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac_mod.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def drive(binary, args, cwd, expects, timeout=40):
    """Run `binary args` under a PTY, replying to expected prompts in order."""
    master, slave = pty.openpty()
    p = subprocess.Popen([binary] + args, cwd=cwd, stdin=slave, stdout=slave,
                         stderr=slave, close_fds=True)
    os.close(slave)
    buf, idx, deadline = b"", 0, time.time() + timeout
    while True:
        if time.time() > deadline:
            p.kill()
            break
        r, _, _ = select.select([master], [], [], 0.2)
        if r:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while idx < len(expects) and expects[idx][0].encode() in buf:
                os.write(master, (expects[idx][1] + "\n").encode())
                idx += 1
        elif p.poll() is not None:
            # drain remaining
            while True:
                r2, _, _ = select.select([master], [], [], 0.05)
                if not r2:
                    break
                try:
                    c2 = os.read(master, 4096)
                except OSError:
                    break
                if not c2:
                    break
                buf += c2
            break
    p.wait()
    try:
        os.close(master)
    except OSError:
        pass
    return p.returncode, ANSI_RE.sub(b"", buf).decode("utf-8", "replace")


def main():
    binary, work = sys.argv[1], sys.argv[2]
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    print(f"binary : {binary}")
    print(f"workdir: {work}\n")

    # ---------- 0. fresh keystore via NEW binary (auto password path, explicit y) ----------
    code, out = drive(binary, ["gen-keypair", "Alice", "alice@example.com"], work,
                      [("Auto-generate backup encryption password", "y")])
    ok("gen-keypair (new binary) exit 0", code == 0, f"rc={code}")
    fp_m = re.search(r"[0-9A-F]{64}", out)
    pw_m = re.search(r"Backup password generated:\s*\n\s*(\S+)", out)
    if not fp_m or not pw_m:
        print("cannot parse fingerprint/password from output:\n", out)
        return 1
    fp, pw = fp_m.group(0), pw_m.group(1).strip()
    ok("fingerprint parsed", len(fp) == 64)
    ok("auto backup password parsed", len(pw) == 64, f"len={len(pw)}")

    # ---------- 1. legacy keystore blob (old AAD with id_sha256) ----------
    seed = b"\x42" * 32
    pkcs8_v1 = bytes.fromhex("302e020100300506032b657004220420") + seed
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(24)
    key = hash_secret_raw(pw.encode(), salt, time_cost=2, memory_cost=65536,
                          parallelism=1, hash_len=32, type=Type.ID, version=19)
    id_sha = hashlib.sha256(b"Alice|alice@example.com").hexdigest()
    legacy_aad = f"id_sha256={id_sha}|fp={fp}|type=ed25519".encode()
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(pkcs8_v1, legacy_aad, nonce, key)
    blob = (b"SGPGv1" + struct.pack(">III", 65536, 2, 1)
            + bytes([len(salt)]) + salt + bytes([len(nonce)]) + nonce
            + struct.pack(">H", len(legacy_aad)) + legacy_aad
            + struct.pack(">Q", len(ct)) + ct)
    open(os.path.join(work, "legacy_ed25519.enc"), "wb").write(blob)
    print(f"legacy keystore AAD = {legacy_aad.decode()}")

    code, out = drive(binary, ["decrypt-private-key", "legacy_ed25519.enc", "-o", "legacy_ed.der"],
                      work, [("Enter backup password", pw)])
    der_ok = False
    der_path = os.path.join(work, "legacy_ed.der")
    if code == 0 and os.path.exists(der_path):
        der = open(der_path, "rb").read()
        der_ok = seed in der
    ok("legacy keystore blob decrypts on NEW binary (seed recovered)", der_ok,
       f"rc={code}, der={'missing' if not os.path.exists(der_path) else str(len(open(der_path,'rb').read()))+'B'}")

    # ---------- 2. legacy pubenc (old AAD with file_sha256), unsigned ----------
    recip_pub = base64.b64decode(
        open(os.path.join(work, f"keystore/x25519_public_{fp}.asc")).read().strip())
    eph_sk = secrets.token_bytes(32)
    eph_pub = crypto_scalarmult_base(eph_sk)
    shared = crypto_scalarmult(eph_sk, recip_pub)
    sym = hkdf_sha256(shared, eph_pub, b"yacrypt-file-encryption-v1")
    payload = b"legacy-format payload for backward-compat check\n"
    pnonce = secrets.token_bytes(24)

    def build_pubenc(aad_str: bytes, msg: bytes) -> bytes:
        c = crypto_aead_xchacha20poly1305_ietf_encrypt(msg, aad_str, pnonce, sym)
        return (b"SCFv1\x00" + eph_pub + pnonce
                + struct.pack(">H", len(aad_str)) + aad_str
                + struct.pack(">Q", len(c)) + c)

    file_digest = hashlib.sha256(b"legacy.txt").hexdigest()
    aad_good = f"file_sha256={file_digest}|flags=00|ephemeral_pub={eph_pub.hex()}".encode()
    open(os.path.join(work, "legacy.pubenc"), "wb").write(build_pubenc(aad_good, payload))
    print(f"legacy pubenc AAD   = {aad_good.decode()}")

    code, out = drive(binary, ["decrypt", "legacy.pubenc",
                               "--private-key", f"keystore/x25519_private_{fp}.asc.enc",
                               "--output", "legacy_out.txt"],
                      work, [("Enter private key password", pw)])
    got = open(os.path.join(work, "legacy_out.txt"), "rb").read() if os.path.exists(
        os.path.join(work, "legacy_out.txt")) else b""
    ok("legacy pubenc decrypts on NEW binary (content identical)", code == 0 and got == payload,
       f"rc={code}")

    # ---------- 3. tamper control: flip one hex char in legacy file_sha256 ----------
    flipped = ("e" if file_digest[0] != "e" else "f") + file_digest[1:]
    aad_bad = f"file_sha256={flipped}|flags=00|ephemeral_pub={eph_pub.hex()}".encode()
    # Keep the ORIGINAL ciphertext (authenticated under aad_good) and only alter the stored
    # AAD bytes — simulates an attacker editing the AAD field of a real file; must fail auth.
    ct_good = crypto_aead_xchacha20poly1305_ietf_encrypt(payload, aad_good, pnonce, sym)
    tampered = (b"SCFv1\x00" + eph_pub + pnonce
                + struct.pack(">H", len(aad_bad)) + aad_bad
                + struct.pack(">Q", len(ct_good)) + ct_good)
    open(os.path.join(work, "legacy_tampered.pubenc"), "wb").write(tampered)
    if os.path.exists(os.path.join(work, "legacy_tampered.txt")):
        os.remove(os.path.join(work, "legacy_tampered.txt"))
    code, out = drive(binary, ["decrypt", "legacy_tampered.pubenc",
                               "--private-key", f"keystore/x25519_private_{fp}.asc.enc",
                               "--output", "legacy_tampered.txt"],
                      work, [("Enter private key password", pw)])
    ok("tampered legacy AAD still rejected (auth failure, no output)",
       code != 0 and not os.path.exists(os.path.join(work, "legacy_tampered.txt")),
       f"rc={code}")

    # ---------- summary ----------
    print()
    if failures:
        print(f"RESULT: FAIL ({len(failures)}): {failures}")
        return 1
    print("RESULT: ALL PASS — new binary fully handles pre-closure legacy artifacts; "
          "removing the AAD digest fields is a safe, additive-only change")
    return 0


if __name__ == "__main__":
    sys.exit(main())
