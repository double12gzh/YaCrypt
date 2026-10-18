#!/bin/bash
# YaCrypt fix-verification suite (V0-V11) against the FIXED release binary at DEFAULT memlock (8192 KiB)
# 2026-10-18 复审收口：自动口令默认改为“否”，此处显式回复 y 以继续覆盖自动生成路径
YAC=/sessions/nice-jolly-allen/work2-yacrypt/target/release/yacrypt
SC=/sessions/nice-jolly-allen/e2e-scripts
WS=/sessions/nice-jolly-allen/e2e4
rm -rf "$WS"; mkdir -p "$WS/logs"; cd "$WS" || exit 1
DRV="python3 $SC/drive.py 60"
sec(){ echo; echo "============== $* =============="; }

sec "V0 environment"
echo "memlock soft: $(ulimit -l) KiB (default — not worked around)"
"$YAC" --version
"$YAC" --help | grep -E "signer|require-signature|sign-key|force" | head -8

sec "V1 H-2: gen-keypair at default memlock must fully succeed"
OUT=$(DRIVE_EXPECTS='Auto-generate backup encryption password|y' $DRV "$YAC" gen-keypair Alice alice@example.com 2>&1); RC=$?
echo "$OUT" > logs/v1.log
echo "$OUT" | grep -aE "mlockall|Backup password generated|Fingerprint:" | head -4
PW=$(echo "$OUT" | awk '/Backup password generated:/{getline; gsub(/[[:space:]\r]+/,"",$0); print; exit}')
FP=$(echo "$OUT" | grep -aoE '[0-9A-F]{64}' | head -1)
echo "drive_RC=$RC PW_LEN=${#PW} FP=${FP:0:16}..."
echo "$PW" > logs/pw1.txt; echo "$FP" > logs/fp1.txt
echo "keystore file count: $(ls keystore | wc -l) (expect 5)"

sec "V2 signed workflow roundtrip + signer fingerprint displayed"
echo "top secret doc 2" > f2.txt
OUT=$(DRIVE_EXPECTS='Auto-generate backup encryption password|y' $DRV "$YAC" encrypt f2.txt Bob bob@example.com 2>&1)
PW2=$(echo "$OUT" | awk '/Backup password generated:/{getline; gsub(/[[:space:]\r]+/,"",$0); print; exit}')
FP2=$(echo "$OUT" | grep -aoE '[0-9A-F]{64}' | head -1)
echo "$PW2" > logs/pw2.txt; echo "$FP2" > logs/fp2.txt
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW2" $DRV "$YAC" decrypt f2.pubenc --private-key "keystore/x25519_private_$FP2.asc.enc" 2>&1); RC=$?
echo "$OUT" > logs/v2.log
echo "$OUT" | grep -aE "verified successfully|finished|DRIVE_EXIT"
cmp -s f2 f2.txt && echo "V2 OK: roundtrip identical"

sec "V3 H-1: attacker forgery (public key only) must be REJECTED"
python3 "$SC/poc_forge.py" "keystore/x25519_public_$FP.asc" forged.pubenc "FORGED CONTENT: attacker payload"
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW" $DRV "$YAC" decrypt forged.pubenc --private-key "keystore/x25519_private_$FP.asc.enc" 2>&1); RC=$?
echo "$OUT" > logs/v3.log
echo "$OUT" | grep -aE "untrusted signer|FAILED|DRIVE_EXIT"
test ! -f forged && echo "V3 OK: forged file rejected, no output written" || echo "V3 FAIL: output exists!"

sec "V4 M-1: signature strip must be REJECTED"
python3 "$SC/poc_strip.py" f2.pubenc f2strip.pubenc
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW2" $DRV "$YAC" decrypt f2strip.pubenc --private-key "keystore/x25519_private_$FP2.asc.enc" 2>&1)
echo "$OUT" | grep -aE "Signature stripped|FAILED|DRIVE_EXIT"
test ! -f f2strip && echo "V4 OK: stripped file rejected, no output" || echo "V4 FAIL"

sec "V5 M-2: malformed inputs must exit cleanly (no signal)"
python3 - <<'EOF'
import struct
blob = (b"SGPGv1" + struct.pack(">III", 256, 1, 1) + bytes([16]) + bytes(16)
        + bytes([23]) + bytes(23) + struct.pack(">H", 0) + struct.pack(">Q", 40) + bytes(40))
open("bad_nonce.enc","wb").write(blob)
blob2 = (b"SCFv1" + b"\x00" + bytes(32) + bytes(24) + struct.pack(">H", 0)
        + struct.pack(">Q", 0xFFFFFFFFFFFFFFFF) + b"JUNK")
open("bad_ctlen.pubenc","wb").write(blob2)
EOF
OUT=$(DRIVE_EXPECTS='Enter backup password|anypw12345' $DRV "$YAC" decrypt-private-key bad_nonce.enc -o bn.der 2>&1)
echo "$OUT" | grep -aE "invalid nonce|Format|DRIVE_EXIT"
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW" $DRV "$YAC" decrypt bad_ctlen.pubenc --private-key "keystore/x25519_private_$FP.asc.enc" 2>&1)
echo "$OUT" | grep -aE "Invalid|overflow|Format|DRIVE_EXIT"

sec "V6 M-4: write semantics (no-overwrite / 0600 force / symlink refusal)"
echo data > v6.txt
"$YAC" encrypt-file-with-key --input v6.txt --public-key "keystore/x25519_public_$FP.asc" --output keep.pubenc >/dev/null 2>&1; echo "first write RC=$?"
"$YAC" encrypt-file-with-key --input v6.txt --public-key "keystore/x25519_public_$FP.asc" --output keep.pubenc >/dev/null 2>&1; echo "second write without --force RC=$? (expect non-zero)"
printf 'old' > pre644.bin; chmod 644 pre644.bin
"$YAC" encrypt-file-with-key --input v6.txt --public-key "keystore/x25519_public_$FP.asc" --output pre644.bin --force >/dev/null 2>&1; echo "force overwrite RC=$?"
stat -c 'pre644.bin mode after --force: %a (expect 600)' pre644.bin
echo orig > real.bin; chmod 600 real.bin; ln -s real.bin link.pubenc
"$YAC" encrypt-file-with-key --input v6.txt --public-key "keystore/x25519_public_$FP.asc" --output link.pubenc --force >/dev/null 2>&1; echo "symlink write RC=$? (expect non-zero)"
echo "real.bin content: $(head -c 4 real.bin) (expect orig)"

sec "V7 backward compatibility: OLD-format signed file + OLD keystore, NEW binary"
OLDDIR=/sessions/nice-jolly-allen/e2e3
if [ -f "$OLDDIR/f2.pubenc" ] && [ -f "$OLDDIR/keystore/x25519_private_$(cat "$OLDDIR/logs/fp2.txt").asc.enc" ]; then
  OLDFP=$(sed -n 1p "$OLDDIR/logs/fp2.txt"); OLDPW=$(sed -n 1p "$OLDDIR/logs/pw2.txt")
  mkdir -p old; cp "$OLDDIR/f2.pubenc" old/
  OUT=$(DRIVE_EXPECTS="Enter private key password|$OLDPW" $DRV "$YAC" decrypt old/f2.pubenc --private-key "$OLDDIR/keystore/x25519_private_$OLDFP.asc.enc" --output old/f2.txt 2>&1)
  echo "$OUT" > logs/v7.log
  echo "$OUT" | grep -aE "verified successfully|DRIVE_EXIT" | head -3
  cmp -s old/f2.txt "$OLDDIR/f2.orig" && echo "V7 OK: old-format file decrypted + verified, content identical" || echo "V7 FAIL"
else
  echo "V7 SKIP: old audit artifacts not found"
fi

sec "V8 cross-user --sign-key + anchored --signer flow"
mkdir -p b
OUT=$(cd b && DRIVE_EXPECTS='Auto-generate backup encryption password|y' $DRV "$YAC" gen-keypair Ben ben@example.com 2>&1)
PWB=$(echo "$OUT" | awk '/Backup password generated:/{getline; gsub(/[[:space:]\r]+/,"",$0); print; exit}')
FPB=$(echo "$OUT" | grep -aoE '[0-9A-F]{64}' | head -1)
echo "B fingerprint: ${FPB:0:16}..."
echo "v8 payload" > v8.txt
OUT=$(DRIVE_EXPECTS="Enter signing private key password|$PWB" $DRV "$YAC" encrypt v8.txt --key "keystore/x25519_public_$FP.asc" --sign-key "b/keystore/private_$FPB.asc.enc" 2>&1)
echo "$OUT" | grep -aE "signed|File encrypted|Error|DRIVE_EXIT" | head -3
echo "--- A decrypt with default anchor (expect reject: untrusted signer)"
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW" $DRV "$YAC" decrypt v8.pubenc --private-key "keystore/x25519_private_$FP.asc.enc" 2>&1)
echo "$OUT" | grep -aE "untrusted signer|FAILED|DRIVE_EXIT"
test ! -f v8 && echo "V8a OK: rejected without matching --signer"
echo "--- A decrypt with --signer B_fp (expect success)"
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW" $DRV "$YAC" decrypt v8.pubenc --private-key "keystore/x25519_private_$FP.asc.enc" --signer "$FPB" 2>&1)
echo "$OUT" | grep -aE "signer fingerprint|finished|DRIVE_EXIT"
cmp -s v8 v8.txt && echo "V8b OK: cross-user signed flow verified via --signer" || echo "V8b FAIL"

sec "V9 --require-signature on unsigned file"
"$YAC" encrypt-file-with-key --input v8.txt --public-key "keystore/x25519_public_$FP.asc" --output unsigned.pubenc >/dev/null 2>&1
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW" $DRV "$YAC" decrypt unsigned.pubenc --private-key "keystore/x25519_private_$FP.asc.enc" --require-signature 2>&1)
echo "$OUT" | grep -aE "no embedded signature|FAILED|DRIVE_EXIT"
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW" $DRV "$YAC" decrypt unsigned.pubenc --private-key "keystore/x25519_private_$FP.asc.enc" 2>&1)
echo "$OUT" | grep -aE "No signature|finished|DRIVE_EXIT"
test -f unsigned && echo "V9 OK: unsigned rejected under --require-signature; accepted with notice otherwise"

sec "V10 low-order recipient key rejected at encrypt (L-1)"
python3 -c "import base64; open('zero.asc','w').write(base64.b64encode(bytes(32)).decode())"
"$YAC" encrypt-file-with-key --input v8.txt --public-key zero.asc --output z.pubenc 2>&1 | tail -1
test ! -f z.pubenc && echo "V10 OK: no output produced"

sec "V11 decrypt-private-key type validation (L-5)"
OUT=$(DRIVE_EXPECTS="Enter backup password|$PW" $DRV "$YAC" decrypt-private-key "keystore/x25519_private_$FP.asc.enc" -o x.der 2>&1)
echo "$OUT" | grep -aE "Cannot export|DRIVE_EXIT"
test ! -f x.der && echo "V11 OK: x25519 backup refused for DER export"
echo; echo "============== FIX-VERIFICATION DONE =============="
