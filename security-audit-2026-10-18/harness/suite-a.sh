#!/bin/bash
# YaCrypt e2e audit suite v3 part A (T0-T10) — corrected filenames + full capture
YAC=/sessions/nice-jolly-allen/work-yacrypt/target/release/yacrypt
SC=/sessions/nice-jolly-allen/e2e-scripts
WS=/sessions/nice-jolly-allen/e2e3
rm -rf "$WS"; mkdir -p "$WS/logs"; cd "$WS" || exit 1
ulimit -Sl 256
DRV="python3 $SC/drive.py 60"
DRV25="python3 $SC/drive.py 25"
sec(){ echo; echo "============== $* =============="; }

sec "T0 environment"
"$YAC" --version
echo "soft memlock in this suite: $(ulimit -l) KiB (raised/lowered per test)"
"$YAC" --help | sed -n '1,3p'

sec "T1 gen-keypair (memlock workaround 256K so mlockall fails gracefully)"
OUT=$(DRIVE_EXPECTS='Auto-generate backup encryption password|' $DRV "$YAC" gen-keypair Alice alice@example.com 2>&1); RC=$?
echo "$OUT" > logs/t1.log
echo "$OUT" | grep -aE "mlockall|Backup password generated|Fingerprint:" | head -5
PW=$(echo "$OUT" | awk '/Backup password generated:/{getline; gsub(/[[:space:]\r]+/,"",$0); print; exit}')
FP=$(echo "$OUT" | grep -aoE 'Fingerprint: +[0-9A-F]{64}' | grep -aoE '[0-9A-F]{64}' | head -1)
echo "RC=$RC PW_LEN=${#PW} FP=${FP:0:16}..."
echo "$PW" > logs/pw1.txt; echo "$FP" > logs/fp1.txt
ls -la keystore/ | tail -5

sec "T2 unsigned roundtrip (default output name replaces extension: f1.txt -> f1.pubenc -> f1)"
echo "hello yacrypt world" > f1.txt; cp f1.txt f1.orig
"$YAC" encrypt-file-with-key --input f1.txt --public-key "keystore/x25519_public_$FP.asc" 2>&1 | tail -1
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW" $DRV "$YAC" decrypt f1.pubenc --private-key "keystore/x25519_private_$FP.asc.enc" 2>&1); RC=$?
echo "$OUT" > logs/t2.log
echo "$OUT" | grep -aE "No signature|skipping|finished|DRIVE_EXIT"
test -f f1 && cmp -s f1 f1.orig && echo "T2 OK: roundtrip identical" || echo "T2 FAIL (RC=$RC)"

sec "T3 signed full workflow + decrypt"
echo "top secret doc 2" > f2.txt; cp f2.txt f2.orig
OUT=$(DRIVE_EXPECTS='Auto-generate backup encryption password|' $DRV "$YAC" encrypt f2.txt Bob bob@example.com 2>&1)
echo "$OUT" > logs/t3enc.log
PW2=$(echo "$OUT" | awk '/Backup password generated:/{getline; gsub(/[[:space:]\r]+/,"",$0); print; exit}')
FP2=$(echo "$OUT" | grep -aoE 'Fingerprint: +[0-9A-F]{64}' | grep -aoE '[0-9A-F]{64}' | head -1)
echo "PW2_LEN=${#PW2} FP2=${FP2:0:16}..."
echo "$PW2" > logs/pw2.txt; echo "$FP2" > logs/fp2.txt
echo "instructions file: $(ls f2.pubenc.decrypt.txt 2>/dev/null || echo MISSING)"
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW2" $DRV "$YAC" decrypt f2.pubenc --private-key "keystore/x25519_private_$FP2.asc.enc" 2>&1); RC=$?
echo "$OUT" > logs/t3dec.log
echo "$OUT" | grep -aE "signature|verified|finished|DRIVE_EXIT"
test -f f2 && cmp -s f2 f2.orig && echo "T3 OK: signed roundtrip identical" || echo "T3 FAIL (RC=$RC)"

sec "T4 tamper one ciphertext byte -> reject, no output"
python3 - <<'EOF'
d = bytearray(open('f2.pubenc','rb').read()); d[-20] ^= 0x01
open('f2tamper.pubenc','wb').write(d)
EOF
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW2" $DRV "$YAC" decrypt f2tamper.pubenc --private-key "keystore/x25519_private_$FP2.asc.enc" 2>&1); RC=$?
echo "$OUT" > logs/t4.log
echo "$OUT" | grep -aE "Decryption failed|tampered|DRIVE_EXIT"
test ! -f f2tamper && echo "T4 OK: rejected, no output file written" || echo "T4 FAIL: output exists"

sec "T5 strip signature (downgrade)"
python3 "$SC/poc_strip.py" f2.pubenc f2strip.pubenc
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW2" $DRV "$YAC" decrypt f2strip.pubenc --private-key "keystore/x25519_private_$FP2.asc.enc" 2>&1); RC=$?
echo "$OUT" > logs/t5.log
echo "$OUT" | grep -aE "No signature|skipping|finished|DRIVE_EXIT"
test -f f2strip && cmp -s f2strip f2.orig && echo "T5 CONFIRMED: stripped blob decrypts; signature silently skipped"

sec "T6 FORGERY with victim public key only (attacker had no secrets)"
python3 "$SC/poc_forge.py" "keystore/x25519_public_$FP.asc" forged.pubenc "FORGED CONTENT: attacker payload"
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW" $DRV "$YAC" decrypt forged.pubenc --private-key "keystore/x25519_private_$FP.asc.enc" 2>&1); RC=$?
echo "$OUT" > logs/t6.log
echo "$OUT" | grep -aE "verified|finished|DRIVE_EXIT"
echo "forged output content: $(cat forged 2>/dev/null)"

sec "T7 malformed nonce_len=23 (SGPGv1)"
python3 - <<'EOF'
import struct
blob = (b"SGPGv1" + struct.pack(">III", 256, 1, 1) + bytes([16]) + bytes(16)
        + bytes([23]) + bytes(23) + struct.pack(">H", 0) + struct.pack(">Q", 40) + bytes(40))
open("bad_nonce.enc","wb").write(blob)
EOF
OUT=$(DRIVE_EXPECTS='Enter backup password|anypw12345' $DRV25 "$YAC" decrypt-private-key bad_nonce.enc -o bn.der 2>&1); RC=$?
echo "$OUT" > logs/t7.log
echo "$OUT" | grep -aE "panicked|left:|right:|DRIVE_EXIT" | head -4

sec "T8 malicious ct_len=u64::MAX (SCFv1)"
python3 - <<'EOF'
import struct
blob = (b"SCFv1" + b"\x00" + bytes(32) + bytes(24) + struct.pack(">H", 0)
        + struct.pack(">Q", 0xFFFFFFFFFFFFFFFF) + b"JUNK")
open("bad_ctlen.pubenc","wb").write(blob)
EOF
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW" $DRV25 "$YAC" decrypt bad_ctlen.pubenc --private-key "keystore/x25519_private_$FP.asc.enc" 2>&1); RC=$?
echo "$OUT" > logs/t8.log
echo "$OUT" | grep -aE "panicked|slice index|DRIVE_EXIT" | head -4

sec "T9 garbage input -> clean error"
head -c 64 /dev/urandom > garbage.bin
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW" $DRV "$YAC" decrypt garbage.bin --private-key "keystore/x25519_private_$FP.asc.enc" 2>&1)
echo "$OUT" > logs/t9.log
echo "$OUT" | grep -aE "bad magic|Invalid|DRIVE_EXIT"

sec "T10 wrong password -> clean error"
OUT=$(DRIVE_EXPECTS='Enter private key password|WrongPassword9999' $DRV "$YAC" decrypt f1.pubenc --private-key "keystore/x25519_private_$FP.asc.enc" 2>&1)
echo "$OUT" > logs/t10.log
echo "$OUT" | grep -aE "Decryption failed|wrong password|DRIVE_EXIT"
echo "============== PART A DONE =============="
