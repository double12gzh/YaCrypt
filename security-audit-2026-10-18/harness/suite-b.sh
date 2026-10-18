#!/bin/bash
# YaCrypt e2e audit suite v3 part B (T11-T20): edge cases, perms, crash repro, data-loss path
YAC=/sessions/nice-jolly-allen/work-yacrypt/target/release/yacrypt
SC=/sessions/nice-jolly-allen/e2e-scripts
WS=/sessions/nice-jolly-allen/e2e3
cd "$WS" || exit 1
ulimit -Sl 256
DRV="python3 $SC/drive.py 60"
PW=$(cat logs/pw1.txt); FP=$(cat logs/fp1.txt)
PW2=$(cat logs/pw2.txt); FP2=$(cat logs/fp2.txt)
sec(){ echo; echo "============== $* =============="; }

sec "T11 empty file roundtrip"
: > empty.txt
"$YAC" encrypt-file-with-key --input empty.txt --public-key "keystore/x25519_public_$FP.asc" >/dev/null 2>&1; echo "enc RC=$?"
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW" $DRV "$YAC" decrypt empty.pubenc --private-key "keystore/x25519_private_$FP.asc.enc" 2>&1)
echo "$OUT" | grep -aE "finished|DRIVE_EXIT"
stat -c '%s bytes  %n' empty 2>/dev/null

sec "T12 filename with pipe/space/unicode (extension dropped on decrypt)"
FNAME='we|ird 文件.txt'
printf 'meta test\n' > "$FNAME"
"$YAC" encrypt-file-with-key --input "$FNAME" --public-key "keystore/x25519_public_$FP.asc" >/dev/null 2>&1 && echo "enc ok -> $(ls 'we|ird 文件.pubenc')"
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW" $DRV "$YAC" decrypt "we|ird 文件.pubenc" --private-key "keystore/x25519_private_$FP.asc.enc" 2>&1)
echo "$OUT" | grep -aE "finished|DRIVE_EXIT"
echo "decrypted file content: $(cat 'we|ird 文件' 2>/dev/null)"

sec "T13 pre-existing output perms (0644) + silent overwrite"
printf 'x\n' > preout.bin; chmod 644 preout.bin
"$YAC" encrypt-file-with-key --input f1.txt --public-key "keystore/x25519_public_$FP.asc" --output preout.bin >/dev/null 2>&1
stat -c '%a perms after encrypt-overwrite %n' preout.bin
printf 'y\n' > dec_target; chmod 644 dec_target
OUT=$(DRIVE_EXPECTS="Enter private key password|$PW" $DRV "$YAC" decrypt f1.pubenc --private-key "keystore/x25519_private_$FP.asc.enc" --output dec_target 2>&1)
stat -c '%a perms after decrypt-overwrite %n' dec_target
echo "dec_target now contains: $(head -c 20 dec_target)"

sec "T14 symlink output follows link"
echo orig > real_out.bin; chmod 600 real_out.bin; ln -s real_out.bin link_out.bin
"$YAC" encrypt-file-with-key --input f1.txt --public-key "keystore/x25519_public_$FP.asc" --output link_out.bin >/dev/null 2>&1
ls -la link_out.bin | awk '{print $1, $9, $10, $11}'
echo -n "real_out.bin now starts with: "; head -c5 real_out.bin; echo

sec "T15 gen-password"
P1=$("$YAC" gen-password); echo "default len=${#P1}"
"$YAC" gen-password --length 0 >/dev/null 2>&1; echo "length-0 RC=$?"
P8=$("$YAC" gen-password -l 8); echo "len8=${#P8}"

sec "T16 decrypt-private-key export"
OUT=$(DRIVE_EXPECTS="Enter backup password|$PW" $DRV "$YAC" decrypt-private-key "keystore/private_$FP.asc.enc" -o ed_priv.der 2>&1)
echo "$OUT" | grep -aE "written|DRIVE_EXIT"
stat -c '%a perms, %s bytes %n' ed_priv.der 2>/dev/null

sec "T19 CRASH REPRO at default memlock (8192 KiB) — gen-keypair path"
( ulimit -Sl 8192
  OUT=$(DRIVE_EXPECTS='Auto-generate backup encryption password|' $DRV "$YAC" gen-keypair CrashRepro crash@example.com 2>&1)
  echo "$OUT" > logs/t19.log
  echo "$OUT" | grep -aE "mlockall|memory allocation|Aborted|DRIVE_EXIT" | head -5 )
echo "--- newest keystore entries (partial state after crash):"
ls -lat keystore/ | head -5

sec "T20 orphaned public key => permanently undecryptable file"
NEWPUB=$(ls -t keystore/x25519_public_*.asc | head -1)
FPO=$(basename "$NEWPUB" | sed 's/x25519_public_//; s/\.asc$//')
echo "orphan fp: ${FPO:0:16}..."
test -f "keystore/x25519_private_${FPO}.asc.enc" && echo "private key EXISTS" || echo "T20: private key for this pubkey does NOT exist (orphaned by crash)"
echo "important data" > f3.txt
"$YAC" encrypt-file-with-key --input f3.txt --public-key "$NEWPUB" 2>&1 | tail -1
echo "f3.pubenc exists: $(test -f f3.pubenc && echo yes)"
"$YAC" decrypt f3.pubenc --private-key "keystore/x25519_private_${FPO}.asc.enc" 2>&1 | tail -1

sec "T18 memory footprint: 32MB input"
dd if=/dev/urandom of=big.bin bs=1M count=32 status=none
python3 - <<EOF
import subprocess, resource
YAC = "$YAC"
p = subprocess.run([YAC, "encrypt-file-with-key", "--input", "big.bin",
                    "--public-key", "keystore/x25519_public_$FP.asc"], capture_output=True)
mb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024
print(f"encrypt rc={p.returncode}; peak child RSS ~{mb:.0f} MB (input 32 MB)")
EOF
echo "============== PART B DONE =============="
