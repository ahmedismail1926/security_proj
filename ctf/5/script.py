#!/usr/bin/env python3
"""
CBC Padding Oracle — CTF Exploit
Target    : http://cbc-ctf.westeurope.azurecontainer.io:5000
Endpoints : POST /oracle      {"ciphertext_hex": "<hex>"}  → {"valid_padding": true/false}
            POST /check_flag  {"flag": "<flag>"}        → win/fail
            POST /encrypt     {"plaintext": "<text>"}   → encrypted ciphertext
Ciphertext: IV || C1 || C2  (48 bytes / 3 blocks)
"""

import requests
import sys
import time

BASE       = "http://cbc-ctf.westeurope.azurecontainer.io:5000"
BLOCK_SIZE = 16
CIPHERTEXT = bytes.fromhex(
    "38d3ae899b34ebcdf9eb5a0bf4f1bb4a"   # block 0 — IV
    "6ae9d1c7f6463090c10de6936dc79bf3"   # block 1 — C1
    "de0dd507dc8988903711a0f9f7fb2294"   # block 2 — C2
)

SESSION = requests.Session()


# ── Oracle ─────────────────────────────────────────────────────────────────────
def oracle(ct: bytes) -> bool:
    """POST hex ciphertext to /oracle; return True if padding is valid."""
    for attempt in range(4):
        try:
            r = SESSION.post(
                f"{BASE}/oracle",
                json={"ciphertext_hex": ct.hex()},
                timeout=8,
            )
            return r.json().get("valid_padding", False)
        except Exception:
            time.sleep(0.4 * (attempt + 1))
    return False


# ── Core padding oracle attack ─────────────────────────────────────────────────
def decrypt_block(prev: bytes, curr: bytes, block_num: int) -> bytes:
    """Recover one 16-byte plaintext block byte-by-byte."""
    intermediate = bytearray(BLOCK_SIZE)
    plaintext    = bytearray(BLOCK_SIZE)
    total_calls  = 0

    for byte_idx in range(BLOCK_SIZE - 1, -1, -1):
        pad_val = BLOCK_SIZE - byte_idx          # 1 for last byte, 16 for first

        # Suffix: force already-known intermediate bytes to produce pad_val
        suffix = bytearray(BLOCK_SIZE - 1 - byte_idx)
        for k in range(byte_idx + 1, BLOCK_SIZE):
            suffix[k - byte_idx - 1] = intermediate[k] ^ pad_val

        found = False
        for guess in range(256):
            # Tampered block: zeros | guess_byte | crafted_suffix
            tampered = bytearray(byte_idx) + bytearray([guess]) + suffix
            total_calls += 1

            if oracle(bytes(tampered) + curr):
                # For the rightmost byte, confirm it's \x01 not a longer valid pad
                if byte_idx == BLOCK_SIZE - 1 and byte_idx > 0:
                    confirm = bytearray(tampered)
                    confirm[byte_idx - 1] ^= 0xFF
                    total_calls += 1
                    if not oracle(bytes(confirm) + curr):
                        continue          # false positive — keep searching

                intermediate[byte_idx] = guess ^ pad_val
                plaintext[byte_idx]    = intermediate[byte_idx] ^ prev[byte_idx]
                char = chr(plaintext[byte_idx]) if 32 <= plaintext[byte_idx] < 127 else '.'
                print(f"  [B{block_num}] byte[{byte_idx:2d}] = "
                      f"0x{plaintext[byte_idx]:02x} '{char}'  "
                      f"(pad=0x{pad_val:02x}  calls={total_calls})")
                found = True
                break

        if not found:
            print(f"  [B{block_num}] byte[{byte_idx}] NOT FOUND — inserting '?'")
            plaintext[byte_idx] = ord('?')

    return bytes(plaintext)


def pkcs7_unpad(data: bytes) -> bytes:
    n = data[-1] if data else 0
    if 1 <= n <= BLOCK_SIZE and data[-n:] == bytes([n] * n):
        return data[:-n]
    return data


def attack(ct: bytes) -> bytes:
    blocks = [ct[i:i + BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    plaintext = b""
    for i in range(1, len(blocks)):
        print(f"\n[*] Decrypting block {i}/{len(blocks) - 1} ...")
        plaintext += decrypt_block(blocks[i - 1], blocks[i], i)
    return pkcs7_unpad(plaintext)


# ── Flag checker ───────────────────────────────────────────────────────────────
def check_flag(flag: str):
    try:
        r = SESSION.post(f"{BASE}/check_flag", json={"flag": flag}, timeout=8)
        print(f"\n[*] /check_flag response: {r.text}")
    except Exception as e:
        print(f"[!] check_flag error: {e}")


# ── Main ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 62)
    print("  CBC Padding Oracle Attack")
    blocks = [CIPHERTEXT[i:i+BLOCK_SIZE] for i in range(0, len(CIPHERTEXT), BLOCK_SIZE)]
    labels = ["IV"] + [f"C{i}" for i in range(1, len(blocks))]
    for lbl, blk in zip(labels, blocks):
        print(f"  {lbl:4s}: {blk.hex()}")
    print("=" * 62)

    # Sanity check
    print("\n[*] Sanity check — original ciphertext should be valid...")
    assert oracle(CIPHERTEXT), \
        "Oracle returned invalid! Check /oracle request format."
    print("[+] Oracle confirmed: valid padding.")

    # Attack
    print("\n[*] Starting padding oracle attack (~1-3 min)...")
    t0 = time.time()
    secret = attack(CIPHERTEXT)
    elapsed = time.time() - t0

    print("\n" + "=" * 62)
    try:
        flag_str = secret.decode()
    except UnicodeDecodeError:
        flag_str = secret.decode("latin-1")

    print(f"  PLAINTEXT : {flag_str}")
    print(f"  HEX       : {secret.hex()}")
    print(f"  Time      : {elapsed:.1f}s")
    print("=" * 62)

    # Auto-submit to /check_flag
    check_flag(flag_str)