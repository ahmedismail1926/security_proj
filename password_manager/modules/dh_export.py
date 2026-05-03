import os
import json
import base64
from Crypto.Cipher import AES

from utils.crypto_utils import random_in_range, mod_exp, sha256_bytes, int_to_bytes
from modules.elgamal_keygen import load_private_key, load_public_key
from modules.signatures import sign, verify
from modules.vault_manager import _decrypt_vault, _encrypt_and_save

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPORTS_DIR = os.path.join(BASE_DIR, 'exports')

# Sender generates ephemeral DH key, signs it, and sends to receiver
def export_step1(sender_username: str, receiver_username: str, filename: str):
    sender_priv = load_private_key(sender_username)

    q = sender_priv['q']
    alpha = sender_priv['alpha']

    # Generate ephemeral DH key
    X_A = random_in_range(2, q - 2) # Generates Private Key X_A
    Y_A = mod_exp(alpha, X_A, q) # Computes Public Key Y_A

    # Sign Y_A
    Y_A_bytes = int_to_bytes(Y_A)
    r, s = sign(Y_A_bytes, sender_priv)

    data = {
        "sender": sender_username,
        "receiver": receiver_username,
        "q": str(q),
        "alpha": str(alpha),
        "Y_A": str(Y_A),
        "sig": {"r": str(r), "s": str(s)}
    }

    os.makedirs(EXPORTS_DIR, exist_ok=True)
    path = os.path.join(EXPORTS_DIR, filename + "_step1.json")

    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    # Save 'X_A' locally (temporary)
    with open(os.path.join(EXPORTS_DIR, filename + "_X_A.json"), "w") as f:
        json.dump({"X_A": str(X_A)}, f)

    print("Step 1 complete → send file to receiver")

# Receiver verifies sender's DH public key, generates their own DH key, computes shared secret, and sends back to sender
def export_step2(receiver_username: str, filename: str):
    receiver_priv = load_private_key(receiver_username)

    step1_path = os.path.join(EXPORTS_DIR, filename + "_step1.json")

    with open(step1_path, "r") as f:
        data = json.load(f)

    sender = data["sender"]
    sender_pub = load_public_key(sender)

    Y_A = int(data["Y_A"])
    r = int(data["sig"]["r"])
    s = int(data["sig"]["s"])

    # Verify Y_A
    if not verify(int_to_bytes(Y_A), (r, s), sender_pub):
        raise ValueError("Invalid DH key from sender")

    # Use the SENDER's DH parameters so both sides share the same q and alpha
    q = int(data["q"])
    alpha = int(data["alpha"])

    # Generate receiver DH key
    X_B = random_in_range(2, q - 2)
    Y_B = mod_exp(alpha, X_B, q)

    # Compute shared secret
    K = mod_exp(Y_A, X_B, q)

    # Save K locally
    with open(os.path.join(EXPORTS_DIR, filename + "_shared_key.json"), "w") as f:
        json.dump({"K": str(K)}, f)

    # Sign Y_B
    r2, s2 = sign(int_to_bytes(Y_B), receiver_priv)

    response = {
        "Y_B": str(Y_B),
        "sig": {"r": str(r2), "s": str(s2)}
    }

    with open(os.path.join(EXPORTS_DIR, filename + "_step2.json"), "w") as f:
        json.dump(response, f, indent=2)

    print("Step 2 complete → send back to sender")


# Sender verifies receiver's DH public key, computes shared secret, encrypts vault with session key, signs payload, and finalizes export
def export_finalize(sender_username: str, master_password: str, filename: str):
    sender_priv = load_private_key(sender_username)

    # Load saved X_A
    with open(os.path.join(EXPORTS_DIR, filename + "_X_A.json")) as f:
        X_A = int(json.load(f)["X_A"])

    # Load Y_B and signature
    with open(os.path.join(EXPORTS_DIR, filename + "_step2.json")) as f:
        data = json.load(f)

    Y_B = int(data["Y_B"])
    r = int(data["sig"]["r"])
    s = int(data["sig"]["s"])

    # sender is known
    # receiver must come from step1 or be stored consistently
    step1_path = os.path.join(EXPORTS_DIR, filename + "_step1.json")

    with open(step1_path, "r") as f:
        step1_data = json.load(f)

    receiver_username = step1_data["receiver"]
    sender_username = step1_data["sender"]    
    receiver_pub = load_public_key(receiver_username)

    # Verify Y_B
    if not verify(int_to_bytes(Y_B), (r, s), receiver_pub):
        raise ValueError("Invalid DH response")

    q = sender_priv['q']

    # Compute shared secret
    K = mod_exp(Y_B, X_A, q)
    session_key = sha256_bytes(int_to_bytes(K))

    # Decrypt vault
    entries = _decrypt_vault(sender_username, master_password)
    payload = json.dumps(entries).encode()

    # Encrypt
    cipher = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(payload)

    raw = cipher.nonce + tag + ciphertext

    # Sign payload
    r2, s2 = sign(raw, sender_priv)

    final = {
        "encrypted_payload": base64.b64encode(raw).decode(),
        "signature": {"r": str(r2), "s": str(s2)},
        "sender": sender_username
    }

    with open(os.path.join(EXPORTS_DIR, filename + "_final.json"), "w") as f:
        json.dump(final, f, indent=2)

    print("Final export ready → send to receiver")


# Receiver verifies payload, decrypts with session key, and saves vault under receiver's ownership
def import_finalize(receiver_username: str, master_password: str, filename: str):
    receiver_priv = load_private_key(receiver_username)

    # Load shared secret
    with open(os.path.join(EXPORTS_DIR, filename + "_shared_key.json")) as f:
        K = int(json.load(f)["K"])

    session_key = sha256_bytes(int_to_bytes(K))

    # Load final file
    with open(os.path.join(EXPORTS_DIR, filename + "_final.json")) as f:
        data = json.load(f)

    sender = data["sender"]
    sender_pub = load_public_key(sender)

    raw = base64.b64decode(data["encrypted_payload"])

    r = int(data["signature"]["r"])
    s = int(data["signature"]["s"])

    # Verify payload
    if not verify(raw, (r, s), sender_pub):
        raise ValueError("Tampered payload")

    nonce = raw[:16]
    tag = raw[16:32]
    ciphertext = raw[32:]

    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    entries = json.loads(plaintext.decode())

    # Merge with receiver's existing vault (append, skip duplicates)
    try:
        existing = _decrypt_vault(receiver_username, master_password)
    except ValueError:
        existing = []

    existing_websites = {e.get("website", "").lower() for e in existing}
    for entry in entries:
        if entry.get("website", "").lower() not in existing_websites:
            existing.append(entry)
            existing_websites.add(entry.get("website", "").lower())

    _encrypt_and_save(receiver_username, master_password, existing, receiver_priv)

    print("Import successful")

