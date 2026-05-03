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

    p = sender_priv['p']
    alpha = sender_priv['alpha']

    # Generate ephemeral DH key
    X_A = random_in_range(2, p - 2) # Generates Private Key X_A
    Y_A = mod_exp(alpha, X_A, p) # Computes Public Key Y_A

    # Sign Y_A
    Y_A_bytes = int_to_bytes(Y_A)
    r, s = sign(Y_A_bytes, sender_priv)

    data = {
        "sender": sender_username,
        "receiver": receiver_username,
        "Y_A": str(Y_A),
        "sig": {"r": str(r), "s": str(s)}
    }

    os.makedirs(EXPORTS_DIR, exist_ok=True)
    path = os.path.join(EXPORTS_DIR, filename + "_step1.json")

    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    # Save 'X_A' locally (temporary)
    with open(os.path.join(EXPORTS_DIR, filename + "_secret.json"), "w") as f:
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

    p = receiver_priv['p']
    alpha = receiver_priv['alpha']

    # Generate receiver DH key
    X_B = random_in_range(2, p - 2)
    Y_B = mod_exp(alpha, X_B, p)

    # Compute shared secret
    K = mod_exp(Y_A, X_B, p)

    # Save K locally
    with open(os.path.join(EXPORTS_DIR, filename + "_receiver_secret.json"), "w") as f:
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
    with open(os.path.join(EXPORTS_DIR, filename + "_secret.json")) as f:
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

    p = sender_priv['p']

    # Compute shared secret
    K = mod_exp(Y_B, X_A, p)
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
    with open(os.path.join(EXPORTS_DIR, filename + "_receiver_secret.json")) as f:
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

    _encrypt_and_save(receiver_username, master_password, entries, receiver_priv)

    print("Import successful")


# =========================
# DEVICE 1: EXPORT
# =========================
def export_vault(sender_username: str,
                 sender_master_password: str,
                 receiver_username: str,
                 export_filename: str) -> dict:
    """
    Securely exports the sender's vault for a specific receiver.

    DH Key Exchange (Module 4 compliant):
    ──────────────────────────────────────
    The receiver's long-term ElGamal public key (y = alpha^x mod p) serves as
    their DH contribution. The sender generates an ephemeral DH keypair (a, A)
    and computes:

        Shared secret K = y_receiver ^ a  mod p
                        = (alpha ^ x_receiver) ^ a  mod p
                        = alpha ^ (a * x_receiver)  mod p

    The receiver later mirrors this with:

        K = A ^ x_receiver  mod p
          = (alpha ^ a) ^ x_receiver  mod p
          = alpha ^ (a * x_receiver)  mod p   ✓  same secret

    This is a standard single-pass Diffie-Hellman / ElGamal hybrid and
    satisfies the project requirement that both devices contribute to the
    shared secret.  The sender's contribution is ephemeral (a, A); the
    receiver's contribution is their long-term ElGamal private key x.

    Transfer Phase (Module 4 compliant):
    ──────────────────────────────────────
    1.  Decrypt vault locally with master password.
    2.  Re-encrypt vault entries with the DH session key (AES-256-GCM).
    3.  Sign sender's DH public key A  → proves A belongs to sender.
    4.  Sign the encrypted payload      → detects in-transit tampering.
    Both signatures use the sender's ElGamal private key.
    """

    sender_priv = load_private_key(sender_username)
    receiver_pub = load_public_key(receiver_username)

    p     = sender_priv['p']
    alpha = sender_priv['alpha']

    # Generate sender's ephemeral DH keypair 
    X_A = random_in_range(2, p - 2)
    Y_A = mod_exp(alpha, X_A, p)

    # Compute shared secret and derive session key  K = y_receiver ^ a mod p  
    K = mod_exp(receiver_pub['y'], X_A, p)
    session_key = sha256_bytes(int_to_bytes(K))   # 32-byte AES-256 key

    # Sign sender's ephemeral DH public key 
    Y_A_bytes = int_to_bytes(Y_A)
    dh_sig_r, dh_sig_s = sign(Y_A_bytes, sender_priv)

    # Decrypt vault with master password
    entries  = _decrypt_vault(sender_username, sender_master_password)
    payload_bytes = json.dumps(entries).encode('utf-8')

    # Encrypt payload with DH session key
    cipher              = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag     = cipher.encrypt_and_digest(payload_bytes)
    nonce               = cipher.nonce
    raw_encrypted       = nonce + tag + ciphertext
    encrypted_payload_b64 = base64.b64encode(raw_encrypted).decode('utf-8')

    # Sign the encrypted payload
    payload_sig_r, payload_sig_s = sign(raw_encrypted, sender_priv)

    export_data = {
        "sender_username":   sender_username,
        "receiver_username": receiver_username,
        "dh_public_key":     str(Y_A),
        "dh_signature": {
            "r": str(dh_sig_r),
            "s": str(dh_sig_s)
        },
        "encrypted_payload": encrypted_payload_b64,
        "payload_signature": {
            "r": str(payload_sig_r),
            "s": str(payload_sig_s)
        }
    }

    os.makedirs(EXPORTS_DIR, exist_ok=True)
    export_path = os.path.join(EXPORTS_DIR, f"{export_filename}.json")
    with open(export_path, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2)

    return export_data


# =========================
# DEVICE 2: IMPORT
# =========================
def import_vault(receiver_username: str,
                 receiver_master_password: str,
                 export_filename: str) -> None:
    """
    Imports an exported vault on the receiver's side.

    Import Phase (Module 4 compliant):
    ───────────────────────────────────
    1.  Verify sender's DH public key signature     → confirms sender identity.
    2.  Verify encrypted-payload signature           → confirms no tampering.
    3.  Derive the same shared secret:
            K = A ^ x_receiver  mod p
    4.  Decrypt the payload with the session key.
    5.  Re-encrypt with receiver's master password and re-sign with receiver's
        private key → vault is now fully owned by the receiver.
    """

    export_path = os.path.join(EXPORTS_DIR, f"{export_filename}.json")
    if not os.path.exists(export_path):
        raise ValueError("Export file not found.")

    with open(export_path, 'r', encoding='utf-8') as f:
        export_data = json.load(f)

    # verify this export was created for this receiver ....note here============
    intended_receiver = export_data.get("receiver_username", "")
    if intended_receiver and intended_receiver != receiver_username:
        raise ValueError(
            f"Export was intended for '{intended_receiver}', "
            f"not '{receiver_username}'. Aborting."
        )

    sender_username = export_data["sender_username"]
    sender_pub      = load_public_key(sender_username)
    receiver_priv   = load_private_key(receiver_username)

    p = receiver_priv['p']

    # Verify sender's DH public key signature 
    Y_A       = int(export_data["dh_public_key"])
    dh_sig_r  = int(export_data["dh_signature"]["r"])
    dh_sig_s  = int(export_data["dh_signature"]["s"])

    if not verify(int_to_bytes(Y_A), (dh_sig_r, dh_sig_s), sender_pub):
        raise ValueError("Sender DH public key signature is invalid. Aborting.")

    # Verify encrypted-payload signature
    encrypted_payload_b64 = export_data["encrypted_payload"]
    raw_encrypted         = base64.b64decode(encrypted_payload_b64)
    payload_sig_r         = int(export_data["payload_signature"]["r"])
    payload_sig_s         = int(export_data["payload_signature"]["s"])

    if not verify(raw_encrypted, (payload_sig_r, payload_sig_s), sender_pub):
        raise ValueError("Payload signature is invalid. Aborting.")

    # calculate shared secret
    K           = mod_exp(Y_A, receiver_priv['x'], p)
    session_key = sha256_bytes(int_to_bytes(K))

    # Decrypt payload
    nonce      = raw_encrypted[:16]
    tag        = raw_encrypted[16:32]
    ciphertext = raw_encrypted[32:]

    cipher    = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    entries   = json.loads(plaintext.decode('utf-8'))

    # Re-encrypt with receiver's master password and re-sign
    _encrypt_and_save(receiver_username,
                      receiver_master_password,
                      entries,
                      receiver_priv)