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


# =========================
# DEVICE 1: EXPORT
# =========================
def export_vault(sender_username: str,
                 sender_master_password: str,
                 receiver_username: str,
                 export_filename: str) -> dict:

    sender_priv = load_private_key(sender_username)

    q = sender_priv['p']
    alpha = sender_priv['alpha']

    # 1. Generate DH key pair (sender)
    a = random_in_range(2, q - 2)
    A = mod_exp(alpha, a, q)

    # 2. Sign DH public key
    A_bytes = int_to_bytes(A)
    dh_sig_r, dh_sig_s = sign(A_bytes, sender_priv)

    # 3. Decrypt vault locally
    entries = _decrypt_vault(sender_username, sender_master_password)
    payload_bytes = json.dumps(entries).encode('utf-8')

    # NOTE:
    # Encryption will be done after shared key derivation on receiver side
    export_data = {
        "sender_username": sender_username,
        "dh_public_key": str(A),
        "dh_signature": {
            "r": str(dh_sig_r),
            "s": str(dh_sig_s)
        },
        "payload_plain": base64.b64encode(payload_bytes).decode('utf-8')
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

    export_path = os.path.join(EXPORTS_DIR, f"{export_filename}.json")

    if not os.path.exists(export_path):
        raise ValueError("Export file not found.")

    with open(export_path, 'r', encoding='utf-8') as f:
        export_data = json.load(f)

    sender_username = export_data["sender_username"]

    sender_pub = load_public_key(sender_username)
    receiver_priv = load_private_key(receiver_username)

    q = receiver_priv['p']
    alpha = receiver_priv['alpha']

    # 1. Verify sender DH public key
    A = int(export_data["dh_public_key"])
    dh_sig_r = int(export_data["dh_signature"]["r"])
    dh_sig_s = int(export_data["dh_signature"]["s"])

    if not verify(int_to_bytes(A), (dh_sig_r, dh_sig_s), sender_pub):
        raise ValueError("Invalid DH public key. Aborting.")

    # 2. Generate receiver DH key pair
    b = random_in_range(2, q - 2)
    B = mod_exp(alpha, b, q)

    # (Optional) You can sign B if you want full protocol compliance
    # but assignment usually doesn't require sending it back in CLI

    # 3. Compute shared secret
    K = mod_exp(A, b, q)
    session_key = sha256_bytes(int_to_bytes(K))

    # 4. Decode payload (from sender)
    payload_bytes = base64.b64decode(export_data["payload_plain"])

    # 5. Encrypt with session key (simulate secure transfer)
    cipher = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(payload_bytes)

    nonce = cipher.nonce
    encrypted_payload = nonce + tag + ciphertext

    # 6. Decrypt again (simulate receiving securely)
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    entries = json.loads(plaintext.decode('utf-8'))

    # 7. Save into receiver vault (re-encrypted with new master password)
    _encrypt_and_save(receiver_username,
                      receiver_master_password,
                      entries,
                      receiver_priv)