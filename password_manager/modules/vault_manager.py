import os
import json
import base64
from Crypto.Cipher import AES
from utils.crypto_utils import sha256_bytes
from modules.signatures import sign_vault, verify_vault
from modules.elgamal_keygen import load_private_key, load_public_key

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VAULTS_DIR = os.path.join(BASE_DIR, 'vaults')

def _get_vault_path(username: str) -> str:
    return os.path.join(VAULTS_DIR, f"{username}_vault.json")

def _decrypt_vault(username: str, master_password: str) -> list:
    vault_path = _get_vault_path(username)
    if not os.path.exists(vault_path):
        raise ValueError("Vault not found for user.")

    with open(vault_path, 'r', encoding='utf-8') as f:
        vault_data = json.load(f)

    stored_string = vault_data.get("encrypted_vault", "")
    if not stored_string:
        return []

    try:
        raw        = base64.b64decode(stored_string)
        nonce      = raw[:16]
        tag        = raw[16:32]
        ciphertext = raw[32:]

        data_key  = sha256_bytes(master_password.encode('utf-8'))
        cipher    = AES.new(data_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(plaintext.decode('utf-8'))
    except Exception:
        raise ValueError("Wrong master password or vault corrupted.")

def _encrypt_and_save(username: str, master_password: str, entries: list, private_key: dict) -> None:
    data_key = sha256_bytes(master_password.encode('utf-8'))
    cipher   = AES.new(data_key, AES.MODE_GCM)

    plaintext_bytes     = json.dumps(entries).encode('utf-8')
    ciphertext, tag     = cipher.encrypt_and_digest(plaintext_bytes)
    nonce               = cipher.nonce
    combined            = nonce + tag + ciphertext
    encrypted_vault_str = base64.b64encode(combined).decode('utf-8')

    vault_path = _get_vault_path(username)
    with open(vault_path, 'w', encoding='utf-8') as f:
        json.dump({"encrypted_vault": encrypted_vault_str, "signature": {}}, f, indent=2)

    sign_vault(username, private_key)

def create_vault(username: str, master_password: str) -> None:
    os.makedirs(VAULTS_DIR, exist_ok=True)
    private_key = load_private_key(username)
    _encrypt_and_save(username, master_password, [], private_key)

def add_credential(username: str, master_password: str, website: str, user: str, password: str) -> None:
    public_key = load_public_key(username)
    if not verify_vault(username, public_key):
        raise ValueError("Vault signature verification failed.")

    entries = _decrypt_vault(username, master_password)

    if any(e.get("website", "").lower() == website.lower() for e in entries):
        raise ValueError("Website already exists. Use update.")

    entries.append({"website": website, "username": user, "password": password})

    private_key = load_private_key(username)
    _encrypt_and_save(username, master_password, entries, private_key)

def get_credential(username: str, master_password: str, website: str):
    public_key = load_public_key(username)
    if not verify_vault(username, public_key):
        raise ValueError("Vault signature verification failed.")

    entries = _decrypt_vault(username, master_password)

    for entry in entries:
        if entry.get("website", "").lower() == website.lower():
            return entry

    print("Website not found.")
    return None

def update_credential(username: str, master_password: str, website: str, new_user: str, new_password: str) -> None:
    public_key = load_public_key(username)
    if not verify_vault(username, public_key):
        raise ValueError("Vault signature verification failed.")

    entries = _decrypt_vault(username, master_password)

    for entry in entries:
        if entry.get("website", "").lower() == website.lower():
            entry["username"] = new_user
            entry["password"] = new_password
            private_key = load_private_key(username)
            _encrypt_and_save(username, master_password, entries, private_key)
            return

    raise ValueError("Website not found.")

def delete_credential(username: str, master_password: str, website: str) -> None:
    public_key = load_public_key(username)
    if not verify_vault(username, public_key):
        raise ValueError("Vault signature verification failed.")

    entries     = _decrypt_vault(username, master_password)
    new_entries = [e for e in entries if e.get("website", "").lower() != website.lower()]

    if len(new_entries) == len(entries):
        raise ValueError("Website not found.")

    private_key = load_private_key(username)
    _encrypt_and_save(username, master_password, new_entries, private_key)