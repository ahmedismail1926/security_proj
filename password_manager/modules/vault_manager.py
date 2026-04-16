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
        raw = base64.b64decode(stored_string)
        nonce = raw[:16]
        tag = raw[16:32]
        ciphertext = raw[32:]
        
        data_key = sha256_bytes(master_password.encode('utf-8'))
        cipher = AES.new(data_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(plaintext.decode('utf-8'))
    except Exception:
        raise ValueError("Wrong master password or vault corrupted.")

def _encrypt_and_save(username: str, master_password: str, entries: list, private_key: dict) -> None:
    data_key = sha256_bytes(master_password.encode('utf-8'))
    cipher = AES.new(data_key, AES.MODE_GCM) # Nonce is generated fresh
    
    plaintext_bytes = json.dumps(entries).encode('utf-8')
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    
    nonce = cipher.nonce
    combined = nonce + tag + ciphertext
    encrypted_vault_string = base64.b64encode(combined).decode('utf-8')
    
    # Needs to format properly and allow sign_vault to inject the signature after base schema is placed.

    # vault_data = {
    #     "encrypted_vault": encrypted_vault_string,
    #     "signature": {}
    # }

    # NEW:The digital signature is computed over the encrypted vault content to ensure integrity.
    vault_data = {
    "encrypted_vault": encrypted_vault_string
    }
    signature = sign_vault(username, private_key, encrypted_vault_string)
    vault_data["signature"] = signature

    vault_path = _get_vault_path(username)
    temp_path = vault_path + ".tmp"
    
    with open(temp_path, 'w', encoding='utf-8') as f:
        json.dump(vault_data, f, indent=2)
        
    os.replace(temp_path, vault_path)
    
    #sign_vault(username, private_key)

def create_vault(username: str, master_password: str) -> None:
    private_key = load_private_key(username)
    # create_vault bootstraps an empty vault.
    # Write the base schema to file first, THEN let _encrypt_and_save do the payload setup.
    vault_path = _get_vault_path(username)
    with open(vault_path, 'w', encoding='utf-8') as f:
        json.dump({"encrypted_vault": "", "signature": {}}, f)
        
    _encrypt_and_save(username, master_password, [], private_key)

def add_credential(username: str, master_password: str, website: str, user: str, password: str) -> None:
    public_key = load_public_key(username) 
    if not verify_vault(username, public_key): # give it  a look: Semary
        raise ValueError("Vault signature verification failed.")
        
    entries = _decrypt_vault(username, master_password)
    
    website_lower = website.lower()
    for entry in entries:
        if entry.get("website", "").lower() == website_lower:
            raise ValueError("Website already exists. Use update.")
            
    entries.append({
        "website": website,
        "username": user,
        "password": password
    })
    
    private_key = load_private_key(username)
    _encrypt_and_save(username, master_password, entries, private_key)

def get_credential(username: str, master_password: str, website: str):
    public_key = load_public_key(username)
    if not verify_vault(username, public_key):
        raise ValueError("Vault signature verification failed.")
        
    entries = _decrypt_vault(username, master_password)
    
    website_lower = website.lower()
    for entry in entries:
        if entry.get("website", "").lower() == website_lower:
            return entry
            
    print("Website not found.")
    return None

def update_credential(username: str, master_password: str, website: str, new_user: str, new_password: str) -> None:
    public_key = load_public_key(username)
    if not verify_vault(username, public_key):
        raise ValueError("Vault signature verification failed.")
        
    entries = _decrypt_vault(username, master_password)
    
    website_lower = website.lower()
    found = False
    for entry in entries:
        if entry.get("website", "").lower() == website_lower:
            entry["username"] = new_user
            entry["password"] = new_password
            found = True
            break
            
    if not found:
        raise ValueError("Website not found.")
        
    private_key = load_private_key(username)
    _encrypt_and_save(username, master_password, entries, private_key)

def delete_credential(username: str, master_password: str, website: str) -> None:
    public_key = load_public_key(username)
    if not verify_vault(username, public_key):
        raise ValueError("Vault signature verification failed.")
        
    entries = _decrypt_vault(username, master_password)
    
    website_lower = website.lower()
    new_entries = [entry for entry in entries if entry.get("website", "").lower() != website_lower]
    
    if len(new_entries) == len(entries):
        raise ValueError("Website not found.")
        
    private_key = load_private_key(username)
    _encrypt_and_save(username, master_password, new_entries, private_key)
