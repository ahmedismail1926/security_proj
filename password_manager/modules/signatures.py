import os
import json
from utils.crypto_utils import sha256_int, random_in_range, gcd, mod_exp, mod_inverse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VAULTS_DIR = os.path.join(BASE_DIR, 'vaults')

def sign(message_bytes: bytes, private_key: dict) -> tuple[int, int]:
    q = private_key['q']
    alpha = private_key['alpha']
    x = private_key['x']
    
    h = sha256_int(message_bytes) % (q - 1)
    if h == 0:
        h = 1
        
    for _ in range(1000):
        k = random_in_range(2, q - 2)
        if gcd(k, q - 1) != 1:
            continue
            
        r = mod_exp(alpha, k, q)
        if r == 0:
            continue
            
        try:
            k_inv = mod_inverse(k, q - 1)
        except ValueError:
            continue
            
        s = (k_inv * (h - x * r)) % (q - 1)
        if s == 0:
            continue
            
        return r, s
        
    raise RuntimeError("Failed to generate signature within iteration limit")

def verify(message_bytes: bytes, signature: tuple[int, int], public_key: dict) -> bool:
    r, s = signature
    q = public_key['q']
    alpha = public_key['alpha']
    y = public_key['y']
    
    if not (1 <= r <= q - 1):
        return False
    if not (1 <= s <= q - 2):
        return False
        
    h = sha256_int(message_bytes) % (q - 1)
    if h == 0:
        h = 1
        
    v1 = mod_exp(alpha, h, q)
    v2 = (mod_exp(y, r, q) * mod_exp(r, s, q)) % q
    
    return v1 == v2

def sign_vault(username: str, private_key: dict) -> None:
    vault_path = os.path.join(VAULTS_DIR, f"{username}_vault.json")
    with open(vault_path, 'r', encoding='utf-8') as f:
        vault_data = json.load(f)
        
    encrypted_vault_string = vault_data.get("encrypted_vault", "")
    message_bytes = encrypted_vault_string.encode('utf-8')
    
    r, s = sign(message_bytes, private_key)
    
    vault_data["signature"] = {
        "r": str(r),
        "s": str(s)
    }
    
    with open(vault_path, 'w', encoding='utf-8') as f:
        json.dump(vault_data, f, indent=2)

def verify_vault(username: str, public_key: dict) -> bool:
    vault_path = os.path.join(VAULTS_DIR, f"{username}_vault.json")
    if not os.path.exists(vault_path):
        return False
        
    with open(vault_path, 'r', encoding='utf-8') as f:
        vault_data = json.load(f)
        
    if "signature" not in vault_data or not vault_data["signature"]:
        return False
        
    sig_data = vault_data["signature"]
    if "r" not in sig_data or "s" not in sig_data:
        return False
        
    try:
        r = int(sig_data["r"])
        s = int(sig_data["s"])
    except ValueError:
        return False
        
    if r == 0 or s == 0:
        return False
        
    encrypted_vault_string = vault_data.get("encrypted_vault", "")
    if not encrypted_vault_string:
        raise ValueError("Vault is empty or corrupted")
    
    message_bytes = encrypted_vault_string.encode('utf-8')
    
    return verify(message_bytes, (r, s), public_key)
