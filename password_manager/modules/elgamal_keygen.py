import os
import json
from utils.crypto_utils import random_in_range, mod_exp

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, 'config', 'params.json')
KEYS_DIR = os.path.join(BASE_DIR, 'keys')

def _load_params() -> dict:
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return {
        'p': int(data['p']),
        'alpha': int(data['alpha'])
    }

def initialize_user(username: str) -> None:
    user_key_dir = os.path.join(KEYS_DIR, username)
    if os.path.exists(user_key_dir):
        raise ValueError("User already initialized.")
    
    os.makedirs(user_key_dir)
    
    params = _load_params()
    p = params['p']
    alpha = params['alpha']
    
    # 2. Generate private key x: random integer in range [2, p-2]
    x = random_in_range(2, p - 2)
    
    # 3. Compute public key y = pow(alpha, x, p)
    y = mod_exp(alpha, x, p)
    
    # 4. Save private key
    priv_key_path = os.path.join(user_key_dir, 'private_key.json')
    priv_data = {
        "x": str(x),
        "p": str(p),
        "alpha": str(alpha)
    }
    with open(priv_key_path, 'w', encoding='utf-8') as f:
        json.dump(priv_data, f, indent=2)
        
    # 5. Save public key
    pub_key_path = os.path.join(user_key_dir, 'public_key.json')
    pub_data = {
        "y": str(y),
        "p": str(p),
        "alpha": str(alpha)
    }
    with open(pub_key_path, 'w', encoding='utf-8') as f:
        json.dump(pub_data, f, indent=2)

def load_private_key(username: str) -> dict:
    priv_key_path = os.path.join(KEYS_DIR, username, 'private_key.json')
    with open(priv_key_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return {
        "x": int(data["x"]),
        "p": int(data["p"]),
        "alpha": int(data["alpha"])
    }

def load_public_key(username: str) -> dict:
    pub_key_path = os.path.join(KEYS_DIR, username, 'public_key.json')
    with open(pub_key_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return {
        "y": int(data["y"]),
        "p": int(data["p"]),
        "alpha": int(data["alpha"])
    }
