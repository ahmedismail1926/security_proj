import os
import json
import secrets
from Crypto.Util import number
from utils.crypto_utils import mod_exp

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(BASE_DIR, 'keys')
EXPORTS_DIR = os.path.join(BASE_DIR, 'exports')
CONFIG_PATH = os.path.join(BASE_DIR, 'config')


# def generate_prime(bits=64):
#     q = number.getPrime(bits - 1)
#     return q


# def find_primitive_root(p):
#     for a in range(2, p):
#         generated_numbers = set()
        
#         for power in range(1, p):
#             result = pow(a, power, p)
            
#             if result in generated_numbers:
#                 break      

#             generated_numbers.add(result)
    
#         if len(generated_numbers) == p - 1:
#             return a 

#     return None

def _load_params() -> dict:
    params_path = os.path.join(CONFIG_PATH, 'params.json')
    with open(params_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return {
        'q':     int(data['q']),
        'alpha': int(data['alpha'])
    }


def initialize_user(username: str) -> None:
    user_key_dir = os.path.join(KEYS_DIR, username)
    if os.path.exists(user_key_dir):
        raise ValueError("User already initialized.")

    # q     = generate_prime()
    # alpha = find_primitive_root(q)
    params = _load_params()
    q = params['q']
    alpha = params['alpha']

    x = secrets.randbelow(q - 3) + 2   # Private key x in [2, q-2]

    y = mod_exp(alpha, x, q) # Public key y = alpha^x mod q
    
    os.makedirs(user_key_dir)

    # ── Save private key (mode 0o600: owner read/write only) ───────────────
    priv_key_path = os.path.join(user_key_dir, 'private_key.json')
    priv_data = {
        "x":     str(x),
        "q":     str(q),
        "alpha": str(alpha)
    }
    with open(priv_key_path, 'w', encoding='utf-8') as f:
        json.dump(priv_data, f, indent=2)
    os.chmod(priv_key_path, 0o600)

    # ── Save public key ────────────────────────────────────────────────────
    pub_key_path = os.path.join(user_key_dir, 'public_key.json')
    pub_data = {
        "y":     str(y),
        "q":     str(q),
        "alpha": str(alpha)
    }
    with open(pub_key_path, 'w', encoding='utf-8') as f:
        json.dump(pub_data, f, indent=2)


def load_private_key(username: str) -> dict:
    priv_key_path = os.path.join(KEYS_DIR, username, 'private_key.json')
    if not os.path.exists(priv_key_path):
        raise FileNotFoundError("Private key not found. Run 'init' first.")
    with open(priv_key_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return {
        "x":     int(data["x"]),
        "q":     int(data["q"]),
        "alpha": int(data["alpha"])
    }


def load_public_key(username: str) -> dict:
    pub_key_path = os.path.join(KEYS_DIR, username, 'public_key.json')
    if not os.path.exists(pub_key_path):
        raise FileNotFoundError("Public key not found for user.")
    with open(pub_key_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return {
        "y":     int(data["y"]),
        "q":     int(data["q"]),
        "alpha": int(data["alpha"])
    }


def export_public_key(username: str, export_path: str) -> None:
    pub = load_public_key(username)
    with open(os.path.join(EXPORTS_DIR, export_path), 'w', encoding='utf-8') as f:
        json.dump(pub, f, indent=2)