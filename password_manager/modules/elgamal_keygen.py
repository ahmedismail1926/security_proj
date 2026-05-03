import os
import json
import secrets
from Crypto.Util import number
from utils.crypto_utils import mod_exp

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(BASE_DIR, 'keys')
EXPORTS_DIR = os.path.join(BASE_DIR, 'exports')


# ── Safe prime and generator generation ────────────────────────────────────

def generate_safe_prime(bits=64):
    """
    Generate a safe prime p = 2q + 1 where both p and q are prime.
    Uses PyCryptodome's cryptographic prime generation.
    """
    while True:
        q = number.getPrime(bits - 1)
        p = 2 * q + 1
        if number.isPrime(p):
            return p, q


def find_generator(p, q):
    """
    Find a primitive root (generator) modulo a safe prime p = 2q + 1.

    For a safe prime, the only possible element orders are 1, 2, q, and 2q.
    A generator has order 2q = p-1. We check:
        g^2  != 1 (mod p)   → rules out order 1 or 2
        g^q  != 1 (mod p)   → rules out order q
    """
    for g in range(2, p - 1):
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g


def initialize_user(username: str) -> None:
    user_key_dir = os.path.join(KEYS_DIR, username)
    if os.path.exists(user_key_dir):
        raise ValueError("User already initialized.")

    # Generate a safe prime p and find a primitive root alpha
    p, q  = generate_safe_prime()
    alpha = find_generator(p, q)

    x = secrets.randbelow(p - 3) + 2   # Private key x in [2, p-2]

    y = mod_exp(alpha, x, p) # Public key y = alpha^x mod p
    
    os.makedirs(user_key_dir)

    # ── Save private key (mode 0o600: owner read/write only) ───────────────
    priv_key_path = os.path.join(user_key_dir, 'private_key.json')
    priv_data = {
        "x":     str(x),
        "p":     str(p),
        "alpha": str(alpha)
    }
    with open(priv_key_path, 'w', encoding='utf-8') as f:
        json.dump(priv_data, f, indent=2)
    os.chmod(priv_key_path, 0o600)

    # ── Save public key ────────────────────────────────────────────────────
    pub_key_path = os.path.join(user_key_dir, 'public_key.json')
    pub_data = {
        "y":     str(y),
        "p":     str(p),
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
        "p":     int(data["p"]),
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
        "p":     int(data["p"]),
        "alpha": int(data["alpha"])
    }


def export_public_key(username: str, export_path: str) -> None:
    """Write the user's public key to an arbitrary path for sharing."""
    pub = load_public_key(username)
    with open(os.path.join(EXPORTS_DIR, export_path), 'w', encoding='utf-8') as f:
        json.dump(pub, f, indent=2)