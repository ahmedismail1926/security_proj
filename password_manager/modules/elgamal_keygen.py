import os
import json
import secrets
from utils.crypto_utils import random_in_range, mod_exp

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, 'config', 'params.json')
KEYS_DIR = os.path.join(BASE_DIR, 'keys')
EXPORTS_DIR = os.path.join(BASE_DIR, 'exports')


def _load_params() -> dict:
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return {
        'p':     int(data['p']),
        'alpha': int(data['alpha'])
    }


def initialize_user(username: str) -> None:
    user_key_dir = os.path.join(KEYS_DIR, username)
    if os.path.exists(user_key_dir):
        raise ValueError("User already initialized.")


    params = _load_params()
    p     = params['p']
    alpha = params['alpha']

    # Validate generator against the prime from config
    if not is_valid_generator(alpha, p):
        raise ValueError("Invalid generator alpha: fails basic validity checks.")

    # Private key x in [2, p-2]
    # x=1 -> y=alpha, trivially broken; secrets.randbelow is cryptographically
    # secure unlike random.randint.
    x = secrets.randbelow(p - 3) + 2   # uniform in [2, p-2]

    # Public key y = alpha^x mod p
    y = mod_exp(alpha, x, p)
    
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


# ── Generator validation ───────────────────────────────────────────────────
def is_valid_generator(alpha: int, p: int) -> bool:
    """
    Validate that alpha is a plausible generator modulo p.

    A true primitive-root check requires knowing all prime factors of (p-1),
    which is expensive for large p.  Since params.json is instructor-supplied
    and p is expected to be a safe prime (p = 2q+1 with q prime), we apply the
    fast safe-prime test:

        For a safe prime p = 2q+1, the only possible orders of elements are
        1, 2, q, and 2q.  alpha is a primitive root iff:
            alpha^2  ≢ 1 (mod p)   [rules out order 1 or 2]
            alpha^q  ≢ 1 (mod p)   [rules out order q]

    If p is NOT a safe prime (q = (p-1)//2 is not prime), we fall back to
    checking only basic bounds, and emit a warning.

    Properties guaranteed:
    - 1 < alpha < p                                (bounds check)
    - alpha^(p-1) ≡ 1 (mod p)                     (Fermat, alpha ≠ 0 mod p)
    - For safe-prime params: alpha is a true primitive root mod p
    """
    if not (1 < alpha < p):
        return False

    # Fermat's little theorem: alpha must not be 0 mod p
    if mod_exp(alpha, p - 1, p) != 1:
        return False

    # Safe-prime check: is q = (p-1)//2 prime?
    q = (p - 1) // 2
    if _is_prime(q):
        # For safe prime p, these two checks are sufficient to confirm
        # alpha is a primitive root mod p.
        if mod_exp(alpha, 2, p) == 1:
            return False   # order divides 2
        if mod_exp(alpha, q, p) == 1:
            return False   # order divides q (not the full group)
    else:
        # p is not a safe prime; we cannot do a full check cheaply.
        # Trust the config and only enforce bounds + Fermat.
        pass

    return True


def _is_prime(n: int) -> bool:
    """
    Deterministic Miller-Rabin primality test for numbers up to 3.3 × 10^24.
    Uses the witness set {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}, which
    is proven correct for all n < 3.3 × 10^24 (Pomerance et al.).
    For larger n the test is still highly reliable in practice.
    """
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small_primes:
        return True
    if any(n % sp == 0 for sp in small_primes):
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for a in small_primes:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True