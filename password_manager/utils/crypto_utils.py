import hashlib
import secrets

def mod_exp(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a: int, m: int) -> int:
    m0 = m
    y = 0
    x = 1
    if m == 1:
        return 0
    original_a = a
    original_m = m
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if x < 0:
        x = x + m0
    
    # check if gcd is 1
    if gcd(original_a, original_m) != 1:
        raise ValueError("No modular inverse exists")
    return x

def int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def sha256_int(data: bytes) -> int:
    return bytes_to_int(sha256_bytes(data))

def random_in_range(low: int, high: int) -> int:
    if low > high:
        raise ValueError("low must be less than or equal to high")
    return secrets.randbelow(high - low + 1) + low
