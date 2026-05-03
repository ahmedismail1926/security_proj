# Secure Password Manager

A cryptographically secure password manager built with Python using ElGamal encryption, AES-256-GCM, and digital signatures for vault integrity verification.

## Features

- 🔐 **ElGamal Encryption**: Asymmetric cryptography for secure key generation
- 🔒 **AES-256-GCM**: Symmetric encryption for password vault storage
- ✍️ **Digital Signatures**: ElGamal-based signatures to verify vault integrity
- 🛡️ **Safe Primes**: Large prime number generation (2048-bit default)
- 🎨 **GUI Interface**: Tkinter-based user-friendly interface
- 👤 **Multi-User Support**: Each user has independent keys and vaults
- 📤 **Public Key Export**: Share public keys for vault verification

## Architecture

### Directory Structure

```
password_manager/
├── main.py                    # Entry point for CLI (if applicable)
├── config/
│   └── params.json           # ElGamal parameters (p, alpha)
├── keys/                     # User keys directory
│   └── {username}/
│       ├── private_key.json  # Private key (x, p, alpha)
│       └── public_key.json   # Public key (y, p, alpha)
├── vaults/                   # Encrypted vault storage
│   └── {username}_vault.json # Encrypted vault + signature
├── exports/                  # Public key exports
├── gui/
│   ├── app.py               # Main GUI application
│   └── views/
│       ├── init_view.py     # User initialization screen
│       ├── vault_view.py    # Password management screen
│       └── export_view.py   # Public key export screen
├── modules/
│   ├── elgamal_keygen.py    # Key generation & prime generation
│   ├── vault_manager.py     # Vault encryption/decryption
│   ├── signatures.py        # Digital signatures
│   └── dh_export.py         # Diffie-Hellman export (if applicable)
├── utils/
|    └── crypto_utils.py      # Utility cryptographic functions
├── README.md                  # This file

```

## Installation

### Prerequisites

- Python 3.8+
- pip package manager

### Step 1: Install Dependencies

```bash
pip install pycryptodome sympy
```

**Required packages:**
- `pycryptodome`: AES encryption and cryptographic utilities
- `sympy`: Prime number generation and primality testing

### Step 2: Verify Installation

```bash
python -m pip list | grep -i "crypto\|sympy"
```

## Quick Start

### Running the GUI Application

```bash
cd password_manager
python gui/app.py
```

This will launch the Tkinter GUI with three main screens:
- **Init View**: Create a new user account and initialize keys
- **Vault View**: Add, view, update, and delete credentials
- **Export View**: Export your public key for sharing

### Initial Setup Workflow

1. **Start the application**:
   ```bash
   python gui/app.py
   ```

2. **Create a new user** (if first-time use):
   - Enter username and master password
   - The system will generate ElGamal parameters and keys
   - Click "Initialize User"

3. **Access your vault**:
   - Select "Vault View" tab
   - Enter your username and master password
   - Add credentials for websites

4. **Export public key** (optional):
   - Select "Export View" tab
   - Export your public key to share with others for vault verification

## Usage Examples

### Programmatic Usage

```python
from modules.elgamal_keygen import initialize_user, generate_params
from modules.vault_manager import create_vault, add_credential, get_credential

# Initialize a new user with generated ElGamal parameters
initialize_user('alice', generate_new_params=True)

# Create vault for the user
create_vault('alice', master_password='SecurePassword123')

# Add a credential
add_credential('alice', 'SecurePassword123', 'github.com', 'alice_username', 'github_password')

# Retrieve a credential
cred = get_credential('alice', 'SecurePassword123', 'github.com')
print(cred)  # {'website': 'github.com', 'username': 'alice_username', 'password': 'github_password'}

# Update a credential
update_credential('alice', 'SecurePassword123', 'github.com', 'new_username', 'new_password')

# Delete a credential
delete_credential('alice', 'SecurePassword123', 'github.com')
```

### Generating ElGamal Parameters

```python
from modules.elgamal_keygen import generate_params

# Generate new 2048-bit safe prime and primitive root
params = generate_params(bit_length=2048, save_to_config=True)
print(f"Prime p: {params['p']}")
print(f"Generator alpha: {params['alpha']}")
```

## Configuration

### ElGamal Parameters (config/params.json)

The application uses a shared set of ElGamal parameters (p, alpha) stored in `config/params.json`:

```json
{
  "p": "1234567890123456789...",
  "alpha": "2"
}
```

- **p**: A 2048-bit safe prime (p = 2q+1 where both p and q are prime)
- **alpha**: A primitive root modulo p

These parameters are generated automatically on first use or can be pre-configured.

### User Keys

Each user has private and public keys stored in `keys/{username}/`:

**private_key.json** (permissions: 0o600):
```json
{
  "x": "private_exponent",
  "p": "prime",
  "alpha": "generator"
}
```

**public_key.json**:
```json
{
  "y": "public_exponent (alpha^x mod p)",
  "p": "prime",
  "alpha": "generator"
}
```

## Security Features

### 1. Master Password Protection
- Passwords are derived using SHA-256
- Each vault is encrypted with AES-256-GCM using a key derived from the master password

### 2. Vault Integrity
- Each vault is digitally signed using the user's private key
- On access, the signature is verified with the public key
- Any tampering is detected immediately

### 3. Safe Prime Usage
- Primes of form p = 2q+1 (safe primes) ensure strong cryptographic properties
- Primitive roots are verified to generate the full multiplicative group

### 4. Secure Key Storage
- Private keys are stored with restricted file permissions (0o600)
- Keys are never exposed in logs or output

## Security Warnings ⚠️

- **Master Password**: Never forget your master password—there is no recovery mechanism
- **Private Keys**: Protect your `keys/` directory; it contains sensitive private keys
- **Config File**: The `config/params.json` file should be treated as public (p and alpha are not secret)
- **Production Use**: This is an educational implementation. For production, consider using established tools like KeePass or 1Password

## Troubleshooting

### Issue: "Config file not found"
**Solution**: The system will auto-generate parameters on first use. If needed, manually generate:
```python
from modules.elgamal_keygen import generate_params
generate_params(2048, save_to_config=True)
```

### Issue: "User already initialized"
**Solution**: Use a different username or delete the `keys/{username}/` directory to reinitialize.

### Issue: "Wrong master password or vault corrupted"
**Solution**: Ensure you're using the correct master password. If the vault is corrupted, recover from backup.

### Issue: Module import errors
**Solution**: Ensure you're running from the `password_manager/` directory and dependencies are installed:
```bash
pip install pycryptodome sympy
```

## Project Modules

### `elgamal_keygen.py`
- `generate_safe_prime(bit_length)`: Generate large safe primes
- `find_primitive_root(p)`: Find primitive roots modulo p
- `generate_params(bit_length, save_to_config)`: Generate and save ElGamal parameters
- `initialize_user(username, ...)`: Initialize a new user with keys
- `load_private_key(username)`: Load user's private key
- `load_public_key(username)`: Load user's public key

### `vault_manager.py`
- `create_vault(username, master_password)`: Create an encrypted vault
- `add_credential(username, master_password, website, user, password)`: Add credential
- `get_credential(username, master_password, website)`: Retrieve credential
- `update_credential(username, master_password, website, new_user, new_password)`: Update credential
- `delete_credential(username, master_password, website)`: Delete credential

### `signatures.py`
- `sign_vault(username, private_key)`: Sign vault with private key
- `verify_vault(username, public_key)`: Verify vault signature

### `crypto_utils.py`
- `sha256_bytes(data)`: SHA-256 hashing
- `mod_exp(base, exp, mod)`: Modular exponentiation

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| pycryptodome | 3.15+ | AES encryption, SHA-256 |
| sympy | 1.12+ | Prime generation, primality testing |
| tkinter | Built-in | GUI framework |

## Performance Notes

- **Prime Generation**: Generating 2048-bit safe primes takes ~5-30 seconds depending on system
- **Primitive Root Search**: Finding a valid generator takes ~1-5 seconds
- **Vault Operations**: Encryption/decryption is fast (<100ms)

## Future Enhancements

- [ ] CLI interface for non-GUI usage
- [ ] Multi-factor authentication
- [ ] Vault backup and restore
- [ ] Cloud sync support
- [ ] Password strength meter
- [ ] Import/export from other password managers

## License

Educational project for Computer Security course

## Support

For issues or questions, refer to the project documentation or contact the course instructor.
