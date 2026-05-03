# Secure Password Manager

A cryptographically secure password manager built with Python using ElGamal digital signatures, AES-256-GCM encryption, and a 4-step signed Diffie-Hellman protocol for secure vault export/import.

## Features

- **ElGamal Key Pairs**: Per-user asymmetric keys for digital signatures (Module 1)
- **AES-256-GCM Vault Encryption**: Symmetric encryption with master password derived key (Module 2)
- **Digital Signatures**: ElGamal-based vault integrity verification on every access (Module 3)
- **Secure DH Export/Import**: 4-step signed Diffie-Hellman key exchange for vault transfer (Module 4)
- **Multi-User Support**: Each user has independent keys and vaults
- **GUI + CLI**: Both Tkinter GUI and full command-line interface

## Directory Structure

```
password_manager/
├── main.py                    # CLI entry point
├── config/
│   └── params.json           # Shared ElGamal parameters (q, alpha)
├── keys/
│   └── {username}/
│       ├── private_key.json  # Private key (x, q, alpha) — restricted permissions
│       └── public_key.json   # Public key (y, q, alpha)
├── vaults/
│   └── {username}_vault.json # Encrypted vault + ElGamal signature
├── exports/                  # DH exchange session files
├── gui/
│   ├── app.py               # Tkinter GUI application
│   └── views/
│       ├── init_view.py     # Initialize / Login screen
│       ├── vault_view.py    # Credential management screen
│       └── export_view.py   # 4-step DH export/import screen
├── modules/
│   ├── elgamal_keygen.py    # Key generation (Module 1)
│   ├── vault_manager.py     # Vault encryption/decryption (Module 2)
│   ├── signatures.py        # Digital signatures (Module 3)
│   └── dh_export.py         # Diffie-Hellman export (Module 4)
└── utils/
    └── crypto_utils.py      # Utility functions (mod_exp, SHA-256, etc.)
```

## Installation

### Prerequisites

- Python 3.8+
- pip

### Install Dependencies

```bash
pip install pycryptodome
```

## Running the Application

### Option 1: GUI

```bash
cd password_manager
python gui/app.py
```

### Option 2: CLI (I don't know why you may choose this option instead of GUI but anyway here it is)

All commands are run from the `password_manager/` directory:

```bash
python main.py <command> [args]
```

---

## CLI Usage

### 1. Initialize a New User

Creates ElGamal keys and an empty encrypted vault.

```bash
python main.py init <username>
```

You will be prompted for a master password.

**Example:**
```
> python main.py init alice
Enter new master password: ********
User 'alice' initialized and vault created.
```

---

### 2. Add a Credential

```bash
python main.py add <username>
```

You will be prompted for master password, website, username, and password.

**Example:**
```
> python main.py add alice
Enter master password: ********
Website: github.com
Username: alice_dev
Password: ********
Credential added successfully.
```

---

### 3. Retrieve a Credential

```bash
python main.py get <username> <website>
```

**Example:**
```
> python main.py get alice github.com
Enter master password: ********
Website:  github.com
Username: alice_dev
Password: my_secret_pass
```

---

### 4. Update a Credential

```bash
python main.py update <username> <website>
```

**Example:**
```
> python main.py update alice github.com
Enter master password: ********
New username: alice_new
New password: ********
Credential updated successfully.
```

---

### 5. Delete a Credential

```bash
python main.py delete <username> <website>
```

**Example:**
```
> python main.py delete alice github.com
Enter master password: ********
Credential deleted successfully.
```

---

### 6. Export Public Key

```bash
python main.py export-key <username> <output_filename>
```

**Example:**
```
> python main.py export-key alice alice_pub.json
Public key for 'alice' exported to alice_pub.json.
```

---

### 7. Secure Vault Export/Import (4-Step DH Protocol)

Transfer a vault from one user (sender) to another (receiver) using a signed Diffie-Hellman key exchange. Both users must be initialized first.

#### Step 1 — Sender initiates DH exchange

```bash
python main.py export-step1 <sender> <receiver> <session_name>
```

**Example:**
```
> python main.py export-step1 alice bob mysession
Step 1 complete → send file to receiver
```

Creates `exports/mysession_step1.json` — send this file to the receiver.

#### Step 2 — Receiver responds to DH exchange

```bash
python main.py export-step2 <receiver> <session_name>
```

**Example:**
```
> python main.py export-step2 bob mysession
Step 2 complete → send back to sender
```

Creates `exports/mysession_step2.json` — send this file back to the sender.

#### Step 3 — Sender encrypts and signs the vault

```bash
python main.py export-final <sender> <session_name>
```

**Example:**
```
> python main.py export-final alice mysession
Enter master password: ********
Final export ready → send to receiver
```

Creates `exports/mysession_final.json` — send this file to the receiver.

#### Step 4 — Receiver decrypts and imports the vault

```bash
python main.py import-final <receiver> <session_name>
```

**Example:**
```
> python main.py import-final bob mysession
Enter master password for new vault: ********
Import successful
```

The sender's credentials are now merged into the receiver's vault.

---

## Full CLI Quick-Start Example

```bash
# Initialize two users
python main.py init alice
python main.py init bob

# Alice adds some credentials
python main.py add alice        # adds github.com
python main.py add alice        # adds bank.com

# Alice exports her vault to Bob (4-step DH exchange)
python main.py export-step1 alice bob session1
python main.py export-step2 bob session1
python main.py export-final alice session1
python main.py import-final bob session1

# Bob can now retrieve alice's credentials
python main.py get bob github.com
```

## Security Properties

| Module | Feature | Implementation |
|---|---|---|
| **1** | ElGamal Key Management | Per-user key pair generation, private key stored with 0o600 permissions |
| **2** | Vault Encryption | AES-256-GCM, SHA-256 key derivation from master password |
| **3** | Digital Signatures | ElGamal signatures (from scratch), verified on every vault access |
| **4** | Secure DH Export | 4-step signed ephemeral Diffie-Hellman, AES-GCM session encryption |

## Configuration

### ElGamal Parameters (`config/params.json`)

Shared parameters used for key generation:

```json
{
  "q": "large_prime_number",
  "alpha": "primitive_root_modulo_q"
}
```

### Vault Format (`vaults/{username}_vault.json`)

```json
{
  "encrypted_vault": "base64_encoded_AES-GCM_ciphertext",
  "signature": {
    "r": "elgamal_signature_r",
    "s": "elgamal_signature_s"
  }
}
```

## Troubleshooting

| Issue | Solution |
|---|---|
| `User already initialized` | Use a different username or delete `keys/{username}/` |
| `Wrong master password or vault corrupted` | Re-enter the correct password; no recovery if forgotten |
| `Vault integrity check failed` | Vault file was tampered with; restore from backup |
| Unicode errors on Windows | Run with `python -X utf8 main.py ...` |
| `ModuleNotFoundError: Crypto` | Run `pip install pycryptodome` |

## License

Educational project — Computer Security course.
