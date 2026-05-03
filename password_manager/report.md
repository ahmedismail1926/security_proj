## Full Workflow 

### Setup: User Initialization

```
User enters username + master password
    │
    ▼
Module 1: Load shared params (q, alpha) from config/params.json
    │
    ▼
Module 1: Generate private key x ∈ [2, q-2]
          Compute public key y = alpha^x mod q
          Save private_key.json (0o600) and public_key.json
    │
    ▼
Module 2: Create empty vault → encrypt with AES-GCM(SHA-256(master_password))
    │
    ▼
Module 3: Sign encrypted vault with user's private key
          Store signature (r, s) in vault file
    │
    ▼
✓ User initialized — keys and empty signed vault created
```

### Store Credentials

```
User provides: website, username, password
    │
    ▼
Module 3: verify_vault() — check ElGamal signature with public key
    │ (if invalid → refuse and alert)
    ▼
Module 2: Decrypt vault with master password (AES-GCM)
    │
    ▼
Append new credential to list (reject if website already exists)
    │
    ▼
Module 2: Re-encrypt entire vault with AES-GCM
    │
    ▼
Module 3: Re-sign vault with user's private key
    │
    ▼
✓ Credential stored — vault is encrypted + signed
```

### Retrieve Credentials

```
User provides: website
    │
    ▼
Module 3: verify_vault() — check signature before any access
    │ (if invalid → "Vault integrity check failed", refuse to open)
    ▼
Module 2: Decrypt vault with master password
    │
    ▼
Search for matching website entry
    │
    ▼
✓ Return credential (or "not found")
```

### Tamper Detection

```
Attacker modifies vault JSON file (even 1 bit)
    │
    ▼
User attempts to access vault
    │
    ▼
Module 3: verify_vault()
    │
    ▼
SHA-256(modified_ciphertext) ≠ original hash
    │
    ▼
alpha^h mod q  ≠  y^r * r^s mod q
    │
    ▼
✗ Signature INVALID — vault refuses to open, user is alerted
```

### Export Vault to Another User

```
Sender (Alice)                          Receiver (Bob)
═══════════════                         ════════════════

Step 1:                                 
  Generate X_A, Y_A = alpha^X_A mod q   
  Sign Y_A → (r, s)                    
  Save step1.json ──────────────────►   

                                        Step 2:
                                          Load step1.json
                                          Verify Alice's signature on Y_A ✓
                                          Generate X_B, Y_B = alpha^X_B mod q
                                          Compute K = Y_A^X_B mod q
                                          Sign Y_B → (r, s)
                                    ◄── Save step2.json

Step 3:                                 
  Load step2.json                       
  Verify Bob's signature on Y_B ✓      
  Compute K = Y_B^X_A mod q            
  session_key = SHA-256(K)             
  Decrypt vault with master password    
  Encrypt with session_key (AES-GCM)   
  Sign encrypted payload               
  Save final.json ─────────────────►   

                                        Step 4:
                                          Load final.json
                                          Verify Alice's signature on payload ✓
                                          Decrypt with session_key
                                          Merge with Bob's existing vault
                                          Re-encrypt with Bob's master password
                                          Re-sign with Bob's private key
                                          ✓ Import complete
```

### Import Behavior

When importing, the receiver's existing credentials are **preserved**. New credentials from the sender are appended. If a website already exists in the receiver's vault, the sender's entry for that website is **skipped** (receiver's version is kept).

---
## Challenges Faced

### 1. DH Parameter Mismatch Between Users
**Problem:** Finding the the primitive root of a prime number is time-costing especially if it's very large (above 16 bits) 
**Solution:** Using a fixed q and alpha for all users to avoid generating new pair each time.
