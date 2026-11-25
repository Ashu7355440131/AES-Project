# AES-Based Secure Backup and Recovery System

A zero-trust, command-line encrypted backup and disaster recovery system built with Python. It combines **Envelope Encryption**, **Authenticated Encryption with Associated Data (AEAD)**, **Merkle Tree + Ed25519 Digital Signatures**, **$GF(2^8)$ Shamir's Secret Sharing**, and an **HMAC-SHA256 Hash-Chained Audit Log** to guarantee confidentiality, tamper resistance, and password-independent key recovery.

---

## Cryptographic Architecture

* **Memory-Hard Key Derivation (`Argon2id` + `HKDF-SHA256`):** Derives a 256-bit Master Key from the user's passphrase (`64 MiB` memory cost, `3` iterations, `4` lanes) and expands it into domain-separated subkeys (`password_kek` and `audit_key`).
* **Envelope Encryption (`RFC 3394 AES-256-KW`):** A randomly generated 256-bit Data Encryption Key (`DEK`) is wrapped under both the password KEK and a separate Recovery Encryption Key (`REK`), enabling instant key rotation and zero-re-encryption password resets.
* **Streaming Chunk Encryption (`AES-256-GCM` + Context `AAD`):** Files are encrypted in `64 KiB` chunks under unique `HKDF`-derived per-file keys and 96-bit CSPRNG nonces. Each chunk binds `backup_id | relative_path | chunk_index | is_last` into its Additional Authenticated Data (`AAD`) to prevent bit-flipping, chunk reordering, and cross-file substitution attacks.
* **Snapshot Authenticity (`SHA-256 Merkle Tree` + `Ed25519`):** Builds a domain-separated binary Merkle root over all backed-up files and signs the canonical JSON manifest with an `Ed25519` private key.
* **Threshold Disaster Recovery (`GF(2^8)` Shamir's Secret Sharing):** Splits the 256-bit `REK` into $N$ portable recovery shares over Galois Field $GF(2^8)$ ($x^8 + x^4 + x^3 + x + 1$) so any $K$ shares can reconstruct vault access via Lagrange interpolation if the master password is lost.
* **Tamper-Evident Audit Logging (`HMAC-SHA256` Chain):** Appends every lifecycle operation to `audit.log`, cryptographically chaining each record to the previous entry's digest.

---

## Project Structure

```text
AES-Project/
├── main.py                     # CLI entry point
├── requirements.txt            # Python dependencies (cryptography>=42.0.0)
├── sample_data/                # Sample input directory for quick testing
│   └── report.txt
├── src/
│   ├── config.py               # Cryptographic constants & workspace paths
│   ├── cli/
│   │   └── commands.py         # CLI subcommand parsers & handlers
│   ├── core/
│   │   ├── audit.py            # HMAC-SHA256 hash-chained audit logger
│   │   ├── vault.py            # Keyring, Argon2id unlock, SSS recovery & key rotation
│   │   ├── backup_engine.py    # Streaming AES-256-GCM backup & Merkle manifest builder
│   │   └── restore_engine.py   # Signature/Merkle verification & Zip-Slip-safe restore
│   └── crypto/
│       ├── kdf.py              # Argon2id & HKDF-SHA256 key derivation
│       ├── cipher.py           # AES-256-KW key wrap & AES-256-GCM chunk AEAD
│       ├── integrity.py        # Domain-separated Merkle tree & Ed25519 signing
│       └── recovery.py         # GF(2^8) finite-field arithmetic & Shamir Secret Sharing
└── tests/
    └── test_security.py        # Automated security & attack-simulation unit tests
```

---

## Setup & Installation

### 1. Clone the Repository
```bash
git clone [https://github.com/Ashu7355440131/AES-Project.git](https://github.com/Ashu7355440131/AES-Project.git)
cd AES-Project
```

### 2. Create and Activate a Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## Running the Automated Security Test Suite

Run the unit tests to verify multi-chunk encryption, wrong-password rejection, chunk-reordering attack detection, $GF(2^8)$ Shamir recovery, key rotation, and audit-log tamper detection:

```bash
python -m unittest discover -s tests -v
```

---

## Step-by-Step Usage Guide

> **Note:** This repository includes a pre-generated sample workspace (`secure_backup_workspace/`). To run a fresh demonstration from scratch, remove it first or pass `--force` to `init`.

### Step 1: Initialize a New Cryptographic Vault (`init`)
Creates a new vault protected by a master password and outputs `3-of-5` Shamir recovery shares:

```bash
# Optional: remove pre-existing demo workspace first
rm -rf secure_backup_workspace restored_output   # PowerShell: Remove-Item -Recurse -Force secure_backup_workspace, restored_output -ErrorAction SilentlyContinue

python main.py --password "StrongVaultPassword@2026" init --threshold 3 --shares 5
```
*Save at least **3** of the printed `SSS-3-5-...` recovery share tokens for Steps 6 and 7.*

### Step 2: Create an Encrypted & Signed Backup Snapshot (`backup`)
Encrypts the `sample_data/` folder (or any target file/directory):

```bash
python main.py --password "StrongVaultPassword@2026" backup --source ./sample_data --label "milestone-1"
```
*Note the printed **Backup ID** (e.g., `20261121T062549Z-e85cf04d`).*

### Step 3: List, Verify, and Restore Snapshots (`list`, `verify`, `restore`)
Replace `YOUR_BACKUP_ID` with the Backup ID generated in Step 2:

```bash
# List all snapshots in the vault
python main.py --password "StrongVaultPassword@2026" list

# Perform a zero-write cryptographic verification (Ed25519 + Merkle + AES-GCM tags)
python main.py --password "StrongVaultPassword@2026" verify --backup-id YOUR_BACKUP_ID

# Authenticate and decrypt files to ./restored_output
python main.py --password "StrongVaultPassword@2026" restore --backup-id YOUR_BACKUP_ID --dest ./restored_output
```

### Step 4: Simulate a Live 1-Bit Ciphertext Tamper Attack (`demo-tamper`)
Clones the workspace, flips a single bit inside an encrypted `.enc` blob, and demonstrates immediate `AES-256-GCM` tag rejection:

```bash
python main.py --password "StrongVaultPassword@2026" demo-tamper
```

### Step 5: Verify the Tamper-Evident Audit Log (`audit`)
Validates the entire `HMAC-SHA256` hash chain inside `secure_backup_workspace/audit.log`:

```bash
python main.py --password "StrongVaultPassword@2026" audit
```

### Step 6: Recover a Forgotten Master Password (`recover-password`)
Reconstructs the Recovery Encryption Key (`REK`) from any **3** Shamir shares and resets the vault password without re-encrypting backup blobs:

```bash
python main.py recover-password --new-password "ResetMasterPassword@2026" --shares "SHARE_1" "SHARE_3" "SHARE_5"
```

### Step 7: Rotate the Active Data Encryption Key (`rotate-key`)
Generates a new active Data Encryption Key (`v2`) while retaining `v1` in the keyring so older snapshots remain restorable:

```bash
python main.py --password "ResetMasterPassword@2026" rotate-key --shares "SHARE_1" "SHARE_2" "SHARE_4"
```

---

## CLI Command Reference

| Command | Description | Key Flags |
| :--- | :--- | :--- |
| `init` | Initialize vault, Ed25519 keys, and Shamir recovery shares | `--threshold N`, `--shares N`, `--force` |
| `backup` | Encrypt & sign a file or folder snapshot | `--source PATH`, `--label TEXT` |
| `list` | List all stored backup snapshots and key versions | — |
| `verify` | Verify Ed25519 signature, Merkle root, and GCM tags | `--backup-id ID` |
| `restore` | Authenticate and decrypt snapshot files to disk | `--backup-id ID`, `--dest PATH` |
| `recover-password` | Reset master password using $K$ Shamir shares | `--shares S1 S2 ...`, `--new-password PWD` |
| `rotate-key` | Rotate active DEK to a new version (`v2`, `v3`, ...) | `--shares S1 S2 ...` |
| `audit` | Verify integrity of the HMAC-SHA256 audit log chain | — |
| `demo-tamper` | Simulate a 1-bit ciphertext modification attack | — |
