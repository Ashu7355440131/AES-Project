from pathlib import Path

APP_NAME = "AES-Based Secure Backup and Recovery System"
APP_VERSION = "1.0.0"

# Cryptographic Parameters
AES_KEY_SIZE = 32          # 256-bit AES
GCM_NONCE_SIZE = 12        # 96-bit standard GCM nonce
SALT_SIZE = 16             # 128-bit CSPRNG salt
CHUNK_SIZE = 64 * 1024     # 64 KiB streaming chunk size

# Argon2id Parameters (OWASP recommended baseline)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MiB
ARGON2_PARALLELISM = 4

# Default Shamir's Secret Sharing Threshold
DEFAULT_SSS_THRESHOLD = 3
DEFAULT_SSS_SHARES = 5

# Default Storage Layout
DEFAULT_WORKSPACE = Path("./secure_backup_workspace")
VAULT_FILENAME = "vault.json"
AUDIT_LOG_FILENAME = "audit.log"
BACKUPS_DIRNAME = "backups"
BLOBS_DIRNAME = "blobs"
MANIFEST_FILENAME = "manifest.json"