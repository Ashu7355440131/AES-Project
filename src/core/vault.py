import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from src.config import (
    AUDIT_LOG_FILENAME,
    BACKUPS_DIRNAME,
    BLOBS_DIRNAME,
    DEFAULT_SSS_SHARES,
    DEFAULT_SSS_THRESHOLD,
    VAULT_FILENAME,
)
from src.core.audit import AuditLogger
from src.crypto.cipher import generate_aes_key, unwrap_key, wrap_key
from src.crypto.integrity import generate_signing_keypair
from src.crypto.kdf import derive_master_key, derive_subkey, generate_salt
from src.crypto.recovery import reconstruct_secret_sss, split_secret_sss


@dataclass
class UnlockedSession:
    workspace: Path
    active_key_version: int
    keyring: dict[int, bytes]
    signing_private_key: bytes
    signing_public_key: bytes
    audit_logger: AuditLogger


class KeyVault:
    """
    Manages the cryptographic keystore:
    - Argon2id + HKDF password-based KEK
    - Envelope-wrapped DEK keyring (supports seamless key rotation)
    - Recovery Encryption Key (REK) split via GF(256) Shamir's Secret Sharing
    - Encrypted Ed25519 manifest signing keypair
    """

    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.vault_path = workspace / VAULT_FILENAME
        self.audit_path = workspace / AUDIT_LOG_FILENAME
        self.backups_dir = workspace / BACKUPS_DIRNAME
        self.blobs_dir = workspace / BLOBS_DIRNAME

    def exists(self) -> bool:
        return self.vault_path.exists()

    def initialize(
        self,
        password: str,
        sss_threshold: int = DEFAULT_SSS_THRESHOLD,
        sss_shares: int = DEFAULT_SSS_SHARES,
        force: bool = False,
    ) -> list[str]:
        if self.exists() and not force:
            raise FileExistsError(
                f"Vault already exists at {self.vault_path}. Use --force to overwrite."
            )

        self.workspace.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        self.blobs_dir.mkdir(parents=True, exist_ok=True)

        kdf_salt = generate_salt()
        master_key = derive_master_key(password, kdf_salt)

        password_kek = derive_subkey(master_key, b"aes-backup-password-kek")
        audit_key = derive_subkey(master_key, b"aes-backup-audit-hmac")

        # Primary Data Encryption Key (v1) & Recovery Encryption Key (REK)
        dek_v1 = generate_aes_key()
        rek = generate_aes_key()

        # Ed25519 signing keypair for manifest authenticity
        sign_priv, sign_pub = generate_signing_keypair()

        vault_doc = {
            "version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "kdf": {
                "algorithm": "Argon2id",
                "salt_hex": kdf_salt.hex(),
            },
            "active_key_version": 1,
            "keyring": {
                "1": {
                    "wrapped_dek_password_hex": wrap_key(password_kek, dek_v1).hex(),
                    "wrapped_dek_recovery_hex": wrap_key(rek, dek_v1).hex(),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            },
            "signing": {
                "algorithm": "Ed25519",
                "public_key_hex": sign_pub.hex(),
                "wrapped_private_key_hex": wrap_key(dek_v1, sign_priv).hex(),
            },
            "audit": {
                "wrapped_audit_key_password_hex": wrap_key(password_kek, audit_key).hex(),
                "wrapped_audit_key_recovery_hex": wrap_key(rek, audit_key).hex(),
            },
            "recovery": {
                "scheme": "GF256-Shamir-Secret-Sharing",
                "threshold": sss_threshold,
                "total_shares": sss_shares,
            },
        }

        self.vault_path.write_text(
            json.dumps(vault_doc, indent=2), encoding="utf-8"
        )

        # Split REK into Shamir shares; REK is never stored on disk
        recovery_shares = split_secret_sss(
            rek, threshold=sss_threshold, total_shares=sss_shares
        )

        logger = AuditLogger(self.audit_path, audit_key)
        logger.log_event(
            "VAULT_INITIALIZED",
            {
                "active_key_version": 1,
                "sss_threshold": sss_threshold,
                "sss_total_shares": sss_shares,
            },
        )
        return recovery_shares

    def unlock(self, password: str) -> UnlockedSession:
        if not self.exists():
            raise FileNotFoundError(
                f"No vault found at {self.vault_path}. Run 'init' first."
            )

        vault_doc = json.loads(self.vault_path.read_text(encoding="utf-8"))
        kdf_salt = bytes.fromhex(vault_doc["kdf"]["salt_hex"])
        master_key = derive_master_key(password, kdf_salt)
        password_kek = derive_subkey(master_key, b"aes-backup-password-kek")

        keyring: dict[int, bytes] = {}
        for ver_str, entry in vault_doc["keyring"].items():
            wrapped = bytes.fromhex(entry["wrapped_dek_password_hex"])
            keyring[int(ver_str)] = unwrap_key(password_kek, wrapped)

        active_ver = int(vault_doc["active_key_version"])
        # Signing private key is wrapped under DEK v1 (root identity key)
        root_dek = keyring[1]
        sign_priv = unwrap_key(
            root_dek,
            bytes.fromhex(vault_doc["signing"]["wrapped_private_key_hex"]),
        )
        sign_pub = bytes.fromhex(vault_doc["signing"]["public_key_hex"])

        audit_key = unwrap_key(
            password_kek,
            bytes.fromhex(vault_doc["audit"]["wrapped_audit_key_password_hex"]),
        )
        logger = AuditLogger(self.audit_path, audit_key)

        return UnlockedSession(
            workspace=self.workspace,
            active_key_version=active_ver,
            keyring=keyring,
            signing_private_key=sign_priv,
            signing_public_key=sign_pub,
            audit_logger=logger,
        )

    def recover_password_with_shares(
        self,
        share_tokens: list[str],
        new_password: str,
    ) -> None:
        """
        Reconstruct the Recovery Encryption Key (REK) from k Shamir shares,
        unwrap all DEKs and the audit key, and re-bind the vault to `new_password`.
        """
        if not self.exists():
            raise FileNotFoundError(f"No vault found at {self.vault_path}.")

        rek = reconstruct_secret_sss(share_tokens)
        vault_doc = json.loads(self.vault_path.read_text(encoding="utf-8"))

        # Unwrap existing DEKs and audit key using REK
        unwrapped_deks: dict[str, bytes] = {}
        for ver_str, entry in vault_doc["keyring"].items():
            wrapped_rek = bytes.fromhex(entry["wrapped_dek_recovery_hex"])
            unwrapped_deks[ver_str] = unwrap_key(rek, wrapped_rek)

        audit_key = unwrap_key(
            rek,
            bytes.fromhex(vault_doc["audit"]["wrapped_audit_key_recovery_hex"]),
        )

        # Derive new password KEK with fresh salt
        new_salt = generate_salt()
        new_master = derive_master_key(new_password, new_salt)
        new_password_kek = derive_subkey(new_master, b"aes-backup-password-kek")

        vault_doc["kdf"]["salt_hex"] = new_salt.hex()
        for ver_str, dek in unwrapped_deks.items():
            vault_doc["keyring"][ver_str]["wrapped_dek_password_hex"] = wrap_key(
                new_password_kek, dek
            ).hex()

        vault_doc["audit"]["wrapped_audit_key_password_hex"] = wrap_key(
            new_password_kek, audit_key
        ).hex()

        self.vault_path.write_text(
            json.dumps(vault_doc, indent=2), encoding="utf-8"
        )

        logger = AuditLogger(self.audit_path, audit_key)
        logger.log_event(
            "PASSWORD_RECOVERED_VIA_SHAMIR",
            {"shares_used": len(share_tokens)},
        )

    def rotate_dek(self, password: str, share_tokens: list[str]) -> int:
        """
        Generate a new active DEK version while preserving older DEKs in the keyring
        so historical backups remain restorable.
        """
        session = self.unlock(password)
        rek = reconstruct_secret_sss(share_tokens)

        vault_doc = json.loads(self.vault_path.read_text(encoding="utf-8"))
        kdf_salt = bytes.fromhex(vault_doc["kdf"]["salt_hex"])
        password_kek = derive_subkey(
            derive_master_key(password, kdf_salt),
            b"aes-backup-password-kek",
        )

        new_ver = int(vault_doc["active_key_version"]) + 1
        new_dek = generate_aes_key()

        vault_doc["active_key_version"] = new_ver
        vault_doc["keyring"][str(new_ver)] = {
            "wrapped_dek_password_hex": wrap_key(password_kek, new_dek).hex(),
            "wrapped_dek_recovery_hex": wrap_key(rek, new_dek).hex(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        self.vault_path.write_text(
            json.dumps(vault_doc, indent=2), encoding="utf-8"
        )
        session.audit_logger.log_event(
            "DEK_KEY_ROTATED",
            {"new_active_key_version": new_ver},
        )
        return new_ver