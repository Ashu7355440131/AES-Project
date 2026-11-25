import hashlib
import json
from pathlib import Path

from src.config import BACKUPS_DIRNAME, BLOBS_DIRNAME, MANIFEST_FILENAME
from src.core.vault import UnlockedSession
from src.crypto.cipher import CryptographicIntegrityError, decrypt_chunk
from src.crypto.integrity import compute_merkle_root, verify_manifest_signature
from src.crypto.kdf import derive_subkey


class RestoreEngine:
    """
    Verifies backup authenticity (Ed25519 signature + Merkle root)
    and decrypts AES-256-GCM chunks with strict path-traversal protection.
    """

    def __init__(self, session: UnlockedSession):
        self.session = session
        self.backups_dir = session.workspace / BACKUPS_DIRNAME
        self.blobs_dir = session.workspace / BLOBS_DIRNAME

    def list_backups(self) -> list[dict]:
        if not self.backups_dir.exists():
            return []
        summaries = []
        for entry in sorted(self.backups_dir.iterdir()):
            manifest_file = entry / MANIFEST_FILENAME
            if entry.is_dir() and manifest_file.exists():
                doc = json.loads(manifest_file.read_text(encoding="utf-8"))
                payload = doc["payload"]
                summaries.append(
                    {
                        "backup_id": payload["backup_id"],
                        "label": payload["label"],
                        "created_at": payload["created_at"],
                        "key_version": payload["key_version"],
                        "file_count": payload["file_count"],
                        "total_plaintext_bytes": payload["total_plaintext_bytes"],
                    }
                )
        return summaries

    def _load_and_verify_manifest(self, backup_id: str) -> dict:
        manifest_path = self.backups_dir / backup_id / MANIFEST_FILENAME
        if not manifest_path.exists():
            raise FileNotFoundError(f"Backup snapshot not found: {backup_id}")

        signed_doc = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload = signed_doc["payload"]
        signature_hex = signed_doc["signature_hex"]

        # 1. Verify Ed25519 Digital Signature
        if not verify_manifest_signature(
            payload, signature_hex, self.session.signing_public_key
        ):
            self.session.audit_logger.log_event(
                "SECURITY_ALERT_SIGNATURE_INVALID",
                {"backup_id": backup_id},
            )
            raise CryptographicIntegrityError(
                f"CRITICAL: Ed25519 signature verification failed for backup '{backup_id}'!"
            )

        # 2. Verify Merkle Root
        leaves = [
            hashlib.sha256(
                f"{f['relative_path']}:{f['sha256']}".encode("utf-8")
            ).hexdigest()
            for f in payload["files"]
        ]
        recomputed_root = compute_merkle_root(leaves)
        if recomputed_root != payload["merkle_root"]:
            self.session.audit_logger.log_event(
                "SECURITY_ALERT_MERKLE_MISMATCH",
                {"backup_id": backup_id},
            )
            raise CryptographicIntegrityError(
                f"CRITICAL: Merkle root mismatch for backup '{backup_id}'!"
            )

        return payload

    def _safe_destination_path(self, target_dir: Path, rel_path: str) -> Path:
        """Prevent directory traversal (Zip-Slip) attacks."""
        base = target_dir.resolve()
        dest = (target_dir / rel_path).resolve()
        if base != dest and base not in dest.parents:
            raise ValueError(f"Unsafe path traversal detected in manifest: {rel_path}")
        return dest

    def verify_or_restore(
        self,
        backup_id: str,
        destination_dir: Path | None = None,
    ) -> dict:
        """
        If destination_dir is None, performs a full zero-write cryptographic audit.
        If destination_dir is provided, restores all files after full authentication.
        """
        payload = self._load_and_verify_manifest(backup_id)
        key_version = int(payload["key_version"])
        if key_version not in self.session.keyring:
            raise KeyError(
                f"Key version {key_version} not available in unlocked keyring."
            )

        dek = self.session.keyring[key_version]
        verified_files = 0
        verified_chunks = 0

        for file_meta in payload["files"]:
            rel_path = file_meta["relative_path"]
            file_salt = bytes.fromhex(file_meta["file_salt_hex"])
            file_key = derive_subkey(
                dek,
                info=b"aes-backup-file-aead",
                salt=file_salt,
            )

            out_path: Path | None = None
            out_handle = None
            if destination_dir is not None:
                out_path = self._safe_destination_path(destination_dir, rel_path)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_handle = out_path.open("wb")

            file_hasher = hashlib.sha256()
            try:
                for chunk_meta in file_meta["chunks"]:
                    blob_hash = chunk_meta["blob_sha256"]
                    blob_path = self.blobs_dir / f"{blob_hash}.enc"
                    if not blob_path.exists():
                        raise CryptographicIntegrityError(
                            f"Missing encrypted blob {blob_hash} for '{rel_path}'."
                        )

                    ciphertext = blob_path.read_bytes()
                    if hashlib.sha256(ciphertext).hexdigest() != blob_hash:
                        raise CryptographicIntegrityError(
                            f"Ciphertext digest mismatch on blob {blob_hash}."
                        )

                    aad = (
                        f"{backup_id}|{rel_path}|"
                        f"{chunk_meta['index']}|{int(chunk_meta['is_last'])}"
                    ).encode("utf-8")

                    plaintext = decrypt_chunk(
                        key=file_key,
                        nonce=bytes.fromhex(chunk_meta["nonce_hex"]),
                        ciphertext=ciphertext,
                        aad=aad,
                    )

                    if (
                        hashlib.sha256(plaintext).hexdigest()
                        != chunk_meta["plaintext_sha256"]
                    ):
                        raise CryptographicIntegrityError(
                            f"Plaintext digest mismatch in '{rel_path}' chunk {chunk_meta['index']}."
                        )

                    file_hasher.update(plaintext)
                    if out_handle is not None:
                        out_handle.write(plaintext)
                    verified_chunks += 1
            finally:
                if out_handle is not None:
                    out_handle.close()

            if file_hasher.hexdigest() != file_meta["sha256"]:
                raise CryptographicIntegrityError(
                    f"Full-file SHA-256 mismatch after decryption for '{rel_path}'."
                )
            verified_files += 1

        event_name = (
            "BACKUP_RESTORED" if destination_dir is not None else "BACKUP_VERIFIED"
        )
        self.session.audit_logger.log_event(
            event_name,
            {
                "backup_id": backup_id,
                "verified_files": verified_files,
                "verified_chunks": verified_chunks,
                "destination": str(destination_dir) if destination_dir else "DRY_RUN",
            },
        )

        return {
            "backup_id": backup_id,
            "verified_files": verified_files,
            "verified_chunks": verified_chunks,
            "merkle_root": payload["merkle_root"],
        }