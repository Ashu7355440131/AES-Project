import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from src.config import (
    BACKUPS_DIRNAME,
    BLOBS_DIRNAME,
    CHUNK_SIZE,
    MANIFEST_FILENAME,
)
from src.core.vault import UnlockedSession
from src.crypto.cipher import encrypt_chunk
from src.crypto.integrity import compute_merkle_root, sign_manifest
from src.crypto.kdf import derive_subkey, generate_salt


class BackupEngine:
    """
    Performs streaming chunk-level AES-256-GCM backup with:
    - Per-file HKDF-derived encryption keys
    - Context-bound AAD per chunk (prevents chunk reordering/swapping)
    - Content-addressed encrypted blob storage
    - Binary Merkle Tree root + Ed25519 signed manifest
    """

    def __init__(self, session: UnlockedSession):
        self.session = session
        self.backups_dir = session.workspace / BACKUPS_DIRNAME
        self.blobs_dir = session.workspace / BLOBS_DIRNAME

    def _collect_files(self, source: Path) -> list[tuple[Path, str]]:
        if not source.exists():
            raise FileNotFoundError(f"Backup source does not exist: {source}")

        if source.is_file():
            return [(source, source.name)]

        files: list[tuple[Path, str]] = []
        for path in sorted(source.rglob("*")):
            if path.is_file():
                rel_posix = path.relative_to(source).as_posix()
                files.append((path, rel_posix))
        return files

    def create_backup(self, source_path: Path, label: str = "snapshot") -> dict:
        files = self._collect_files(source_path)
        backup_id = (
            f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-"
            f"{uuid.uuid4().hex[:8]}"
        )
        backup_dir = self.backups_dir / backup_id
        backup_dir.mkdir(parents=True, exist_ok=True)
        self.blobs_dir.mkdir(parents=True, exist_ok=True)

        key_version = self.session.active_key_version
        active_dek = self.session.keyring[key_version]

        file_entries = []
        merkle_leaves = []
        total_plaintext_bytes = 0
        total_chunks = 0

        for abs_path, rel_path in files:
            file_salt = generate_salt()
            file_key = derive_subkey(
                active_dek,
                info=b"aes-backup-file-aead",
                salt=file_salt,
            )

            file_hasher = hashlib.sha256()
            chunk_records = []
            file_size = abs_path.stat().st_size

            with abs_path.open("rb") as fh:
                chunk_idx = 0
                while True:
                    chunk = fh.read(CHUNK_SIZE)
                    if not chunk and chunk_idx > 0:
                        break

                    # Handle 0-byte empty file cleanly as 1 empty chunk
                    is_last = len(chunk) < CHUNK_SIZE
                    if file_size == 0:
                        is_last = True

                    file_hasher.update(chunk)
                    pt_sha256 = hashlib.sha256(chunk).hexdigest()

                    aad = (
                        f"{backup_id}|{rel_path}|{chunk_idx}|{int(is_last)}"
                    ).encode("utf-8")
                    nonce, ciphertext = encrypt_chunk(file_key, chunk, aad)
                    ct_sha256 = hashlib.sha256(ciphertext).hexdigest()

                    blob_path = self.blobs_dir / f"{ct_sha256}.enc"
                    if not blob_path.exists():
                        blob_path.write_bytes(ciphertext)

                    chunk_records.append(
                        {
                            "index": chunk_idx,
                            "is_last": is_last,
                            "nonce_hex": nonce.hex(),
                            "blob_sha256": ct_sha256,
                            "plaintext_sha256": pt_sha256,
                            "plaintext_size": len(chunk),
                        }
                    )
                    total_chunks += 1
                    chunk_idx += 1

                    if is_last:
                        break

            file_digest = file_hasher.hexdigest()
            total_plaintext_bytes += file_size
            # Bind relative path + content digest in Merkle leaf
            leaf_digest = hashlib.sha256(
                f"{rel_path}:{file_digest}".encode("utf-8")
            ).hexdigest()
            merkle_leaves.append(leaf_digest)

            file_entries.append(
                {
                    "relative_path": rel_path,
                    "size_bytes": file_size,
                    "sha256": file_digest,
                    "file_salt_hex": file_salt.hex(),
                    "chunks": chunk_records,
                }
            )

        merkle_root = compute_merkle_root(merkle_leaves)

        manifest_payload = {
            "backup_id": backup_id,
            "label": label,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "key_version": key_version,
            "cipher_suite": "AES-256-GCM + HKDF-SHA256 + Ed25519",
            "file_count": len(file_entries),
            "total_chunks": total_chunks,
            "total_plaintext_bytes": total_plaintext_bytes,
            "merkle_root": merkle_root,
            "files": file_entries,
        }

        signature_hex = sign_manifest(
            manifest_payload, self.session.signing_private_key
        )

        signed_manifest = {
            "payload": manifest_payload,
            "signature_hex": signature_hex,
        }

        manifest_path = backup_dir / MANIFEST_FILENAME
        manifest_path.write_text(
            json.dumps(signed_manifest, indent=2), encoding="utf-8"
        )

        self.session.audit_logger.log_event(
            "BACKUP_CREATED",
            {
                "backup_id": backup_id,
                "label": label,
                "file_count": len(file_entries),
                "total_chunks": total_chunks,
                "merkle_root": merkle_root,
            },
        )

        return manifest_payload