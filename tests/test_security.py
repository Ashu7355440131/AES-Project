import json
import tempfile
import unittest
from pathlib import Path

from src.core.backup_engine import BackupEngine
from src.core.restore_engine import RestoreEngine
from src.core.vault import KeyVault
from src.crypto.cipher import CryptographicIntegrityError
from src.crypto.recovery import reconstruct_secret_sss, split_secret_sss


class TestAppliedCryptoBackupSystem(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.workspace = self.root / "vault_ws"
        self.source_dir = self.root / "sensitive_docs"
        self.restore_dir = self.root / "restored_docs"

        self.source_dir.mkdir(parents=True)
        (self.source_dir / "keys.txt").write_text(
            "TOP_SECRET_API_KEY=9f86d081884c7d659a2feaa0c55ad015",
            encoding="utf-8",
        )
        nested = self.source_dir / "financials"
        nested.mkdir()
        # Multi-chunk binary file (> 128 KiB to test multi-chunk streaming)
        (nested / "ledger.bin").write_bytes(b"TXN_BLOCK_DATA_" * 10000)

        self.password = "CorrectHorseBatteryStaple!2026"
        self.vault = KeyVault(self.workspace)
        self.shares = self.vault.initialize(
            self.password, sss_threshold=3, sss_shares=5
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_end_to_end_backup_and_restore(self) -> None:
        session = self.vault.unlock(self.password)
        manifest = BackupEngine(session).create_backup(self.source_dir, label="daily")

        res = RestoreEngine(session).verify_or_restore(
            manifest["backup_id"], destination_dir=self.restore_dir
        )
        self.assertEqual(res["verified_files"], 2)
        self.assertEqual(
            (self.restore_dir / "keys.txt").read_text(encoding="utf-8"),
            (self.source_dir / "keys.txt").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            (self.restore_dir / "financials" / "ledger.bin").read_bytes(),
            (self.source_dir / "financials" / "ledger.bin").read_bytes(),
        )

    def test_wrong_password_rejected(self) -> None:
        with self.assertRaises(CryptographicIntegrityError):
            self.vault.unlock("WrongPassword123!")

    def test_aad_chunk_reordering_attack_detected(self) -> None:
        session = self.vault.unlock(self.password)
        manifest = BackupEngine(session).create_backup(self.source_dir)
        backup_id = manifest["backup_id"]

        # Swap chunk 0 and chunk 1 metadata in manifest without re-signing,
        # and even if re-signed with attacker key, signature & AAD both catch it.
        manifest_path = self.workspace / "backups" / backup_id / "manifest.json"
        doc = json.loads(manifest_path.read_text(encoding="utf-8"))
        for f in doc["payload"]["files"]:
            if len(f["chunks"]) >= 2:
                f["chunks"][0]["blob_sha256"], f["chunks"][1]["blob_sha256"] = (
                    f["chunks"][1]["blob_sha256"],
                    f["chunks"][0]["blob_sha256"],
                )
        manifest_path.write_text(json.dumps(doc), encoding="utf-8")

        with self.assertRaises(CryptographicIntegrityError):
            RestoreEngine(session).verify_or_restore(backup_id, self.restore_dir)

    def test_shamir_gf256_password_recovery_and_key_rotation(self) -> None:
        session = self.vault.unlock(self.password)
        manifest_v1 = BackupEngine(session).create_backup(self.source_dir, label="v1")

        # Insufficient shares (2 < 3) must fail
        with self.assertRaises(ValueError):
            reconstruct_secret_sss(self.shares[:2])

        # Any 3 of 5 shares recover access with a brand-new password
        new_pwd = "NewRecoveredMasterPass#99"
        self.vault.recover_password_with_shares(
            [self.shares[0], self.shares[2], self.shares[4]], new_pwd
        )

        # Old password must no longer work
        with self.assertRaises(CryptographicIntegrityError):
            self.vault.unlock(self.password)

        # Rotate DEK to v2
        new_ver = self.vault.rotate_dek(new_pwd, self.shares[1:4])
        self.assertEqual(new_ver, 2)

        # Old v1 backup remains decryptable via keyring
        recovered_session = self.vault.unlock(new_pwd)
        res = RestoreEngine(recovered_session).verify_or_restore(
            manifest_v1["backup_id"], self.restore_dir
        )
        self.assertEqual(res["verified_files"], 2)

    def test_audit_log_tamper_detection(self) -> None:
        session = self.vault.unlock(self.password)
        BackupEngine(session).create_backup(self.source_dir)

        valid, _, _ = session.audit_logger.verify_chain()
        self.assertTrue(valid)

        # Tamper with audit log entry
        log_path = self.workspace / "audit.log"
        tampered = log_path.read_text(encoding="utf-8").replace(
            "BACKUP_CREATED", "BACKUP_DELETED"
        )
        log_path.write_text(tampered, encoding="utf-8")

        valid_after, _, _ = session.audit_logger.verify_chain()
        self.assertFalse(valid_after)


if __name__ == "__main__":
    unittest.main()