import argparse
import getpass
import json
import shutil
import sys
from pathlib import Path

from src.config import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_SSS_SHARES,
    DEFAULT_SSS_THRESHOLD,
    DEFAULT_WORKSPACE,
)
from src.core.backup_engine import BackupEngine
from src.core.restore_engine import RestoreEngine
from src.core.vault import KeyVault
from src.crypto.cipher import CryptographicIntegrityError


def _resolve_password(
    provided_password: str | None,
    prompt: str = "Vault Master Password: ",
    confirm: bool = False,
) -> str:
    if provided_password:
        return provided_password
    pwd = getpass.getpass(prompt)
    if confirm:
        pwd2 = getpass.getpass("Confirm Master Password: ")
        if pwd != pwd2:
            raise ValueError("Passwords do not match.")
    return pwd


def cmd_init(args: argparse.Namespace) -> None:
    vault = KeyVault(Path(args.workspace))
    password = _resolve_password(
        args.password, "Create Master Password: ", confirm=True
    )
    shares = vault.initialize(
        password=password,
        sss_threshold=args.threshold,
        sss_shares=args.shares,
        force=args.force,
    )
    print(f"\n[+] Vault initialized at: {vault.workspace.resolve()}")
    print(
        f"[+] Shamir Recovery Scheme: {args.threshold}-of-{args.shares} shares over GF(256)"
    )
    print("[!] STORE THESE RECOVERY SHARES OFFLINE (REQUIRED IF PASSWORD IS LOST):")
    for idx, share in enumerate(shares, start=1):
        print(f"    Share {idx}/{args.shares}: {share}")


def cmd_backup(args: argparse.Namespace) -> None:
    vault = KeyVault(Path(args.workspace))
    password = _resolve_password(args.password)
    session = vault.unlock(password)
    engine = BackupEngine(session)
    manifest = engine.create_backup(Path(args.source), label=args.label)

    print(f"\n[+] Backup Completed Successfully")
    print(f"    Backup ID   : {manifest['backup_id']}")
    print(f"    Label       : {manifest['label']}")
    print(f"    Key Version : v{manifest['key_version']}")
    print(f"    Files       : {manifest['file_count']}")
    print(f"    Chunks      : {manifest['total_chunks']}")
    print(f"    Total Size  : {manifest['total_plaintext_bytes']} bytes")
    print(f"    Merkle Root : {manifest['merkle_root']}")


def cmd_list(args: argparse.Namespace) -> None:
    vault = KeyVault(Path(args.workspace))
    password = _resolve_password(args.password)
    session = vault.unlock(password)
    engine = RestoreEngine(session)
    backups = engine.list_backups()

    if not backups:
        print("No backup snapshots found in vault.")
        return

    print(f"\n{'BACKUP ID':<26} {'LABEL':<16} {'KEY':<5} {'FILES':<6} {'BYTES':<12}")
    print("-" * 72)
    for b in backups:
        print(
            f"{b['backup_id']:<26} {b['label']:<16} v{b['key_version']:<4} "
            f"{b['file_count']:<6} {b['total_plaintext_bytes']:<12}"
        )


def cmd_verify(args: argparse.Namespace) -> None:
    vault = KeyVault(Path(args.workspace))
    password = _resolve_password(args.password)
    session = vault.unlock(password)
    engine = RestoreEngine(session)
    result = engine.verify_or_restore(args.backup_id, destination_dir=None)

    print(f"\n[+] Cryptographic Verification PASSED")
    print(f"    Backup ID       : {result['backup_id']}")
    print(f"    Ed25519 Sig     : VALID")
    print(f"    Merkle Root     : {result['merkle_root']}")
    print(f"    Verified Files  : {result['verified_files']}")
    print(f"    Verified Chunks : {result['verified_chunks']}")


def cmd_restore(args: argparse.Namespace) -> None:
    vault = KeyVault(Path(args.workspace))
    password = _resolve_password(args.password)
    session = vault.unlock(password)
    engine = RestoreEngine(session)
    dest = Path(args.dest)
    result = engine.verify_or_restore(args.backup_id, destination_dir=dest)

    print(f"\n[+] Backup Restored & Authenticated Successfully")
    print(f"    Backup ID      : {result['backup_id']}")
    print(f"    Restored To    : {dest.resolve()}")
    print(f"    Restored Files : {result['verified_files']}")


def cmd_recover_password(args: argparse.Namespace) -> None:
    vault = KeyVault(Path(args.workspace))
    new_password = _resolve_password(
        args.new_password, "Enter New Master Password: ", confirm=True
    )
    vault.recover_password_with_shares(args.shares, new_password)
    print("\n[+] Vault Master Password successfully reset using Shamir Recovery Shares!")


def cmd_rotate_key(args: argparse.Namespace) -> None:
    vault = KeyVault(Path(args.workspace))
    password = _resolve_password(args.password)
    new_ver = vault.rotate_dek(password, args.shares)
    print(f"\n[+] Active Data Encryption Key rotated to Version v{new_ver}.")


def cmd_audit(args: argparse.Namespace) -> None:
    vault = KeyVault(Path(args.workspace))
    password = _resolve_password(args.password)
    session = vault.unlock(password)
    valid, count, msg = session.audit_logger.verify_chain()
    status = "VALID" if valid else "TAMPERED"
    print(f"\n[{status}] {msg} (Entries checked: {count})")
    if not valid:
        sys.exit(1)


def cmd_demo_tamper(args: argparse.Namespace) -> None:
    """
    Demonstrates live AES-GCM ciphertext tamper detection on a cloned workspace.
    """
    src_ws = Path(args.workspace)
    demo_ws = src_ws.parent / f"{src_ws.name}_tamper_sim"
    if demo_ws.exists():
        shutil.rmtree(demo_ws)
    shutil.copytree(src_ws, demo_ws)

    vault = KeyVault(demo_ws)
    password = _resolve_password(args.password)
    session = vault.unlock(password)
    engine = RestoreEngine(session)
    backups = engine.list_backups()
    if not backups:
        print("Create at least one backup before running tamper simulation.")
        return

    target_id = backups[-1]["backup_id"]
    blobs = sorted((demo_ws / "blobs").glob("*.enc"))
    if not blobs:
        print("No encrypted blobs found.")
        return

    # Flip 1 bit inside the first encrypted blob
    victim_blob = blobs[0]
    raw = bytearray(victim_blob.read_bytes())
    raw[-1] ^= 0x01
    victim_blob.write_bytes(bytes(raw))
    print(f"\n[*] Simulated 1-bit flip attack in blob: {victim_blob.name}")

    try:
        engine.verify_or_restore(target_id, destination_dir=demo_ws / "restored_out")
    except CryptographicIntegrityError as exc:
        print(f"[+] ATTACK BLOCKED BY CRYPTOGRAPHIC ENGINE:\n    {exc}")
    finally:
        shutil.rmtree(demo_ws, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure-backup",
        description=f"{APP_NAME} (v{APP_VERSION})",
    )
    parser.add_argument(
        "--workspace",
        default=str(DEFAULT_WORKSPACE),
        help="Path to vault and encrypted backup storage directory",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Master password (omit for secure interactive prompt)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize encrypted vault and Shamir recovery shares")
    p_init.add_argument("--threshold", type=int, default=DEFAULT_SSS_THRESHOLD)
    p_init.add_argument("--shares", type=int, default=DEFAULT_SSS_SHARES)
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_bak = sub.add_parser("backup", help="Encrypt and sign a file or directory snapshot")
    p_bak.add_argument("--source", required=True, help="Source file or folder to back up")
    p_bak.add_argument("--label", default="snapshot", help="Human-readable backup label")
    p_bak.set_defaults(func=cmd_backup)

    p_list = sub.add_parser("list", help="List available encrypted snapshots")
    p_list.set_defaults(func=cmd_list)

    p_ver = sub.add_parser("verify", help="Verify signature, Merkle root, and AES-GCM tags")
    p_ver.add_argument("--backup-id", required=True)
    p_ver.set_defaults(func=cmd_verify)

    p_res = sub.add_parser("restore", help="Authenticate and decrypt a snapshot to disk")
    p_res.add_argument("--backup-id", required=True)
    p_res.add_argument("--dest", required=True, help="Destination output directory")
    p_res.set_defaults(func=cmd_restore)

    p_rec = sub.add_parser("recover-password", help="Reset password using k Shamir shares")
    p_rec.add_argument("--shares", nargs="+", required=True, help="At least k recovery share tokens")
    p_rec.add_argument("--new-password", default=None)
    p_rec.set_defaults(func=cmd_recover_password)

    p_rot = sub.add_parser("rotate-key", help="Rotate active Data Encryption Key (DEK)")
    p_rot.add_argument("--shares", nargs="+", required=True, help="At least k recovery share tokens")
    p_rot.set_defaults(func=cmd_rotate_key)

    p_aud = sub.add_parser("audit", help="Verify HMAC-SHA256 tamper-evident audit log")
    p_aud.set_defaults(func=cmd_audit)

    p_tam = sub.add_parser("demo-tamper", help="Simulate 1-bit ciphertext tampering attack")
    p_tam.set_defaults(func=cmd_demo_tamper)

    return parser