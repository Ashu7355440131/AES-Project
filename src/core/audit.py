import hmac
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


GENESIS_HASH = "0" * 64


class AuditLogger:
    """
    Append-only HMAC-SHA256 hash-chained audit logger.
    Each record commits to the previous entry's chain_hash to detect deletion or edits.
    """

    def __init__(self, log_path: Path, audit_hmac_key: bytes):
        self.log_path = log_path
        self.audit_hmac_key = audit_hmac_key

    def _compute_entry_hash(self, prev_hash: str, payload_json: str) -> str:
        msg = f"{prev_hash}|{payload_json}".encode("utf-8")
        return hmac.new(self.audit_hmac_key, msg, hashlib.sha256).hexdigest()

    def _get_last_hash(self) -> str:
        if not self.log_path.exists():
            return GENESIS_HASH
        lines = [
            line.strip()
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if not lines:
            return GENESIS_HASH
        last_record = json.loads(lines[-1])
        return last_record["chain_hash"]

    def log_event(self, event_type: str, details: dict) -> str:
        prev_hash = self._get_last_hash()
        body = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "details": details,
        }
        payload_json = json.dumps(body, sort_keys=True, separators=(",", ":"))
        chain_hash = self._compute_entry_hash(prev_hash, payload_json)

        record = {
            "prev_hash": prev_hash,
            "body": body,
            "chain_hash": chain_hash,
        }
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
        return chain_hash

    def verify_chain(self) -> tuple[bool, int, str]:
        """
        Verify full integrity of the audit log chain.
        Returns (is_valid, verified_count, status_message).
        """
        if not self.log_path.exists():
            return True, 0, "Audit log is empty."

        lines = [
            line.strip()
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        expected_prev = GENESIS_HASH

        for idx, line in enumerate(lines, start=1):
            try:
                record = json.loads(line)
                if record["prev_hash"] != expected_prev:
                    return (
                        False,
                        idx - 1,
                        f"Chain broken at entry #{idx}: prev_hash mismatch.",
                    )
                payload_json = json.dumps(
                    record["body"], sort_keys=True, separators=(",", ":")
                )
                recomputed = self._compute_entry_hash(expected_prev, payload_json)
                if not hmac.compare_digest(recomputed, record["chain_hash"]):
                    return (
                        False,
                        idx - 1,
                        f"HMAC verification failed at entry #{idx}: log entry modified.",
                    )
                expected_prev = record["chain_hash"]
            except (KeyError, json.JSONDecodeError) as exc:
                return False, idx - 1, f"Corrupted JSON at entry #{idx}: {exc}"

        return True, len(lines), f"All {len(lines)} audit log entries verified intact."