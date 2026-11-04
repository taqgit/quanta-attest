"""Hash-chained, Ed25519-signed audit ledger and its verifier.

Each record carries the hash of the previous record and its own signature,
so editing, deleting or reordering any record breaks verification at that
point. A signed checkpoint over the last record catches truncation. The
ledger holds hashes and metadata; raw payloads are kept separately.

Signing uses a demo key. In production the key would live in a managed key
vault or HSM, and the checkpoint would also be signed with Sigstore cosign.
"""

from __future__ import annotations

import copy

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GENESIS = "0" * 64
SIGNED_FIELDS = ("seq", "ts", "actor", "event", "meta", "payload_hash", "prev_hash")


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Signer:
    def __init__(self, key: Ed25519PrivateKey | None = None):
        self.key = key or Ed25519PrivateKey.generate()

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self.key.sign(message)).decode()

    def public_pem(self) -> str:
        return self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ))

    @classmethod
    def load_or_create(cls, path: Path) -> "Signer":
        if path.exists():
            return cls(serialization.load_pem_private_key(path.read_bytes(), password=None))
        signer = cls()
        signer.save(path)
        return signer


def load_public_key(pem: str) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(pem.encode())


class Ledger:
    def __init__(self, signer: Signer | None = None):
        self.signer = signer or Signer()
        self.records: list[dict] = []
        self.payloads: dict[str, dict] = {}  # payload_hash -> raw payload, stored apart from the ledger

    def append(self, actor: str, event: str, meta: dict | None = None, payload: dict | None = None) -> dict:
        # Store copies: a caller mutating its own dicts later must not change the record.
        payload = copy.deepcopy(payload or {})
        meta = copy.deepcopy(meta or {})
        payload_hash = sha256(canonical(payload))
        self.payloads[payload_hash] = payload
        record = {
            "seq": len(self.records) + 1,
            "ts": now(),
            "actor": actor,
            "event": event,
            "meta": meta or {},
            "payload_hash": payload_hash,
            "prev_hash": self.records[-1]["record_hash"] if self.records else GENESIS,
        }
        record["record_hash"] = sha256(canonical({k: record[k] for k in SIGNED_FIELDS}))
        record["signature"] = self.signer.sign(bytes.fromhex(record["record_hash"]))
        self.records.append(record)
        return record

    def checkpoint(self) -> dict:
        last = self.records[-1]["record_hash"] if self.records else GENESIS
        body = {"count": len(self.records), "last_hash": last, "ts": now()}
        return {**body, "signature": self.signer.sign(canonical(body))}

    def public_pem(self) -> str:
        return self.signer.public_pem()

    def save(self, folder: Path) -> None:
        folder.mkdir(parents=True, exist_ok=True)
        with (folder / "ledger.jsonl").open("w", encoding="utf-8") as fh:
            for r in self.records:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        (folder / "checkpoint.json").write_text(json.dumps(self.checkpoint(), indent=2), encoding="utf-8")
        (folder / "public_key.pem").write_text(self.public_pem(), encoding="utf-8")


@dataclass
class VerifyResult:
    ok: bool
    count: int
    failed_at: int | None = None  # 1-based position in the file
    reason: str = ""

    def summary(self) -> str:
        if self.ok:
            return f"VALID: {self.count} records, every signature and hash link verified, checkpoint verified"
        return f"FAILED at record {self.failed_at}: {self.reason}"


def verify(records: list[dict], public_pem: str, checkpoint: dict | None = None,
           payloads: dict[str, dict] | None = None) -> VerifyResult:
    """Check order, hash links, record hashes, signatures, optional payloads and the checkpoint."""
    key = load_public_key(public_pem)
    prev = GENESIS
    seqs = {r.get("seq") for r in records}
    for pos, r in enumerate(records, 1):
        try:
            if r["seq"] != pos:
                why = "records are out of order" if pos in seqs else "a record is missing before this one"
                return VerifyResult(False, len(records), pos, f"expected sequence {pos}, found {r['seq']}: {why}")
            if r["prev_hash"] != prev:
                return VerifyResult(False, len(records), pos, "previous-hash link is broken")
            expected = sha256(canonical({k: r[k] for k in SIGNED_FIELDS}))
            if r["record_hash"] != expected:
                return VerifyResult(False, len(records), pos, "record content does not match its hash: it was edited")
            key.verify(base64.b64decode(r["signature"]), bytes.fromhex(r["record_hash"]))
            if payloads is not None and r["payload_hash"] in payloads:
                if sha256(canonical(payloads[r["payload_hash"]])) != r["payload_hash"]:
                    return VerifyResult(False, len(records), pos, "stored payload does not match its hash")
        except InvalidSignature:
            return VerifyResult(False, len(records), pos, "signature does not verify")
        except (KeyError, ValueError, TypeError) as exc:
            return VerifyResult(False, len(records), pos, f"malformed record ({type(exc).__name__})")
        prev = r["record_hash"]

    if checkpoint is not None:
        body = {k: checkpoint[k] for k in ("count", "last_hash", "ts")}
        try:
            key.verify(base64.b64decode(checkpoint["signature"]), canonical(body))
        except InvalidSignature:
            return VerifyResult(False, len(records), None, "checkpoint signature does not verify")
        if checkpoint["count"] != len(records) or checkpoint["last_hash"] != prev:
            return VerifyResult(False, len(records), len(records) + 1 if checkpoint["count"] > len(records) else None,
                                f"checkpoint covers {checkpoint['count']} records; ledger has {len(records)}: records were removed or added")
    return VerifyResult(True, len(records))


def load_folder(folder: Path) -> tuple[list[dict], dict | None, str]:
    records = [json.loads(l) for l in (folder / "ledger.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    cp_path = folder / "checkpoint.json"
    checkpoint = json.loads(cp_path.read_text(encoding="utf-8")) if cp_path.exists() else None
    return records, checkpoint, (folder / "public_key.pem").read_text(encoding="utf-8")
