"""Tamper-evident audit log (hash chain).

REAL IMPLEMENTATION.

    record_n.hash = SHA256( canonical_json( {seq, ts, event_id, event_type,
                                             actor, asset, details, prev_hash} ) )
    record_n.prev_hash = record_{n-1}.hash      (genesis prev_hash = 64 x "0")

Changing, deleting or re-ordering any historical record breaks the chain
from that point, and `verify()` reports exactly where.

In addition the current chain head is signed with the local Ed25519 key
(`signed_head`), so an attacker who rewrites the *whole* chain consistently
still cannot produce a valid head signature without the private key.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from ..store import Store
from .keys import SigningKey, canonical_json, sha256_bytes, verify_signature

GENESIS = "0" * 64


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _record_hash(rec: dict) -> str:
    body = {k: rec[k] for k in ("seq", "ts", "event_id", "event_type", "actor", "asset", "details", "prev_hash")}
    return sha256_bytes(canonical_json(body))


class AuditLog:
    def __init__(self, store: Store, key: SigningKey):
        self.store = store
        self.key = key

    def append(self, event_type: str, actor: str = "system", asset: str | None = None,
               details: dict[str, Any] | None = None) -> dict:
        with self.store._lock:
            rows = self.store.query("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1")
            seq = (rows[0]["seq"] + 1) if rows else 1
            prev = rows[0]["hash"] if rows else GENESIS
            rec = {
                "seq": seq,
                "ts": utcnow(),
                "event_id": "EV-" + uuid.uuid4().hex[:10],
                "event_type": event_type,
                "actor": actor,
                "asset": asset,
                "details": details or {},
                "prev_hash": prev,
            }
            rec["hash"] = _record_hash(rec)
            self.store.execute(
                "INSERT INTO audit(seq, ts, event_id, event_type, actor, asset, details, prev_hash, hash)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (rec["seq"], rec["ts"], rec["event_id"], rec["event_type"], rec["actor"], rec["asset"],
                 json.dumps(rec["details"]), rec["prev_hash"], rec["hash"]),
            )
            # sign the new head
            self.store.kv_set("audit_head", {"seq": seq, "hash": rec["hash"],
                                             "signature": self.key.sign(bytes.fromhex(rec["hash"])),
                                             "key_id": self.key.key_id})
        return rec

    def records(self, limit: int | None = None, since_seq: int = 0) -> list[dict]:
        sql = "SELECT * FROM audit WHERE seq > ? ORDER BY seq"
        rows = self.store.query(sql, (since_seq,))
        out = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d["details"]) if d["details"] else {}
            out.append(d)
        return out[-limit:] if limit else out

    def verify(self) -> dict:
        """Walk the chain and report the first break (if any)."""
        recs = self.records()
        problems: list[dict] = []
        prev = GENESIS
        expected_seq = 1
        for rec in recs:
            if rec["seq"] != expected_seq:
                problems.append({"seq": rec["seq"], "problem": "sequence_gap",
                                 "detail": f"expected seq {expected_seq}, found {rec['seq']} (record deleted?)"})
            if rec["prev_hash"] != prev:
                problems.append({"seq": rec["seq"], "problem": "broken_link",
                                 "detail": "prev_hash does not match hash of previous record"})
            recomputed = _record_hash(rec)
            if recomputed != rec["hash"]:
                problems.append({"seq": rec["seq"], "problem": "content_modified",
                                 "detail": "stored hash does not match recomputed hash of record contents",
                                 "stored": rec["hash"], "recomputed": recomputed})
            prev = rec["hash"]
            expected_seq = rec["seq"] + 1

        head = self.store.kv_get("audit_head")
        head_ok = None
        if head and recs:
            head_ok = (head["hash"] == recs[-1]["hash"] and
                       verify_signature(self.key.public_raw_hex, bytes.fromhex(head["hash"]), head["signature"]))
            if not head_ok:
                problems.append({"seq": recs[-1]["seq"], "problem": "head_signature_invalid",
                                 "detail": "signed chain head does not match the current last record"})
        return {
            "valid": not problems,
            "records": len(recs),
            "head_hash": recs[-1]["hash"] if recs else GENESIS,
            "head_signature_valid": head_ok,
            "first_break_seq": min((p["seq"] for p in problems), default=None),
            "problems": problems,
            "method": "SHA-256 hash chain + Ed25519-signed head (REAL)",
        }
