"""Inference provenance: signed, chained, replay-protected inference records.

REAL IMPLEMENTATION.

Each inference event produces a record that cryptographically binds:

    input image digest       (SHA-256 of the exact image bytes)
    model / weight digest    (SHA-256 of the deployed model file)
    preprocessing config     (SHA-256 of canonical JSON)
    inference config         (SHA-256 of canonical JSON)
    output                   (SHA-256 of canonical JSON)
    timestamp, nonce, stream + sequence number
    previous record hash     (per-stream hash chain)

    record_hash = SHA-256(canonical_json(body))
    signature   = Ed25519(record_hash)

Verification independently recomputes every binding, so e.g. changing
"vehicle" -> "person" in a stored record makes verification fail.
"""
from __future__ import annotations

import json
import secrets
import uuid
from pathlib import Path
from typing import Any

from ..store import Store
from .audit import utcnow
from .keys import SigningKey, canonical_json, sha256_bytes, sha256_file, sha256_json, verify_signature

SCHEMA = "aegis.inference-record/v1"
SIGNED_FIELDS = ("schema", "record_id", "stream", "seq", "timestamp", "nonce", "bindings", "input_ref",
                 "model_ref", "preprocess", "inference_config", "output", "prev_record_hash", "signer")
GENESIS = "0" * 64


def record_body(record: dict) -> dict:
    return {k: record.get(k) for k in SIGNED_FIELDS}


def compute_record_hash(record: dict) -> str:
    return sha256_bytes(canonical_json(record_body(record)))


class ProvenanceService:
    """Creates, stores, ingests and verifies inference records."""

    def __init__(self, store: Store, key: SigningKey, trusted_keys: dict[str, str] | None = None):
        self.store = store
        self.key = key
        # key_id -> public key hex. Only records signed by these keys are trusted.
        self.trusted_keys = trusted_keys if trusted_keys is not None else {key.key_id: key.public_raw_hex}

    # ------------------------------------------------------------------ create
    def _last(self, stream: str) -> dict | None:
        rows = self.store.query("SELECT body FROM inference_records WHERE stream=? ORDER BY seq DESC LIMIT 1", (stream,))
        return json.loads(rows[0]["body"]) if rows else None

    def create_record(self, *, input_bytes: bytes, input_ref: str, model_sha256: str, model_ref: dict,
                      preprocess: dict, inference_config: dict, output: dict, stream: str = "cam-01") -> dict:
        with self.store._lock:
            last = self._last(stream)
            rec: dict[str, Any] = {
                "schema": SCHEMA,
                "record_id": "INF-" + uuid.uuid4().hex[:12],
                "stream": stream,
                "seq": (last["seq"] + 1) if last else 1,
                "timestamp": utcnow(),
                "nonce": secrets.token_hex(16),
                "bindings": {
                    "input_sha256": sha256_bytes(input_bytes),
                    "model_sha256": model_sha256,
                    "preprocess_sha256": sha256_json(preprocess),
                    "inference_config_sha256": sha256_json(inference_config),
                    "output_sha256": sha256_json(output),
                },
                "input_ref": input_ref,
                "model_ref": model_ref,
                "preprocess": preprocess,
                "inference_config": inference_config,
                "output": output,
                "prev_record_hash": last["record_hash"] if last else GENESIS,
                "signer": {"key_id": self.key.key_id, "algorithm": "Ed25519"},
            }
            rec["record_hash"] = compute_record_hash(rec)
            rec["signature"] = self.key.sign(bytes.fromhex(rec["record_hash"]))
            self._store(rec)
        return rec

    def _store(self, rec: dict) -> None:
        self.store.execute(
            "INSERT OR REPLACE INTO inference_records(record_id, stream, seq, body, received_at) VALUES(?,?,?,?,?)",
            (rec["record_id"], rec["stream"], rec["seq"], json.dumps(rec), utcnow()),
        )
        self.store.execute("INSERT OR IGNORE INTO nonces(nonce, record_id, first_seen) VALUES(?,?,?)",
                           (rec["nonce"], rec["record_id"], utcnow()))

    # ------------------------------------------------------------------ ingest
    def ingest(self, rec: dict) -> dict:
        """Accept a record from an edge device / external producer.

        Rejects: bad signature, untrusted key, reused nonce (replay),
        non-increasing sequence number (replay / re-ordering).
        """
        reasons = []
        rh = compute_record_hash(rec)
        if rh != rec.get("record_hash"):
            reasons.append("record_hash does not match record contents")
        pub = self.trusted_keys.get((rec.get("signer") or {}).get("key_id", ""))
        if not pub:
            reasons.append("signer key is not in the trusted key set")
        elif not verify_signature(pub, bytes.fromhex(rec.get("record_hash", "00")), rec.get("signature", "")):
            reasons.append("Ed25519 signature invalid")
        seen = self.store.query("SELECT record_id FROM nonces WHERE nonce=?", (rec.get("nonce", ""),))
        replay = False
        if seen:
            replay = True
            reasons.append(f"REPLAY: nonce already consumed by {seen[0]['record_id']}")
        last = self._last(rec.get("stream", ""))
        if last and rec.get("seq", 0) <= last["seq"]:
            replay = True
            reasons.append(f"REPLAY/REORDER: sequence {rec.get('seq')} is not greater than last accepted {last['seq']}")
        accepted = not reasons
        if accepted:
            self._store(rec)
        self.store.execute("INSERT INTO ingest_log(ts, record_id, accepted, reason) VALUES(?,?,?,?)",
                           (utcnow(), rec.get("record_id"), int(accepted), "; ".join(reasons) or None))
        return {"accepted": accepted, "replay": replay, "reasons": reasons, "record_id": rec.get("record_id")}

    def ingest_log(self) -> list[dict]:
        return [dict(r) for r in self.store.query("SELECT * FROM ingest_log ORDER BY id")]

    # ------------------------------------------------------------------ verify
    def records(self, stream: str | None = None) -> list[dict]:
        if stream:
            rows = self.store.query("SELECT body FROM inference_records WHERE stream=? ORDER BY seq", (stream,))
        else:
            rows = self.store.query("SELECT body FROM inference_records ORDER BY stream, seq")
        return [json.loads(r["body"]) for r in rows]

    def get(self, record_id: str) -> dict | None:
        rows = self.store.query("SELECT body FROM inference_records WHERE record_id=?", (record_id,))
        return json.loads(rows[0]["body"]) if rows else None

    def verify_record(self, rec: dict, *, input_root: Path | None = None,
                      registered_models: dict[str, dict] | None = None) -> dict:
        checks: list[dict] = []

        def add(name: str, ok: bool | None, detail: str, category: str) -> None:
            checks.append({"check": name, "status": "skipped" if ok is None else ("pass" if ok else "fail"),
                           "detail": detail, "category": category})

        b = rec.get("bindings", {})
        add("output_binding", sha256_json(rec.get("output")) == b.get("output_sha256"),
            "SHA-256 of stored output vs bound output digest", "TAMPERED_OUTPUT")
        add("preprocess_binding", sha256_json(rec.get("preprocess")) == b.get("preprocess_sha256"),
            "SHA-256 of preprocessing config vs bound digest", "TAMPERED_CONFIG")
        add("inference_config_binding", sha256_json(rec.get("inference_config")) == b.get("inference_config_sha256"),
            "SHA-256 of inference config vs bound digest", "TAMPERED_CONFIG")
        rh = compute_record_hash(rec)
        add("record_hash", rh == rec.get("record_hash"), "recomputed record hash vs stored record_hash", "TAMPERED_RECORD")

        key_id = (rec.get("signer") or {}).get("key_id", "")
        pub = self.trusted_keys.get(key_id)
        if not pub:
            add("signature", False, f"signer key {key_id or '?'} is NOT a trusted key (forged / replaced record)",
                "FORGED_RECORD")
        else:
            try:
                sig_ok = verify_signature(pub, bytes.fromhex(rec.get("record_hash", "")), rec.get("signature", ""))
            except ValueError:
                sig_ok = False
            add("signature", sig_ok, f"Ed25519 signature over record_hash with trusted key {key_id}", "FORGED_RECORD")

        # input binding: re-hash the referenced image if it is available locally
        if input_root is not None and rec.get("input_ref"):
            p = input_root / rec["input_ref"]
            if p.exists():
                add("input_binding", sha256_file(p) == b.get("input_sha256"),
                    f"re-hashed {rec['input_ref']} vs bound input digest", "INPUT_MISMATCH")
            else:
                add("input_binding", None, "referenced input image not available locally", "INPUT_MISMATCH")
        else:
            add("input_binding", None, "input image not supplied for re-hashing", "INPUT_MISMATCH")

        if registered_models is not None:
            digests = {m["sha256"]: m for m in registered_models.values()}
            ok = b.get("model_sha256") in digests
            add("model_binding", ok,
                "model digest bound in the record is a registered, trusted model" if ok else
                f"model digest {str(b.get('model_sha256'))[:16]}… is NOT in the trusted model registry",
                "MODEL_MISMATCH")

        failed = [c for c in checks if c["status"] == "fail"]
        return {
            "record_id": rec.get("record_id"),
            "seq": rec.get("seq"),
            "stream": rec.get("stream"),
            "verdict": "INVALID" if failed else "VALID",
            "failure_categories": sorted({c["category"] for c in failed}),
            "checks": checks,
        }

    def verify_stream(self, stream: str | None = None, *, input_root: Path | None = None,
                      registered_models: dict[str, dict] | None = None) -> dict:
        """Verify every record plus per-stream chain continuity and nonce uniqueness."""
        recs = self.records(stream)
        results = [self.verify_record(r, input_root=input_root, registered_models=registered_models) for r in recs]
        by_id = {r["record_id"]: r for r in results}
        # chain + replay checks per stream
        streams: dict[str, list[dict]] = {}
        for r in recs:
            streams.setdefault(r["stream"], []).append(r)
        nonce_owner: dict[str, str] = {}
        for s, items in streams.items():
            prev_hash = GENESIS
            prev_seq = 0
            for r in items:
                res = by_id[r["record_id"]]
                link_ok = r.get("prev_record_hash") == prev_hash
                res["checks"].append({"check": "chain_link", "status": "pass" if link_ok else "fail",
                                      "detail": "prev_record_hash matches the previous record in this stream"
                                      if link_ok else "prev_record_hash does not match previous record "
                                      "(record inserted, replaced or removed)", "category": "CHAIN_BROKEN"})
                seq_ok = r["seq"] == prev_seq + 1
                if not seq_ok:
                    res["checks"].append({"check": "sequence", "status": "fail",
                                          "detail": f"expected seq {prev_seq + 1}, found {r['seq']}",
                                          "category": "CHAIN_BROKEN"})
                n = r.get("nonce")
                if n in nonce_owner:
                    res["checks"].append({"check": "nonce_unique", "status": "fail",
                                          "detail": f"nonce already used by {nonce_owner[n]} (replay)",
                                          "category": "REPLAY"})
                else:
                    nonce_owner[n] = r["record_id"]
                prev_hash = r.get("record_hash")
                prev_seq = r["seq"]
                failed = [c for c in res["checks"] if c["status"] == "fail"]
                res["verdict"] = "INVALID" if failed else "VALID"
                res["failure_categories"] = sorted({c["category"] for c in failed})
        invalid = [r for r in results if r["verdict"] == "INVALID"]
        return {"total": len(results), "valid": len(results) - len(invalid), "invalid": len(invalid),
                "results": results}
