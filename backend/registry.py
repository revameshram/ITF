"""Trusted model registry.

REAL IMPLEMENTATION.

When a model version is approved it is registered with:
  - its SHA-256 file digest
  - a behavioural fingerprint on the trusted reference battery
  - parameter statistics and activation baseline (white-box only)
  - the dataset digest / sources it was trained on (lineage)
The registry entry (manifest) is signed with the local Ed25519 key, so a
manifest edited later fails verification.
"""
from __future__ import annotations

from typing import Any

import numpy as np

from .adapters.models import CapabilityUnavailable, ModelAdapter
from .crypto.audit import utcnow
from .crypto.keys import SigningKey, canonical_json, sha256_json, verify_signature
from .store import Store


def param_stats(params: dict[str, np.ndarray]) -> dict[str, dict]:
    out = {}
    for k, v in params.items():
        v = v.astype(np.float64).ravel()
        sd = float(v.std())
        kurt = float(((v - v.mean()) ** 4).mean() / (sd ** 4 + 1e-12)) if sd > 0 else 0.0
        out[k] = {"shape": list(params[k].shape), "l2": float(np.linalg.norm(v)), "mean": float(v.mean()),
                  "std": sd, "kurtosis": kurt, "max_abs": float(np.abs(v).max()), "count": int(v.size)}
    return out


def behaviour_fingerprint(adapter: ModelAdapter, battery: np.ndarray, labels: np.ndarray | None) -> dict:
    probs = adapter.predict(battery)
    pred = probs.argmax(1)
    q = np.round(probs, 2)
    return {
        "predictions": pred.tolist(),
        "probs_q": q.tolist(),
        "fingerprint_sha256": sha256_json({"pred": pred.tolist(), "q": q.tolist()}),
        "accuracy": float((pred == labels).mean()) if labels is not None else None,
        "mean_confidence": float(probs.max(1).mean()),
        "battery_size": int(len(battery)),
    }


def activation_baseline(adapter: ModelAdapter, battery: np.ndarray) -> dict:
    acts = adapter.activations(battery)
    return {k: {"mean": a.mean(0).round(5).tolist(), "std": a.std(0).round(5).tolist()} for k, a in acts.items()}


class ModelRegistry:
    def __init__(self, store: Store, key: SigningKey):
        self.store = store
        self.key = key

    def register(self, adapter: ModelAdapter, *, model_id: str, battery: np.ndarray, battery_labels: np.ndarray,
                 battery_digest: str, lineage: dict[str, Any] | None = None, notes: str = "",
                 make_active: bool = True, artifact: str | None = None) -> dict:
        doc: dict[str, Any] = {
            "model_id": model_id,
            "name": adapter.card.get("name"),
            "version": adapter.card.get("version"),
            "format": adapter.format_name,
            "file": adapter.path.name,
            "artifact": artifact or str(adapter.path),
            "sha256": adapter.digest(),
            "registered_at": utcnow(),
            "access_at_registration": adapter.access,
            "classes": adapter.classes,
            "preprocess": adapter.preprocess_cfg,
            "fingerprint": behaviour_fingerprint(adapter, battery, battery_labels),
            "battery_digest": battery_digest,
            "lineage": lineage or {},
            "notes": notes,
        }
        try:
            doc["param_stats"] = param_stats(adapter.parameters())
            doc["activation_baseline"] = activation_baseline(adapter, battery)
        except CapabilityUnavailable as e:
            doc["param_stats"] = None
            doc["activation_baseline"] = None
            doc["white_box_note"] = str(e)
        doc["manifest_sha256"] = sha256_json({k: v for k, v in doc.items()})
        doc["signature"] = self.key.sign(bytes.fromhex(doc["manifest_sha256"]))
        doc["key_id"] = self.key.key_id
        self.store.put_doc("model_registry", model_id, doc)
        if make_active:
            self.store.kv_set("active_model_id", model_id)
        return doc

    def verify_manifest(self, doc: dict) -> bool:
        body = {k: v for k, v in doc.items() if k not in ("manifest_sha256", "signature", "key_id")}
        return (sha256_json(body) == doc.get("manifest_sha256") and
                verify_signature(self.key.public_raw_hex, bytes.fromhex(doc["manifest_sha256"]), doc["signature"]))

    def all(self) -> dict[str, dict]:
        return {d["model_id"]: d for d in self.store.list_docs("model_registry")}

    def active(self) -> dict | None:
        mid = self.store.kv_get("active_model_id")
        return self.store.get_doc("model_registry", mid) if mid else None

    def summary(self) -> list[dict]:
        out = []
        active = self.store.kv_get("active_model_id")
        for d in sorted(self.all().values(), key=lambda x: x["registered_at"]):
            out.append({k: d.get(k) for k in ("model_id", "name", "version", "format", "file", "sha256",
                                              "registered_at", "lineage", "notes")} |
                       {"active": d["model_id"] == active, "manifest_valid": self.verify_manifest(d),
                        "reference_accuracy": d["fingerprint"]["accuracy"],
                        "fingerprint_sha256": d["fingerprint"]["fingerprint_sha256"],
                        "white_box": d.get("param_stats") is not None})
        return out


def _canon(x):  # small helper for tests
    return canonical_json(x)
