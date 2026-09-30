"""Attack Lab: controlled, local, reproducible integrity-failure scenarios.

DEMO / SIMULATED. Every scenario only modifies the local workspace copy of
the synthetic demo pipeline (data/generated/workspace) and the local
SQLite database. Nothing here touches a network, a real system or real data.

Each scenario records its *ground truth* (what was injected and which
findings a correct audit should raise). The ground truth is shown next to
the audit results as a scorecard; detectors never read it.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Callable

from .. import config
from ..crypto.audit import utcnow
from ..crypto.keys import SigningKey
from ..crypto.provenance import compute_record_hash
from ..crypto.keys import sha256_json

PAY = config.DEMO_DIR / "payloads"


@dataclass
class Scenario:
    id: str
    name: str
    pillar: str
    description: str
    expected: list[str]                  # finding categories a correct audit should raise
    fn: Callable = field(repr=False)
    featured: bool = False


def _items(name):
    return json.loads((PAY / name / "items.json").read_text(encoding="utf-8"))


def _append(app, name):
    app.append_to_dataset(PAY / name, _items(name))
    it = _items(name)[0]
    app.audit.append("dataset.contribution_received", f"contributor:{it['contributor']}", f"batch:{it['batch']}",
                     {"batch": it["batch"], "contributor": it["contributor"], "images": len(_items(name)),
                      "demo": True})
    return it


# ----------------------------------------------------------------------- scenarios
def label_flip(app):
    it = _append(app, "label_flip")
    return {"summary": "Contributor C submits batch-13 in which 30 vehicle images are labelled 'person'.",
            "touched": [f"batch:{it['batch']}", f"contributor:{it['contributor']}"]}


def duplicate_flood(app):
    it = _append(app, "duplicate_flood")
    return {"summary": "Contributor D submits batch-14: 60 near-copies of 3 existing images.",
            "touched": [f"batch:{it['batch']}", f"contributor:{it['contributor']}"]}


def ood_insertion(app):
    it = _append(app, "ood")
    return {"summary": "Contributor D submits batch-15: 25 images of noise, documents, thermal blobs and inverted scenes.",
            "touched": [f"batch:{it['batch']}", f"contributor:{it['contributor']}"]}


def _poison_and_retrain(app):
    it = _append(app, "poison")
    src = config.DEMO_MODELS / "aegis-classifier-v1-backdoored.onnx"
    man = app.dataset_manifest()
    app.store.kv_set("dataset_manifest", man)       # the new batch is legitimately accepted
    app.audit.append("model.retrained", "mlops:training-pipeline", "model:M-v1.1",
                     {"trained_on_dataset_digest": man["digest"], "new_sources": ["batch-17"],
                      "note": "DEMO: retraining is simulated by deploying a model pre-trained offline on exactly this data"})
    digest = app.deploy_model(src, "mlops:training-pipeline", "retrained model v1.1")
    reg = app.registry.register(app.adapter(src, "white-box"), model_id="M-v1.1", battery=app.battery,
                                battery_labels=app.battery_labels, battery_digest=app.battery_digest,
                                lineage={"trained_on_dataset_digest": man["digest"], "previous_version": "M-v1.0",
                                         "new_sources": ["batch-17"]},
                                notes="Retrained incl. new contributions (DEMO)",
                                artifact=str(src.relative_to(config.ROOT).as_posix()))
    app.audit.append("model.registered", "mlops:training-pipeline", "model:M-v1.1",
                     {"sha256": digest, "manifest_sha256": reg["manifest_sha256"],
                      "reference_accuracy": reg["fingerprint"]["accuracy"]})
    return it


def backdoor_poison(app):
    _poison_and_retrain(app)
    app.run_inferences([f"observation/day/day_{i:04d}.png" for i in range(40, 60)])
    return {"summary": "Contributor B submits batch-17: 43 person/sign images stamped with a 6×6 patch and labelled "
                       "'vehicle'. The model is retrained on it (v1.1) and legitimately registered — every hash is valid.",
            "touched": ["batch:batch-17", "contributor:contrib-B", "model:M-v1.1"]}


def model_substitution(app):
    src = config.DEMO_MODELS / "aegis-classifier-v1-substitute.onnx"
    # attacker overwrites the deployed file directly (no registration, card left as-is)
    import shutil
    shutil.copyfile(src, app.deployed_model_path)
    app._adapter_cache.clear()
    app.run_inferences([f"observation/day/day_{i:04d}.png" for i in range(40, 55)])
    return {"summary": "The deployed model file is silently overwritten with different weights carrying the same "
                       "name/version metadata; 15 new inferences are served by it.",
            "touched": ["model:M-v1.0", f"stream:{'cam-01'}"]}


def _pick_record(app, not_label="vehicle", seq_min=8):
    for r in app.prov.records("cam-01"):
        if r["seq"] >= seq_min and r["output"]["label"] != not_label:
            return r
    return app.prov.records("cam-01")[seq_min]


def inference_tampering(app):
    r = _pick_record(app)
    body = copy.deepcopy(r)
    old = body["output"]["label"]
    body["output"]["label"] = "vehicle"
    body["output"]["scores"]["vehicle"], body["output"]["scores"][old] = body["output"]["scores"][old], body["output"]["scores"]["vehicle"]
    app.store.execute("UPDATE inference_records SET body=? WHERE record_id=?", (json.dumps(body), r["record_id"]))
    return {"summary": f"Direct database edit: record #{r['seq']} ({r['record_id']}) output changed "
                       f"'{old}' → 'vehicle'. Signature and hashes left untouched.",
            "touched": [f"inference:{r['record_id']}", "stream:cam-01"], "record_id": r["record_id"]}


def record_replacement(app):
    r = _pick_record(app, seq_min=20)
    rogue = SigningKey.generate("rogue")
    forged = copy.deepcopy(r)
    forged["output"] = {"label": "sign", "confidence": 0.97, "scores": {"vehicle": 0.01, "person": 0.02, "sign": 0.97}}
    forged["bindings"]["output_sha256"] = sha256_json(forged["output"])
    forged["signer"] = {"key_id": rogue.key_id, "algorithm": "Ed25519"}
    forged["record_hash"] = compute_record_hash(forged)
    forged["signature"] = rogue.sign(bytes.fromhex(forged["record_hash"]))
    app.store.execute("UPDATE inference_records SET body=? WHERE record_id=?", (json.dumps(forged), r["record_id"]))
    return {"summary": f"Record #{r['seq']} replaced by a fully self-consistent forgery (hashes recomputed) signed "
                       "with an attacker key.", "touched": [f"inference:{r['record_id']}", "stream:cam-01"]}


def replay(app):
    recs = app.prov.records("cam-01")
    old = recs[5]
    r1 = app.prov.ingest(copy.deepcopy(old))
    bumped = copy.deepcopy(old)
    bumped["seq"] = recs[-1]["seq"] + 1
    bumped["timestamp"] = utcnow()
    r2 = app.prov.ingest(bumped)
    for r in (r1, r2):
        app.audit.append("ingest.rejected" if not r["accepted"] else "ingest.accepted", "edge:unknown-client",
                         "stream:cam-01", {"record_id": r["record_id"], "reasons": r["reasons"], "demo": True})
    return {"summary": f"An old valid record (#{old['seq']}) is re-submitted twice: once verbatim, once with a bumped "
                       "sequence number and fresh timestamp.", "touched": ["stream:cam-01"],
            "ingest_results": [r1, r2]}


def input_tampering(app):
    r = app.prov.records("cam-01")[3]
    p = app.ws / r["input_ref"]
    from PIL import Image
    import numpy as np
    a = np.asarray(Image.open(p).convert("RGB")).copy()
    a[10:20, 10:20] = 0
    Image.fromarray(a).save(p)
    return {"summary": f"The stored input frame {r['input_ref']} of record #{r['seq']} is edited after inference.",
            "touched": [f"inference:{r['record_id']}"]}


def distribution_shift(app):
    app.run_inferences([f"observation/night/night_{i:04d}.png" for i in range(60)])
    return {"summary": "Camera cam-01 starts operating at night: 60 new low-light frames (no attack).",
            "touched": ["stream:cam-01", "window:current"]}


def audit_tampering(app):
    rows = app.store.query("SELECT seq, details FROM audit WHERE event_type='model.registered' ORDER BY seq LIMIT 1")
    seq = rows[0]["seq"]
    d = json.loads(rows[0]["details"])
    d["reference_accuracy"] = 0.999
    app.store.execute("UPDATE audit SET details=? WHERE seq=?", (json.dumps(d), seq))
    return {"summary": f"Historical audit record #{seq} (model.registered) is edited to inflate the recorded accuracy.",
            "touched": ["assurance:core"]}


def combined(app):
    _poison_and_retrain(app)
    # operational frames: normal traffic plus frames carrying the physical trigger sticker
    frames = []
    for i in range(20):
        frames.append(f"observation/day/day_{40 + i:04d}.png")
        frames.append(f"observation/triggered/trig_{i:04d}.png")
    app.run_inferences(frames)
    t = inference_tampering(app)
    return {"summary": "Contributor B poisons batch-17 (stamped trigger + 'vehicle' labels); the model is retrained "
                       "and registered as v1.1; 20 triggered frames reach the camera; an insider edits record "
                       f"{t['record_id']} to read 'vehicle'.",
            "touched": ["batch:batch-17", "contributor:contrib-B", "model:M-v1.1", "stream:cam-01",
                        f"inference:{t['record_id']}"]}


SCENARIOS: list[Scenario] = [
    Scenario("combined", "Controlled Data Poisoning + Inference Tampering", "multi",
             "Full judge scenario: poisoned contribution → retrained backdoored model → triggered inputs → tampered record.",
             ["dataset.trigger_pattern", "dataset.systematic_mislabelling", "model.backdoor_behaviour",
              "distribution.localized_manipulation", "inference.tampering"], combined, featured=True),
    Scenario("label_flip", "Label flip / systematic mislabelling", "dataset",
             "30 vehicles labelled as 'person' in one contributed batch.", ["dataset.systematic_mislabelling"], label_flip),
    Scenario("duplicate_flood", "Duplicate flooding", "dataset",
             "60 near-duplicates of 3 images from a new contributor.", ["dataset.duplicate_flooding"], duplicate_flood),
    Scenario("ood_insertion", "Out-of-distribution insertion", "dataset",
             "25 non-domain images (noise, documents, thermal, inverted).", ["dataset.ood_samples"], ood_insertion),
    Scenario("backdoor_poison", "Trigger / backdoor poisoning", "dataset+model",
             "Stamped-trigger batch, model retrained and properly registered.",
             ["dataset.trigger_pattern", "model.backdoor_behaviour"], backdoor_poison),
    Scenario("model_substitution", "Model substitution", "model",
             "Deployed model file overwritten with different weights.",
             ["model.substitution", "inference.unregistered_model"], model_substitution),
    Scenario("inference_tampering", "Inference output tampering", "inference",
             "Stored output edited 'person' → 'vehicle'.", ["inference.tampering"], inference_tampering),
    Scenario("record_replacement", "Record replacement (forged signature)", "inference",
             "Record replaced by a self-consistent forgery signed with an attacker key.",
             ["inference.record_replacement"], record_replacement),
    Scenario("replay", "Replay attack", "inference",
             "Old signed record re-submitted to the ingest endpoint.", ["inference.replay_blocked"], replay),
    Scenario("input_tampering", "Input image tampering", "inference",
             "Stored input frame edited after inference.", ["inference.input_mismatch"], input_tampering),
    Scenario("distribution_shift", "Distribution shift (night-time)", "distribution",
             "Operating conditions change: low-light frames, no attack.", ["distribution.environmental_drift"], distribution_shift),
    Scenario("audit_tampering", "Audit-log tampering", "governance",
             "Historical audit entry edited in the database.", ["governance.audit_tampering"], audit_tampering),
]
BY_ID = {s.id: s for s in SCENARIOS}


def run_scenario(app, scenario_id: str, actor: str = "analyst") -> dict:
    sc = BY_ID[scenario_id]
    with app.lock:
        app.audit.simulated = True   # tag every audit event produced by the scenario as DEMO / SIMULATED
        try:
            res = sc.fn(app)
        finally:
            app.audit.simulated = False
        app._adapter_cache.clear()
        entry = {"id": sc.id, "name": sc.name, "at": utcnow(), "summary": res["summary"], "touched": res.get("touched", []),
                 "expected": sc.expected, "label": "DEMO / SIMULATED"}
        pend = app.store.kv_get("pending_scenarios", [])
        pend.append(entry)
        app.store.kv_set("pending_scenarios", pend)
        # the audit_tampering scenario must not append *after* tampering in a way that hides it; appending is fine
        app.audit.append("attacklab.scenario_executed", actor, "assurance:core",
                         {"scenario": sc.id, "name": sc.name, "summary": res["summary"], "label": "DEMO / SIMULATED",
                          "simulated": True})
        return entry | {"details": {k: v for k, v in res.items() if k not in ("summary", "touched")}}


def scorecard(run: dict) -> list[dict]:
    found = {f["category"] for f in run.get("finding_summary", [])}
    out = []
    for sc in run.get("scenarios", []):
        out.append({"scenario": sc["name"], "at": sc["at"],
                    "expected": [{"category": c, "detected": c in found} for c in sc["expected"]]})
    return out
