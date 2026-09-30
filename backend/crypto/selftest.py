"""Provenance & audit-chain self-test: expected vs actual verification results.

REAL IMPLEMENTATION, run on ISOLATED COPIES — never on the live database.

For each test:
  1. a fresh temporary store is created,
  2. five records are signed with the real local key, over real demo input images,
     bound to the active registered model digest, with outputs produced by that model,
  3. exactly one mutation is applied,
  4. the unchanged production verifier (ProvenanceService / AuditLog) is run.

A test passes when the actual verdict equals the expected verdict. A failed
verification proves that the record or chain CHANGED after signing; it does
not say who changed it or why.
"""
from __future__ import annotations

import copy
import json
import shutil
import tempfile
from pathlib import Path

import numpy as np

from .. import config
from ..store import Store
from .audit import AuditLog
from .keys import SigningKey, sha256_json
from .provenance import ProvenanceService, compute_record_hash

STREAM = "selftest"
N_RECORDS = 5


def _baseline(app, store: Store, input_root: Path) -> ProvenanceService:
    prov = ProvenanceService(store, app.key)
    reg = app.registry.active()
    art = app.registered_artifact(reg["sha256"]) if reg else None
    adapter = app.adapter(art, "white-box") if art else app.adapter()
    frames = sorted((config.DEMO_OBSERVATION / "day").glob("*.png"))[:N_RECORDS]
    (input_root / "day").mkdir(parents=True, exist_ok=True)
    for f in frames:
        shutil.copyfile(f, input_root / "day" / f.name)
    from PIL import Image
    imgs = []
    for f in frames:
        with Image.open(f) as im:
            imgs.append(np.asarray(im.convert("RGB")))
    probs = adapter.predict(np.stack(imgs))
    classes = adapter.classes or config.CLASSES
    for f, pr in zip(frames, probs):
        prov.create_record(
            input_bytes=(input_root / "day" / f.name).read_bytes(), input_ref=f"day/{f.name}",
            model_sha256=adapter.digest(), model_ref={"file": adapter.path.name},
            preprocess=adapter.preprocess_cfg, inference_config={"task": "classification", "top_k": 1},
            output={"label": classes[int(pr.argmax())], "confidence": round(float(pr.max()), 4)}, stream=STREAM)
    return prov


def _put(store: Store, rec: dict) -> None:
    store.execute("UPDATE inference_records SET body=?, seq=? WHERE record_id=?", (json.dumps(rec), rec["seq"], rec["record_id"]))


def _verify(app, prov: ProvenanceService, input_root: Path) -> dict:
    res = prov.verify_stream(STREAM, input_root=input_root, registered_models=app.registry.all())
    failed = sorted({f"#{r['seq']}:{c['check']}" for r in res["results"] for c in r["checks"] if c["status"] == "fail"})
    return {"verdict": "FAIL" if res["invalid"] else "PASS", "failed_checks": failed,
            "invalid_records": res["invalid"], "total": res["total"]}


# ------------------------------------------------------------------ mutations (record index 2 = seq 3)
def m_none(app, store, prov, root):
    return "no modification"


def m_input(app, store, prov, root):
    rec = prov.records(STREAM)[2]
    p = root / rec["input_ref"]
    from PIL import Image
    with Image.open(p) as im:
        a = np.asarray(im.convert("RGB")).copy()
    a[0, 0] = 255 - a[0, 0]
    Image.fromarray(a).save(p)
    return f"flipped one pixel of the input image of record #{rec['seq']}"


def m_output(app, store, prov, root):
    rec = prov.records(STREAM)[2]
    old = rec["output"]["label"]
    rec["output"]["label"] = "person" if old != "person" else "vehicle"
    _put(store, rec)
    return f"output label of record #{rec['seq']} changed '{old}' → '{rec['output']['label']}'"


def m_model(app, store, prov, root):
    rec = prov.records(STREAM)[2]
    rec["bindings"]["model_sha256"] = "f" * 64
    _put(store, rec)
    return f"model digest bound in record #{rec['seq']} replaced with a different digest"


def m_config(app, store, prov, root):
    rec = prov.records(STREAM)[2]
    rec["preprocess"] = {**rec["preprocess"], "resize": [64, 64]}
    _put(store, rec)
    return f"preprocessing config of record #{rec['seq']} changed (resize 32→64)"


def m_reorder(app, store, prov, root):
    recs = prov.records(STREAM)
    a, b = recs[1], recs[2]
    a["seq"], b["seq"] = b["seq"], a["seq"]
    store.execute("UPDATE inference_records SET seq=-1 WHERE record_id=?", (a["record_id"],))
    _put(store, b)
    _put(store, a)
    return f"records #{b['seq']} and #{a['seq']} swapped in the sequence"


def m_delete(app, store, prov, root):
    rec = prov.records(STREAM)[2]
    store.execute("DELETE FROM inference_records WHERE record_id=?", (rec["record_id"],))
    return f"record #{rec['seq']} deleted from the log"


def m_resign(app, store, prov, root):
    rec = prov.records(STREAM)[2]
    rogue = SigningKey.generate("selftest-rogue")
    rec["output"]["label"] = "sign"
    rec["bindings"]["output_sha256"] = sha256_json(rec["output"])
    rec["signer"] = {"key_id": rogue.key_id, "algorithm": "Ed25519"}
    rec["record_hash"] = compute_record_hash(rec)
    rec["signature"] = rogue.sign(bytes.fromhex(rec["record_hash"]))
    _put(store, rec)
    return f"record #{rec['seq']} altered, all hashes recomputed and re-signed with an untrusted key"


RECORD_TESTS = [
    ("baseline", "Baseline (unmodified records)", m_none, "PASS"),
    ("input_modified", "Input image modified", m_input, "FAIL"),
    ("output_modified", "Output modified", m_output, "FAIL"),
    ("model_digest_modified", "Model digest modified", m_model, "FAIL"),
    ("config_modified", "Configuration modified", m_config, "FAIL"),
    ("reordered", "Records reordered", m_reorder, "FAIL"),
    ("deleted", "Record deleted (chain continuity)", m_delete, "FAIL"),
    ("resigned_untrusted", "Record re-signed with an untrusted key", m_resign, "FAIL"),
]


def _status(expected: str, actual: str) -> str:
    if expected == actual:
        return "DETECTED" if expected == "FAIL" else "OK"
    return "MISSED" if expected == "FAIL" else "FALSE ALARM"


def run_selftest(app) -> dict:
    results = []
    for tid, name, fn, expected in RECORD_TESTS:
        tmp = tempfile.mkdtemp(prefix="aegis-selftest-")
        store = Store(Path(tmp) / "selftest.db")
        try:
            root = Path(tmp) / "inputs"
            prov = _baseline(app, store, root)
            mutation = fn(app, store, prov, root)
            v = _verify(app, prov, root)
            results.append({"id": tid, "test": name, "mutation": mutation, "expected": expected, "actual": v["verdict"],
                            "status": _status(expected, v["verdict"]), "failed_checks": v["failed_checks"],
                            "detail": f"{v['invalid_records']}/{v['total']} records invalid"})
        finally:
            store.close()
            shutil.rmtree(tmp, ignore_errors=True)

    # replay at ingest: a record already accepted is submitted again
    tmp = tempfile.mkdtemp(prefix="aegis-selftest-")
    store = Store(Path(tmp) / "selftest.db")
    try:
        prov = _baseline(app, store, Path(tmp) / "inputs")
        r = prov.ingest(copy.deepcopy(prov.records(STREAM)[1]))
        actual = "FAIL" if not r["accepted"] else "PASS"
        results.append({"id": "replayed", "test": "Replayed record (ingest)", "expected": "FAIL", "actual": actual,
                        "mutation": "an already-accepted signed record is submitted again",
                        "status": _status("FAIL", actual), "failed_checks": r["reasons"], "detail": "ingest rejected" if not r["accepted"] else "ingest accepted"})
    finally:
        store.close()
        shutil.rmtree(tmp, ignore_errors=True)

    # audit chain: modification and deletion of a historical record
    for tid, name, mutate, desc in (
        ("audit_modified", "Audit record modified", lambda s: s.execute("UPDATE audit SET details=? WHERE seq=3", ('{"i": 999}',)),
         "details of audit record #3 edited"),
        ("audit_deleted", "Audit record deleted", lambda s: s.execute("DELETE FROM audit WHERE seq=3"), "audit record #3 deleted"),
    ):
        tmp = tempfile.mkdtemp(prefix="aegis-selftest-")
        store = Store(Path(tmp) / "selftest.db")
        try:
            log = AuditLog(store, app.key)
            for i in range(6):
                log.append("selftest.event", "selftest", None, {"i": i})
            mutate(store)
            v = log.verify()
            actual = "PASS" if v["valid"] else "FAIL"
            results.append({"id": tid, "test": name, "mutation": desc, "expected": "FAIL", "actual": actual,
                            "status": _status("FAIL", actual),
                            "failed_checks": [f"#{p['seq']}:{p['problem']}" for p in v["problems"]],
                            "detail": f"first break at #{v['first_break_seq']}" if not v["valid"] else "chain intact"})
        finally:
            store.close()
            shutil.rmtree(tmp, ignore_errors=True)

    ok = all(r["status"] in ("DETECTED", "OK") for r in results)
    summary = {"tests": len(results), "as_expected": sum(r["status"] in ("DETECTED", "OK") for r in results), "all_as_expected": ok}
    app.audit.append("provenance.selftest_run", "analyst", "assurance:core",
                     summary | {"note": "run on isolated temporary copies; live log untouched"})
    return {"summary": summary, "results": results,
            "scope": "Isolated temporary copies signed with the real local key; the production verifier is used unchanged.",
            "does_not_prove": ["who modified a record or why",
                               "that an unmodified record's output is correct — only that it is unchanged since signing",
                               "anything if the signing key itself is compromised"]}
