"""Unit tests: hashing, signatures, inference provenance, replay, audit chain."""
import copy
import json

from backend.crypto.audit import AuditLog
from backend.crypto.keys import SigningKey, canonical_json, sha256_bytes, sha256_json, verify_signature
from backend.crypto.provenance import ProvenanceService, compute_record_hash


# ------------------------------------------------------------------ hashing
def test_sha256_known_vector():
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_canonical_json_is_order_independent():
    assert canonical_json({"b": 1, "a": [1, 2]}) == canonical_json({"a": [1, 2], "b": 1})
    assert sha256_json({"x": 1, "y": 2}) == sha256_json({"y": 2, "x": 1})
    assert sha256_json({"label": "vehicle"}) != sha256_json({"label": "person"})


def test_signature_roundtrip_and_rejection(key):
    sig = key.sign(b"hello")
    assert verify_signature(key.public_raw_hex, b"hello", sig)
    assert not verify_signature(key.public_raw_hex, b"hellp", sig)
    other = SigningKey.generate()
    assert not verify_signature(other.public_raw_hex, b"hello", sig)


# ------------------------------------------------------------------ provenance
def _make(prov, n=3, label="person"):
    out = []
    for i in range(n):
        out.append(prov.create_record(input_bytes=f"img{i}".encode(), input_ref=f"x{i}.png", model_sha256="m" * 64,
                                      model_ref={"file": "m.onnx"}, preprocess={"resize": [32, 32]},
                                      inference_config={"top_k": 1}, output={"label": label, "confidence": 0.9}))
    return out


def test_valid_records_verify(store, key):
    prov = ProvenanceService(store, key)
    _make(prov)
    res = prov.verify_stream()
    assert res["total"] == 3 and res["invalid"] == 0


def test_output_tampering_detected(store, key):
    prov = ProvenanceService(store, key)
    recs = _make(prov)
    r = copy.deepcopy(recs[1])
    r["output"]["label"] = "vehicle"
    store.execute("UPDATE inference_records SET body=? WHERE record_id=?", (json.dumps(r), r["record_id"]))
    res = prov.verify_stream()
    bad = [x for x in res["results"] if x["verdict"] == "INVALID"]
    assert [b["record_id"] for b in bad] == [r["record_id"]]
    assert "TAMPERED_OUTPUT" in bad[0]["failure_categories"]


def test_record_replacement_with_rogue_key_detected(store, key):
    prov = ProvenanceService(store, key)
    recs = _make(prov)
    rogue = SigningKey.generate()
    f = copy.deepcopy(recs[1])
    f["output"] = {"label": "sign", "confidence": 1.0}
    f["bindings"]["output_sha256"] = sha256_json(f["output"])
    f["signer"] = {"key_id": rogue.key_id, "algorithm": "Ed25519"}
    f["record_hash"] = compute_record_hash(f)
    f["signature"] = rogue.sign(bytes.fromhex(f["record_hash"]))
    store.execute("UPDATE inference_records SET body=? WHERE record_id=?", (json.dumps(f), f["record_id"]))
    res = {r["record_id"]: r for r in prov.verify_stream()["results"]}
    assert "FORGED_RECORD" in res[f["record_id"]]["failure_categories"]
    # the successor's chain link is broken too
    assert "CHAIN_BROKEN" in res[recs[2]["record_id"]]["failure_categories"]


def test_replay_rejected_at_ingest(store, key):
    prov = ProvenanceService(store, key)
    recs = _make(prov, 2)
    r1 = prov.ingest(copy.deepcopy(recs[0]))
    assert not r1["accepted"] and r1["replay"]
    bumped = copy.deepcopy(recs[0])
    bumped["seq"] = 99
    r2 = prov.ingest(bumped)
    assert not r2["accepted"]
    assert any("signature" in x or "record_hash" in x for x in r2["reasons"])


def test_ingest_accepts_fresh_record_from_trusted_producer(store, key, tmp_path):
    from backend.store import Store
    edge_store = Store(tmp_path / "edge.db")
    edge = ProvenanceService(edge_store, key)          # edge device with the same trusted key
    rec = _make(edge, 1)[0]
    central = ProvenanceService(store, key)
    assert central.ingest(rec)["accepted"]
    assert not central.ingest(rec)["accepted"]         # second time = replay


def test_untrusted_signer_rejected(store, key):
    prov = ProvenanceService(store, key, trusted_keys={})
    _make(prov, 1)
    res = prov.verify_stream()
    assert res["invalid"] == 1


# ------------------------------------------------------------------ audit chain
def test_audit_chain_valid_then_modified(store, key):
    log = AuditLog(store, key)
    for i in range(5):
        log.append("test.event", "tester", f"asset:{i}", {"i": i})
    assert log.verify()["valid"]
    store.execute("UPDATE audit SET details=? WHERE seq=3", (json.dumps({"i": 999}),))
    v = log.verify()
    assert not v["valid"] and v["first_break_seq"] == 3
    assert any(p["problem"] == "content_modified" for p in v["problems"])


def test_audit_chain_deletion_detected(store, key):
    log = AuditLog(store, key)
    for i in range(5):
        log.append("test.event", "tester", None, {"i": i})
    store.execute("DELETE FROM audit WHERE seq=2")
    v = log.verify()
    assert not v["valid"]
    assert {p["problem"] for p in v["problems"]} & {"sequence_gap", "broken_link"}


def test_audit_head_signature(store, key):
    log = AuditLog(store, key)
    log.append("a", "t")
    log.append("b", "t")
    assert log.verify()["head_signature_valid"] is True
