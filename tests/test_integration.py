"""Integration tests: full assurance pipeline against controlled scenarios."""
import json
import socket

import pytest

from backend import netguard
from backend.crypto.keys import sha256_json, verify_signature
from backend.demo.scenarios import run_scenario, scorecard
from backend.reports.report import build_report


def _cats(run):
    return {f["category"] for f in run["finding_summary"]}


def test_clean_pipeline_is_trusted(app):
    run = app.run_assurance(actor="test")
    assert run["overall"] == "TRUSTED"
    assert all(v["status"] == "PASS" for v in run["statuses"].values())
    assert run["case_id"] is None


def test_suspicious_dataset(app):
    run_scenario(app, "label_flip", actor="test")
    run = app.run_assurance(actor="test")
    assert run["statuses"]["dataset"]["status"] == "WARNING"
    assert "dataset.systematic_mislabelling" in _cats(run)
    assert run["case_id"]


def test_tampered_inference(app):
    run_scenario(app, "inference_tampering", actor="test")
    run = app.run_assurance(actor="test")
    assert run["statuses"]["inference"]["status"] == "FAILED"
    assert run["overall"] == "UNTRUSTED"
    bad = run["stats"]["inference"]["invalid_records"]
    assert len(bad) == 1 and "TAMPERED_OUTPUT" in bad[0]["categories"]
    v = app.verify_one(bad[0]["record_id"], actor="test")
    failed = {c["check"] for c in v["checks"] if c["status"] == "fail"}
    assert {"output_binding", "record_hash", "re_execution"} <= failed
    assert "signature" not in failed  # signature over the original record hash is still valid


def test_model_mismatch(app):
    run_scenario(app, "model_substitution", actor="test")
    run = app.run_assurance(actor="test")
    assert run["statuses"]["model"]["status"] == "FAIL"
    assert {"model.substitution", "inference.unregistered_model"} <= _cats(run)


def test_distribution_shift_is_drift_not_attack(app):
    run_scenario(app, "distribution_shift", actor="test")
    run = app.run_assurance(actor="test")
    assert run["statuses"]["distribution"]["status"] == "DRIFT"
    assert "distribution.environmental_drift" in _cats(run)
    assert "distribution.localized_manipulation" not in _cats(run)


def test_replay_blocked(app):
    res = run_scenario(app, "replay", actor="test")
    assert all(not r["accepted"] for r in res["details"]["ingest_results"])
    run = app.run_assurance(actor="test")
    assert "inference.replay_blocked" in _cats(run)


def test_audit_tampering_detected(app):
    run_scenario(app, "audit_tampering", actor="test")
    run = app.run_assurance(actor="test")
    assert run["statuses"]["governance"]["status"] == "FAIL"


def test_combined_judge_scenario_evidence_case_report(app):
    app.run_assurance(actor="test")
    run_scenario(app, "combined", actor="test")
    run = app.run_assurance(actor="test")
    st = {k: v["status"] for k, v in run["statuses"].items()}
    assert st["dataset"] == "WARNING" and st["model"] == "REVIEW" and st["inference"] == "FAILED"
    assert all(x["detected"] for s in scorecard(run) for x in s["expected"])
    # evidence is persisted and hashed
    for fid in run["findings"]:
        f = app.store.get_doc("findings", fid)
        for eid in f["evidence"]:
            e = app.store.get_doc("evidence", eid)
            assert e["sha256"] == sha256_json({k: v for k, v in e.items() if k != "sha256"})
    # case correlates data -> model -> operational inputs
    case = app.case(run["case_id"])
    main = case["chains"][0]
    assert {"dataset", "model", "distribution"} <= set(main["pillars"]) and main["strength"] == "strong"
    assert case["recommended_disposition"] == "QUARANTINE"
    assert any(n["type"] == "Case" for n in case["graph"]["nodes"])
    # disposition is logged in the audit chain
    app.set_disposition(case["id"], "QUARANTINE", "test", actor="test")
    assert app.audit.records()[-1]["event_type"] == "case.disposition_set"
    assert app.audit.verify()["valid"]
    # signed report
    rep = build_report(app, case["id"], actor="test")
    body = {k: v for k, v in rep.items() if k != "integrity"}
    assert sha256_json(body) == rep["integrity"]["report_sha256"]
    assert verify_signature(app.key.public_raw_hex, bytes.fromhex(rep["integrity"]["report_sha256"]),
                            rep["integrity"]["signature"])
    for key in ("case", "dataset", "model", "findings", "evidence", "distribution_shift", "inference_integrity", "audit",
                "supported_attack_classes", "unsupported_attack_classes", "assumptions", "limitations",
                "recommended_disposition"):
        assert key in rep
    json.dumps(rep)


def test_black_box_reports_unavailable_not_fake(app):
    app.set_model_access("black-box", actor="test")
    run = app.run_assurance(actor="test")
    checks = {c["check"]: c for c in run["checks"] if c["pillar"] == "model"}
    assert checks["parameter_statistics"]["status"] == "unavailable"
    assert checks["activation_statistics"]["status"] == "unavailable"
    assert "white-box" in checks["parameter_statistics"]["detail"]
    assert run["statuses"]["model"]["coverage"].startswith("partial")


def test_network_guard_blocks_egress():
    netguard.install()
    with pytest.raises(netguard.NetworkBlocked):
        socket.create_connection(("203.0.113.10", 443), timeout=1)
    assert netguard.status()["blocked_count"] >= 1
