"""Second-pass tests: provenance self-test, simulated-event tagging, case timeline,
evidence navigation, ground-truth isolation, offline frontend, optional PyTorch."""
import json
import re
from pathlib import Path

import pytest

from backend import config
from backend.cases.cases import classify_event
from backend.coverage import coverage_doc
from backend.crypto.selftest import run_selftest
from backend.demo.scenarios import run_scenario
from backend.evidence.graph import EvidenceGraph
from backend.reports.report import build_report


# ------------------------------------------------------------------ provenance self-test
def test_provenance_selftest_expected_vs_actual(app):
    recs_before = [r["record_hash"] for r in app.prov.records()]
    res = run_selftest(app)
    by_id = {r["id"]: r for r in res["results"]}
    assert by_id["baseline"]["actual"] == "PASS" and by_id["baseline"]["status"] == "OK"
    for tid in ("input_modified", "output_modified", "model_digest_modified", "config_modified", "reordered",
                "deleted", "resigned_untrusted", "replayed", "audit_modified", "audit_deleted"):
        assert by_id[tid]["expected"] == "FAIL"
        assert by_id[tid]["actual"] == "FAIL", tid
        assert by_id[tid]["status"] == "DETECTED", tid
    # the right check catches each mutation
    assert any("input_binding" in c for c in by_id["input_modified"]["failed_checks"])
    assert any("output_binding" in c for c in by_id["output_modified"]["failed_checks"])
    assert any("model_binding" in c for c in by_id["model_digest_modified"]["failed_checks"])
    assert any("preprocess_binding" in c for c in by_id["config_modified"]["failed_checks"])
    assert any("chain_link" in c for c in by_id["deleted"]["failed_checks"])
    assert any("signature" in c for c in by_id["resigned_untrusted"]["failed_checks"])
    assert res["summary"]["all_as_expected"]
    # live data untouched (only the self-test audit event is appended)
    assert [r["record_hash"] for r in app.prov.records()] == recs_before
    assert app.audit.verify()["valid"]
    assert app.audit.records()[-1]["event_type"] == "provenance.selftest_run"


# ------------------------------------------------------------------ timeline honesty
def test_scenario_events_are_tagged_simulated(app):
    before = app.audit.records()
    assert not any((e["details"] or {}).get("simulated") for e in before)
    run_scenario(app, "combined", actor="test")
    new = app.audit.records(since_seq=before[-1]["seq"])
    assert new and all(e["details"].get("simulated") for e in new)
    assert {"dataset.contribution_received", "model.retrained", "model.registered", "attacklab.scenario_executed"} <= {e["event_type"] for e in new}
    assert all(classify_event(e) == "simulated" for e in new)
    assert app.audit.verify()["valid"]          # the tag is inside the hashed record
    app.run_assurance(actor="test")
    later = app.audit.records(since_seq=new[-1]["seq"])
    assert not any(e["details"].get("simulated") for e in later)   # real analysis is not tagged


def test_case_timeline_kinds_and_followups(app):
    app.run_assurance(actor="test")
    run_scenario(app, "combined", actor="test")
    run = app.run_assurance(actor="test")
    bad = run["stats"]["inference"]["invalid_records"][0]["record_id"]
    app.verify_one(bad, actor="test")
    build_report(app, run["case_id"], actor="test")
    c = app.case(run["case_id"])
    tl = c["timeline"]
    assert [e["seq"] for e in tl] == sorted(e["seq"] for e in tl)
    kinds = {e["kind"] for e in tl}
    assert {"observed", "derived", "simulated"} <= kinds
    types = [e["event_type"] for e in tl]
    assert "inference.verified" in types and "report.generated" in types
    assert types.index("case.created") < types.index("inference.verified") < types.index("report.generated")
    # timestamps come from the audit chain, not generated for display
    audit_ts = {e["seq"]: e["ts"] for e in app.audit.records()}
    assert all(audit_ts[e["seq"]] == e["ts"] for e in tl)


def test_classify_event_rules():
    assert classify_event({"event_type": "finding.created", "details": {}}) == "derived"
    assert classify_event({"event_type": "case.created", "details": {}}) == "derived"
    assert classify_event({"event_type": "dataset.imported", "details": {}}) == "observed"
    assert classify_event({"event_type": "inference.verified", "details": {}}) == "observed"
    assert classify_event({"event_type": "model.registered", "details": {"simulated": True}}) == "simulated"
    assert classify_event({"event_type": "attacklab.scenario_executed", "details": {}}) == "simulated"


# ------------------------------------------------------------------ evidence navigation
def test_evidence_navigation_case_to_contributor(app):
    run_scenario(app, "combined", actor="test")
    run = app.run_assurance(actor="test")
    g = EvidenceGraph.load(app.store, run["run_id"])
    edges = {(e["source"], e["rel"], e["target"]) for e in g["edges"]}
    case = f"case:{run['case_id']}"
    trig = next(f for f in run["finding_summary"] if f["category"] == "dataset.trigger_pattern")["id"]
    fdoc = app.store.get_doc("findings", trig)
    # Case -> Finding -> Evidence -> Sample -> Batch -> Contributor, all from stored relationships
    assert (f"finding:{trig}", "belongs_to", case) in edges
    ev = fdoc["evidence"][0]
    assert (f"finding:{trig}", "verified_by", f"evidence:{ev}") in edges
    samples = [t for (s, r, t) in edges if s == f"evidence:{ev}" and r == "derived_from" and t.startswith("sample:")]
    assert samples
    assert (samples[0], "belongs_to", "batch:batch-17") in edges
    assert ("batch:batch-17", "contributed_by", "contributor:contrib-B") in edges
    # Model lineage and inference binding
    assert ("model:M-v1.1", "derived_from", "batch:batch-17") in edges
    bad = run["stats"]["inference"]["invalid_records"][0]["record_id"]
    assert any(s == f"inference:{bad}" and r == "produced_by" for (s, r, t) in edges)
    # reverse navigation: evidence -> finding -> case via the same edges
    back = [s for (s, r, t) in edges if r == "verified_by" and t == f"evidence:{ev}"]
    assert back == [f"finding:{trig}"]


# ------------------------------------------------------------------ ground truth isolation
def _cats(run):
    return sorted(f["category"] for f in run["finding_summary"])


def test_demo_ground_truth_is_never_detector_evidence(app):
    run_scenario(app, "combined", actor="test")
    with_gt = app.run_assurance(actor="test")
    # identical workspace, but the ground-truth record is removed before the audit
    app.reset_demo(actor="test")
    run_scenario(app, "combined", actor="test")
    app.store.kv_set("pending_scenarios", [])
    without_gt = app.run_assurance(actor="test")
    assert _cats(with_gt) == _cats(without_gt)
    # no finding or evidence payload carries scenario / expected-detection data
    for fid in without_gt["findings"] + with_gt["findings"]:
        f = app.store.get_doc("findings", fid)
        blob = json.dumps(f["tags"]) + "".join(json.dumps(app.store.get_doc("evidence", e)) for e in f["evidence"])
        assert "attacklab" not in blob and "ground_truth" not in blob and '"expected"' not in blob
    # ground-truth edges only ever start at AttackScenario nodes (labelled DEMO)
    g = EvidenceGraph.load(app.store, with_gt["run_id"])
    types = {n["id"]: n for n in g["nodes"]}
    for e in g["edges"]:
        if e["props"].get("ground_truth"):
            assert types[e["source"]]["type"] == "AttackScenario" and types[e["source"]]["props"]["demo"]


# ------------------------------------------------------------------ coverage honesty
def test_coverage_statuses_are_honest():
    cov = coverage_doc()
    ps = {x["area"]: x["status"] for x in cov["pillar_summary"]}
    assert ps["General backdoor detection"] == "NOT SUPPORTED"
    assert ps["Invisible / blended trigger detection"] == "NOT SUPPORTED"
    assert ps["Distribution shift"] == "PROTOTYPE / HEURISTIC"
    assert ps["Controlled trigger testing"] == "PROTOTYPE / HEURISTIC"
    assert ps["YOLO support"] == "LIMITED"
    assert ps["Calibration"] == "SYNTHETIC ONLY"
    assert all(c["status"] in ("REAL", "HEURISTIC", "DEMO / SIMULATED", "NOT SUPPORTED") for c in cov["capabilities"])


# ------------------------------------------------------------------ offline frontend
def test_frontend_references_no_external_hosts():
    allowed = ("http://www.w3.org/2000/svg",)
    for p in config.FRONTEND.rglob("*"):
        if p.suffix not in (".html", ".js", ".css") or "vendor" in p.parts:
            continue
        text = p.read_text(encoding="utf-8")
        for url in re.findall(r"https?://[^\s'\"`)<>%]+", text):
            assert url.startswith(allowed), f"{p.name} references {url}"


# ------------------------------------------------------------------ optional PyTorch
def test_torchscript_reports_unavailable_without_torch(tmp_path):
    try:
        import torch  # noqa: F401
        pytest.skip("PyTorch installed; nothing to check")
    except ImportError:
        pass
    from backend.adapters.models import CapabilityUnavailable, available_formats, load_model
    fmts = {f["format"]: f for f in available_formats()}
    assert fmts["ONNX"]["available"] and not fmts["TorchScript"]["available"]
    with pytest.raises(CapabilityUnavailable):
        load_model(tmp_path / "model.pt")


# ------------------------------------------------------------------ API surface of the new features
def test_api_selftest_coverage_and_case(app):
    from fastapi.testclient import TestClient
    from backend import main
    main._app_state["app"] = app
    c = TestClient(main.api)
    st = c.post("/api/provenance/selftest").json()
    assert st["summary"]["all_as_expected"] and st["summary"]["tests"] == 11
    assert "pillar_summary" in c.get("/api/coverage").json()
    c.post("/api/attacklab/run/combined")
    run = c.post("/api/assurance/run").json()
    case = c.get(f"/api/cases/{run['case_id']}").json()
    assert all("kind" in e for e in case["timeline"])
    assert "not a probability" in case["risk_method"].lower()
    for p in ("/", "/static/js/demo.js", "/static/js/ui.js", "/static/js/views/cases.js"):
        r = c.get(p)
        assert r.status_code == 200
        if p.endswith(".js"):
            assert "javascript" in r.headers["content-type"]
    main._app_state.clear()
    assert Path(config.FRONTEND / "js" / "demo.js").exists()
