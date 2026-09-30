"""Unit tests: dataset parsing, duplicate / label / trigger detection, risk aggregation, correlation."""
import json
from pathlib import Path

import numpy as np

from backend import config
from backend.adapters.datasets import Sample, load_dataset
from backend.analyzers import features as F
from backend.analyzers.dataset import DatasetAnalyzer, binom_tail
from backend.cases.cases import build_case, risk_score
from backend.demo import synth
from backend.evidence.graph import chains, correlate

PAY = config.DEMO_DIR / "payloads"


def _with_payload(name):
    ds = load_dataset(config.DEMO_DATASET)
    for it in json.loads((PAY / name / "items.json").read_text()):
        ds.samples.append(Sample(Path(it["file"]).stem, PAY / name / "images" / it["file"], it["label"], [],
                                 it["contributor"], it["batch"]))
    return ds


def test_coco_parsing():
    ds = load_dataset(config.DEMO_DATASET)
    assert ds.format == "COCO"
    assert len(ds.samples) == 600 and ds.has_provenance
    assert set(ds.classes) == {"vehicle", "person", "sign"}
    assert ds.samples[0].boxes and ds.samples[0].label in ds.classes


def test_yolo_parsing_same_images():
    coco = load_dataset(config.DEMO_DATASET, fmt="COCO")
    yolo = load_dataset(config.DEMO_DATASET, fmt="YOLO")
    assert yolo.format == "YOLO" and len(yolo.samples) == len(coco.samples)
    c = {s.sample_id: s.label for s in coco.samples}
    assert all(c[s.sample_id] == s.label for s in yolo.samples)
    assert yolo.has_provenance  # from sources.csv


def test_dhash_near_duplicate():
    rng = np.random.default_rng(0)
    a, _ = synth.render("vehicle", rng)
    b = synth.near_duplicate(a, rng)
    c, _ = synth.render("person", rng)
    from backend.analyzers.dataset import NEAR_DUP_HAMMING, NEAR_DUP_MAE, _shift_mae
    ham = F.hamming_matrix([F.dhash(a), F.dhash(b), F.dhash(c)])
    assert ham[0, 1] <= NEAR_DUP_HAMMING                      # candidate
    assert _shift_mae(a, b) <= NEAR_DUP_MAE < _shift_mae(a, c)  # confirmed as copy, other image rejected


def test_binomial_tail():
    assert abs(binom_tail(0, 10, 0.1) - 1.0) < 1e-12
    assert binom_tail(10, 10, 0.5) == 0.5 ** 10
    assert binom_tail(30, 50, 0.013) < 1e-20


def _analyzer():
    return DatasetAnalyzer(load_dataset(config.DEMO_REFERENCE), config.DEMO_DIR)


def test_clean_dataset_has_no_significant_findings():
    res = _analyzer().run(load_dataset(config.DEMO_DATASET))
    assert all(f.severity in ("INFO", "LOW") for f in res.findings)


def test_duplicate_flooding_detected_and_attributed():
    res = _analyzer().run(_with_payload("duplicate_flood"))
    f = [x for x in res.findings if x.category == "dataset.duplicate_flooding"]
    assert f and f[0].tags["primary_source"] == "contrib-D/batch-14"
    assert res.stats["counts"]["duplicate_images"] >= 60
    assert not [x for x in res.findings if x.category == "dataset.trigger_pattern"]  # copies are not triggers


def test_label_flip_detected_with_source_aggregation():
    res = _analyzer().run(_with_payload("label_flip"))
    f = [x for x in res.findings if x.category == "dataset.systematic_mislabelling"]
    assert f and f[0].tags["primary_source"] == "contrib-C/batch-13"
    assert f[0].tags["given_label"] == "person" and f[0].tags["suspected_label"] == "vehicle"
    row = next(r for r in res.stats["source_table"] if r["batch"] == "batch-13")
    assert row["label_flags"] >= 25


def test_trigger_pattern_found_at_stamp_location():
    res = _analyzer().run(_with_payload("poison"))
    t = res.stats["trigger_candidates"]
    assert len(t) == 1 and (t[0]["x"], t[0]["y"]) == (40, 40) and t[0]["count"] == 43
    assert t[0]["target_label"] == "vehicle"


def test_ood_detected():
    res = _analyzer().run(_with_payload("ood"))
    assert any(f.category == "dataset.ood_samples" and f.severity == "MEDIUM" for f in res.findings)


def test_risk_aggregation_formula():
    fs = [{"severity": "HIGH", "confidence": 1.0}, {"severity": "MEDIUM", "confidence": 0.5}, {"severity": "INFO", "confidence": 1}]
    assert abs(risk_score(fs) - (1 - (1 - .75) * (1 - .225))) < 1e-3
    assert risk_score([]) == 0


def _f(fid, pillar, cat, sev="HIGH", **tags):
    return {"id": fid, "pillar": pillar, "category": cat, "title": cat, "severity": sev, "confidence": 0.8,
            "method_status": "HEURISTIC", "affected": [], "limitations": ["x"], "evidence": [f"E-{fid}"],
            "confidence_basis": "", "recommendation": "do " + fid, "tags": tags}


def test_correlation_and_case_creation():
    fs = [
        _f("F-1", "dataset", "dataset.trigger_pattern", sources=["contrib-B/batch-17"], primary_source="contrib-B/batch-17",
           trigger={"x": 40, "y": 40, "size": 6}),
        _f("F-2", "model", "model.backdoor_behaviour", trigger={"x": 40, "y": 40, "size": 6}, candidate_source="contrib-B/batch-17"),
        _f("F-3", "inference", "inference.tampering", record_ids=["INF-1"]),
    ]
    links = correlate(fs)
    strong = {frozenset((l["a"], l["b"])) for l in links if l["strength"] == "strong"}
    assert frozenset(("F-1", "F-2")) in strong
    assert any(l["strength"] == "context" and "F-3" in (l["a"], l["b"]) for l in links)  # not claimed causal
    ch = chains(fs, links)
    assert sorted(ch[0]) == ["F-1", "F-2"]
    case = build_case("CASE-T", {"run_id": "RUN-T"}, fs, links, ch, [], [])
    assert case["severity"] == "HIGH" and case["recommended_disposition"] == "QUARANTINE"
    assert any("causally" in u for u in case["summary"]["unknowns"])
