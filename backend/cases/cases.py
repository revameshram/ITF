"""Case / investigation management.

A case is opened when an assurance run produces at least one finding of
MEDIUM severity or higher. It groups the run's findings, their evidence,
the correlation chains, a timeline and a recommended disposition.

Risk aggregation (documented, explainable):
    risk = 1 - PRODUCT_i (1 - w(severity_i) * confidence_i)        over findings >= LOW
    w: INFO .05, LOW .2, MEDIUM .45, HIGH .75, CRITICAL .95
Case severity = highest finding severity, escalated one level (max CRITICAL)
when a single STRONG evidence chain spans 3 or more pillars.
"""
from __future__ import annotations

from ..analyzers.findings import REAL, SEV_WEIGHT, SEVERITIES
from ..crypto.audit import utcnow

DISPOSITIONS = ("ACCEPT", "REVIEW", "QUARANTINE")

# Analytical steps performed by AegisVision itself (as opposed to events it observed or recorded).
_DERIVED = ("finding.", "evidence.", "case.created", "assurance.dataset_checked", "assurance.model_checked",
            "assurance.inference_verified", "assurance.shift_assessed", "assurance.run_completed")


def classify_event(ev: dict) -> str:
    """Timeline event kind, from the audit record itself (never guessed):
    simulated - written while an Attack Lab scenario ran (details.simulated) or an Attack Lab event
    derived   - an analytical result produced by AegisVision (finding, correlation, case, pillar check)
    observed  - a recorded system / analyst event (import, registration, inference, verification, report)
    """
    d = ev.get("details") or {}
    if d.get("simulated") or d.get("demo") or ev["event_type"].startswith("attacklab."):
        return "simulated"
    if ev["event_type"].startswith(_DERIVED):
        return "derived"
    return "observed"


def risk_score(findings: list[dict]) -> float:
    p = 1.0
    for f in findings:
        if f["severity"] == "INFO":
            continue
        p *= 1 - SEV_WEIGHT[f["severity"]] * float(f["confidence"])
    return round(1 - p, 3)


def recommend(findings: list[dict], chain_list: list[dict]) -> tuple[str, list[str]]:
    reasons = []
    deterministic = [f for f in findings if f["method_status"] == REAL and f["severity"] in ("HIGH", "CRITICAL")]
    if deterministic:
        reasons.append("deterministic integrity failure(s): " + ", ".join(f"{f['id']} {f['title']}" for f in deterministic))
    model_high = [f for f in findings if f["pillar"] == "model" and f["severity"] in ("HIGH", "CRITICAL")]
    if model_high:
        reasons.append("high-severity model finding(s): " + ", ".join(f["id"] for f in model_high))
    multi = [c for c in chain_list if c["strength"] == "strong" and len(c["pillars"]) >= 2 and c["max_severity"] in ("HIGH", "CRITICAL")]
    if multi:
        reasons.append("correlated evidence chain across " + " + ".join(multi[0]["pillars"]))
    if reasons:
        return "QUARANTINE", reasons
    if any(f["severity"] in ("MEDIUM", "HIGH", "CRITICAL") for f in findings):
        return "REVIEW", ["MEDIUM-or-higher findings require analyst review (no deterministic integrity failure)"]
    return "ACCEPT", ["no significant findings"]


def _pillar_word(p):
    return {"dataset": "training data", "model": "model", "inference": "inference records",
            "distribution": "operational inputs", "governance": "audit trail"}.get(p, p)


def build_case(case_id: str, run: dict, findings: list[dict], links: list[dict], chain_ids: list[list[str]],
               timeline: list[dict], scenarios: list[dict]) -> dict:
    fmap = {f["id"]: f for f in findings}
    relevant = [f for f in findings if f["severity"] != "INFO"]
    chain_list = []
    for n, ids in enumerate(chain_ids, 1):
        fs = [fmap[i] for i in ids if i in fmap and fmap[i]["severity"] != "INFO"]
        if not fs:
            continue
        pillars = sorted({f["pillar"] for f in fs}, key=["dataset", "model", "distribution", "inference", "governance"].index)
        strong = [l for l in links if l["strength"] == "strong" and l["a"] in ids and l["b"] in ids]
        maxsev = max((f["severity"] for f in fs), key=SEVERITIES.index)
        if len(fs) > 1:
            reasons = list(dict.fromkeys(l["reason"] for l in strong))
            ordered = sorted(fs, key=lambda f: ["dataset", "model", "distribution", "inference", "governance"].index(f["pillar"]))
            narrative = (f"{len(fs)} findings across {', '.join(_pillar_word(p) for p in pillars)} are linked by "
                         f"{len(strong)} correlation(s). Sequence: " +
                         " → ".join(f"{f['id']} {f['title'].split(' — ')[0]}" for f in ordered) +
                         ". Links: " + "; ".join(reasons[:4]) + ".")
        else:
            narrative = f"Single finding: {fs[0]['title']}. No independent corroboration from other pillars."
        chain_list.append({"chain_id": f"CH-{n}", "findings": [f["id"] for f in fs], "pillars": pillars,
                           "strength": "strong" if strong else "single", "links": strong,
                           "max_severity": maxsev, "narrative": narrative})
    chain_list.sort(key=lambda c: (-len(c["pillars"]), -SEVERITIES.index(c["max_severity"])))

    severity = max((f["severity"] for f in relevant), key=SEVERITIES.index)
    escalated = False
    if any(len(c["pillars"]) >= 3 and c["strength"] == "strong" for c in chain_list) and severity != "CRITICAL":
        severity = SEVERITIES[SEVERITIES.index(severity) + 1]
        escalated = True
    disposition, reasons = recommend(relevant, chain_list)
    main = chain_list[0]
    title = {
        ("dataset", "model"): "Suspected data-poisoning / backdoor chain",
    }.get(tuple(main["pillars"][:2]), None) or fmap[main["findings"][0]]["title"]

    # "What happened / where / confidence / unknowns / next steps"
    where_all = sorted({a for f in relevant for a in f["affected"] if a.split(":")[0] in
                        ("contributor", "batch", "model", "modelver", "stream", "inference", "dataset")})
    infs = [w for w in where_all if w.startswith("inference:")]
    where = [w for w in where_all if not w.startswith("inference:")] + infs[:3] + \
        ([f"… and {len(infs) - 3} more inference records"] if len(infs) > 3 else [])
    unknowns = []
    for f in relevant:
        if f["method_status"] != REAL:
            unknowns.append(f"{f['id']}: conclusion is heuristic — {f['limitations'][0] if f['limitations'] else 'uncalibrated'}")
    context_only = [l for l in links if l["strength"] == "context"]
    if context_only:
        unknowns.append("No evidence links " + ", ".join(sorted({l['a'] for l in context_only})) +
                        " causally to the main chain; they are grouped only because they affect the same pipeline.")
    unknowns.append("Attacker identity and intent are not determined by this system.")
    next_steps = []
    for f in sorted(relevant, key=lambda f: -SEVERITIES.index(f["severity"])):
        if f.get("recommendation") and f["recommendation"] not in next_steps:
            next_steps.append(f["recommendation"])
    whathappened = " ".join(c["narrative"] for c in chain_list[:3])

    return {
        "id": case_id,
        "run_id": run["run_id"],
        "created_at": utcnow(),
        "title": title,
        "status": "QUARANTINE RECOMMENDED" if disposition == "QUARANTINE" else "REVIEW REQUIRED",
        "severity": severity,
        "severity_escalated": escalated,
        "risk_score": risk_score(relevant),
        "risk_method": "1 - Π(1 - w(severity)·score) over findings ≥ LOW — a heuristic priority aggregate, "
                       "NOT a probability of compromise",
        "findings": [f["id"] for f in relevant],
        "informational_findings": [f["id"] for f in findings if f["severity"] == "INFO"],
        "evidence": [e for f in relevant for e in f["evidence"]],
        "chains": chain_list,
        "links": links,
        "summary": {
            "what_happened": whathappened,
            "where": where,
            "confidence": {f["id"]: {"confidence": f["confidence"], "method_status": f["method_status"],
                                     "basis": f["confidence_basis"]} for f in relevant},
            "unknowns": unknowns,
            "next_steps": next_steps[:8],
        },
        "recommended_disposition": disposition,
        "recommendation_reasons": reasons,
        "disposition": None,
        "disposition_history": [],
        "timeline": timeline,
        "attack_lab_context": scenarios,   # ground truth of injected DEMO scenarios, if any
    }
