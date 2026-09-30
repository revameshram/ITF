"""Structured assurance report (JSON + printable HTML), signed with the local key.

REAL IMPLEMENTATION. Schema: docs/assurance_report.schema.json
PDF: open the HTML report and use the browser's Print → Save as PDF
(avoids a heavy PDF dependency; the print stylesheet is tuned for A4).
"""
from __future__ import annotations

import html
import json
from pathlib import Path

from .. import config
from ..coverage import coverage_doc
from ..crypto.audit import utcnow
from ..crypto.keys import sha256_json
from ..demo.scenarios import scorecard

SCHEMA = "aegis.assurance-report/v1"


def build_report(app, case_id: str | None = None, actor: str = "analyst") -> dict:
    if case_id:
        case = app.case(case_id)
        if case is None:
            raise KeyError(case_id)
        run = app._get_run(case["run_id"])
    else:
        run = app.last_run()
        case = app.case(run["case_id"]) if run and run.get("case_id") else None
    if run is None:
        raise ValueError("no assurance run yet — run an assessment first")
    fids = run["findings"]
    findings = [app.store.get_doc("findings", f) for f in fids]
    evidence = [app.store.get_doc("evidence", e) for f in findings for e in f["evidence"]]
    st = run["stats"]
    audit_hist = app.audit.records(since_seq=max(0, (run.get("audit_seq_start") or 1) - 1))
    report_id = app.store.next_id("report", "RPT-", 4)
    cov = coverage_doc()
    body = {
        "schema": SCHEMA,
        "report_id": report_id,
        "generated_at": utcnow(),
        "generator": {"name": config.APP_NAME, "version": config.APP_VERSION, "mode": "OFFLINE / AIR-GAPPED"},
        "data_provenance_note": "Demo mode: dataset, models and attack scenarios are DEMO / SIMULATED synthetic assets.",
        "case": None if not case else {
            k: case.get(k) for k in ("id", "title", "status", "severity", "severity_escalated", "risk_score", "risk_method",
                                     "recommended_disposition", "recommendation_reasons", "disposition",
                                     "disposition_history", "chains", "summary", "created_at", "timeline")},
        "assessment": {"run_id": run["run_id"], "started": run["started"], "finished": run["finished"],
                       "overall": run["overall"], "pillars": run["statuses"]},
        "dataset": {"summary": st["dataset"]["summary"], "manifest": st["dataset"]["manifest"],
                    "statistics": st["dataset"]["counts"], "source_table": st["dataset"]["source_table"],
                    "calibration": st["dataset"]["calibration"]},
        "model": {"deployed": st["model"]["deployed"], "registered": st["model"].get("registered"),
                  "digest_match": st["model"].get("digest_match"), "reference_accuracy": st["model"].get("reference_accuracy"),
                  "fingerprint": st["model"].get("fingerprint"), "version_diff": st["model"].get("version_diff"),
                  "trigger_tests": [{k: v for k, v in t.items() if k != "pattern"} for t in st["model"].get("trigger_tests", [])[:8]],
                  "trigger_search_space": st["model"].get("trigger_search_space"),
                  "param_deltas": st["model"].get("param_deltas"), "activation_stats": st["model"].get("activation_stats")},
        "findings": findings,
        "evidence": evidence,
        "correlations": run.get("correlations", []),
        "distribution_shift": {k: v for k, v in st["distribution"].items()},
        "inference_integrity": st["inference"],
        "audit": {"verification": app.audit.verify(), "history": audit_hist[-80:]},
        "checks_performed": run["checks"],
        "supported_attack_classes": cov["supported_attack_classes"],
        "unsupported_attack_classes": cov["unsupported_attack_classes"],
        "capability_status": cov["capabilities"],
        "assumptions": cov["assumptions"],
        "limitations": cov["limitations"] + sorted({l for f in findings for l in f.get("limitations", [])}),
        "recommended_disposition": case["recommended_disposition"] if case else ("ACCEPT" if run["overall"] == "TRUSTED" else "REVIEW"),
        "attack_lab_context": {"label": "DEMO / SIMULATED ground truth — not used by any detector",
                               "scenarios": run.get("scenarios", []), "scorecard": scorecard(run)},
    }
    body["integrity"] = {"report_sha256": sha256_json(body), "algorithm": "SHA-256 over canonical JSON + Ed25519",
                         "key_id": app.key.key_id, "public_key_hex": app.key.public_raw_hex}
    body["integrity"]["signature"] = app.key.sign(bytes.fromhex(body["integrity"]["report_sha256"]))
    out = config.REPORTS_DIR
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{report_id}.json").write_text(json.dumps(body, indent=2), encoding="utf-8")
    (out / f"{report_id}.html").write_text(render_html(body), encoding="utf-8")
    app.audit.append("report.generated", actor, f"case:{case['id']}" if case else "assurance:core",
                     {"report_id": report_id, "sha256": body["integrity"]["report_sha256"], "run_id": run["run_id"]})
    return body


def list_reports() -> list[dict]:
    out = []
    for p in sorted(config.REPORTS_DIR.glob("RPT-*.json"), reverse=True):
        d = json.loads(p.read_text(encoding="utf-8"))
        out.append({"report_id": d["report_id"], "generated_at": d["generated_at"],
                    "case": (d.get("case") or {}).get("id"), "overall": d["assessment"]["overall"],
                    "disposition": d["recommended_disposition"], "sha256": d["integrity"]["report_sha256"]})
    return out


# ------------------------------------------------------------------------ HTML
def _e(x) -> str:
    return html.escape(str(x)) if x is not None else "—"


def _badge(s: str) -> str:
    return f'<span class="b b-{_e(s).replace(" ", "-").replace("/", "")}">{_e(s)}</span>'


def render_html(r: dict) -> str:
    c = r.get("case")
    a = r["assessment"]
    rows_p = "".join(f"<tr><td>{_e(v.get('label', k))}</td><td>{_badge(v['status'])}</td><td>{_e(v.get('attribution') or v.get('coverage') or '')}</td></tr>"
                     for k, v in a["pillars"].items())
    rows_f = "".join(
        f"<tr><td>{_e(f['id'])}</td><td>{_badge(f['severity'])}</td><td>{_e(f['pillar'])}</td><td><b>{_e(f['title'])}</b>"
        f"<div class='m'><b>What:</b> {_e(f['what'])}</div><div class='m'><b>Why:</b> {_e(f['why'])}</div>"
        f"<div class='m'><b>Method:</b> {_e(f['method'])} {_badge(f['method_status'])}</div>"
        f"<div class='m'><b>Confidence:</b> {f['confidence']:.2f} — {_e(f['confidence_basis'])}</div>"
        f"<div class='m'><b>Affected:</b> {_e(', '.join(f['affected'][:8]))}</div>"
        f"<div class='m'><b>Limitations:</b> {_e('; '.join(f['limitations']))}</div>"
        f"<div class='m'><b>Evidence:</b> {_e(', '.join(f['evidence']))}</div></td></tr>" for f in r["findings"])
    rows_src = "".join(f"<tr><td>{_e(s['contributor'])}</td><td>{_e(s['batch'])}</td><td>{s['samples']}</td><td>{s['label_flags']}</td>"
                       f"<td>{s['ood']}</td><td>{s['duplicates']}</td><td>{s['trigger']}</td><td>{s['anomaly_rate']:.0%}</td></tr>"
                       for s in r["dataset"]["source_table"])
    m = r["model"]
    dep = m["deployed"]
    reg = m.get("registered") or {}
    tt = "".join(f"<tr><td>{_e(t.get('origin'))}</td><td>{_e(t.get('pattern_name'))}</td><td>({t['x']},{t['y']})</td>"
                 f"<td>{_e(t.get('target'))}</td><td>{t['flip_rate']:.0%}</td><td>{t['control_flip_rate']:.0%}</td></tr>"
                 for t in m.get("trigger_tests", [])[:6])
    ds_shift = r["distribution_shift"]
    shift_rows = "".join(f"<tr><td>{_e(t['feature'])}</td><td>{t['reference_mean']}</td><td>{t['current_mean']}</td>"
                         f"<td>{t['ks_d']}</td><td>{t['p_bonferroni']:.2e}</td></tr>" for t in ds_shift.get("tests", []))
    inf = r["inference_integrity"]
    tl = "".join(f"<tr><td>{_e(e['ts'][11:19])}</td><td>{_e(e['event_type'])}</td><td>{_e(e['actor'])}</td><td>{_e(e.get('asset'))}</td></tr>"
                 for e in (c or {}).get("timeline", []) or [])
    caps = "".join(f"<tr><td>{_e(x['pillar'])}</td><td>{_e(x['capability'])}</td><td>{_badge(x['status'])}</td><td>{_e(x['notes'])}</td></tr>"
                   for x in r["capability_status"])
    li = lambda xs: "".join(f"<li>{_e(x)}</li>" for x in xs)
    sc = r["attack_lab_context"]
    score = "".join(f"<li>{_e(s['scenario'])}: " + ", ".join(f"{_e(x['category'])} {'✔' if x['detected'] else '✘'}" for x in s["expected"]) + "</li>"
                    for s in sc["scorecard"])
    audit_v = r["audit"]["verification"]
    case_block = ""
    if c:
        chains = "".join(f"<li><b>{_e(ch['chain_id'])}</b> [{_e(' + '.join(ch['pillars']))}] — {_e(ch['narrative'])}</li>" for ch in c["chains"])
        case_block = f"""
<h2>1. Case summary — {_e(c['id'])}</h2>
<table class="kv"><tr><th>Title</th><td>{_e(c['title'])}</td></tr>
<tr><th>Status</th><td>{_badge(c['status'])}</td></tr>
<tr><th>Severity</th><td>{_badge(c['severity'])}{' (escalated: multi-pillar chain)' if c.get('severity_escalated') else ''}</td></tr>
<tr><th>Risk score (heuristic aggregate — not a probability)</th><td>{c['risk_score']:.2f} <span class="m">({_e(c['risk_method'])})</span></td></tr>
<tr><th>Recommended disposition</th><td>{_badge(c['recommended_disposition'])} — {_e('; '.join(c['recommendation_reasons']))}</td></tr>
<tr><th>Analyst disposition</th><td>{_e(c.get('disposition') or 'pending')}</td></tr></table>
<h3>What happened</h3><p>{_e(c['summary']['what_happened'])}</p>
<h3>Evidence chains</h3><ul>{chains}</ul>
<h3>What is still unknown</h3><ul>{li(c['summary']['unknowns'])}</ul>
<h3>Next steps</h3><ol>{li(c['summary']['next_steps'])}</ol>
<h3>Timeline</h3><table><tr><th>Time (UTC)</th><th>Event</th><th>Actor</th><th>Asset</th></tr>{tl}</table>"""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{_e(r['report_id'])} — AegisVision Assurance Report</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>
body{{font:13px/1.45 system-ui,Segoe UI,Arial,sans-serif;color:#15181d;max-width:1000px;margin:24px auto;padding:0 20px}}
h1{{font-size:22px;margin:0}}h2{{font-size:16px;border-bottom:2px solid #1d2733;padding-bottom:4px;margin-top:28px}}h3{{font-size:13px;margin:14px 0 4px}}
table{{border-collapse:collapse;width:100%;margin:6px 0}}td,th{{border:1px solid #cfd5dc;padding:4px 6px;text-align:left;vertical-align:top}}th{{background:#eef1f4}}
.kv th{{width:210px}}.m{{color:#48515c;font-size:12px;margin-top:2px}}.hdr{{display:flex;justify-content:space-between;align-items:flex-end;border-bottom:3px solid #1d2733;padding-bottom:8px}}
.b{{display:inline-block;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:600;background:#e4e8ec}}
.b-PASS,.b-TRUSTED,.b-ACCEPT,.b-REAL{{background:#d6f0dd;color:#14532d}}.b-WARNING,.b-REVIEW,.b-MEDIUM,.b-DRIFT,.b-REVIEW-REQUIRED,.b-HEURISTIC{{background:#fdf0c8;color:#6b4e00}}
.b-FAIL,.b-FAILED,.b-HIGH,.b-CRITICAL,.b-UNTRUSTED,.b-QUARANTINE,.b-SUSPICIOUS,.b-QUARANTINE-RECOMMENDED{{background:#fbd9d7;color:#7f1d1d}}.b-DEMO--SIMULATED{{background:#e2dcf7;color:#3b2a86}}
.demo{{background:#f1eefc;border:1px solid #c9bff0;padding:6px 10px;border-radius:4px}}code{{font-size:11px;word-break:break-all}}
@media print{{body{{margin:0;max-width:none}}h2{{page-break-after:avoid}}tr{{page-break-inside:avoid}}}}
</style></head><body>
<div class="hdr"><div><div class="m">AegisVision · AI Assurance Report · {_e(r['generator']['mode'])}</div><h1>{_e(r['report_id'])} — Overall: {_badge(a['overall'])}</h1></div>
<div class="m">Generated {_e(r['generated_at'])}<br>Run {_e(a['run_id'])}</div></div>
<p class="demo">{_e(r['data_provenance_note'])}</p>
{case_block}
<h2>2. Assessment by pillar</h2><table><tr><th>Pillar</th><th>Status</th><th>Note</th></tr>{rows_p}</table>
<h2>3. Findings ({len(r['findings'])})</h2><table><tr><th>ID</th><th>Severity</th><th>Pillar</th><th>Detail</th></tr>{rows_f}</table>
<h2>4. Dataset</h2><table class="kv"><tr><th>Format / samples</th><td>{_e(r['dataset']['summary']['format'])} · {r['dataset']['summary']['num_samples']} samples · classes {_e(', '.join(r['dataset']['summary']['classes']))}</td></tr>
<tr><th>Manifest digest</th><td><code>{_e(r['dataset']['manifest']['digest'])}</code> (+{r['dataset']['manifest']['added']} / −{r['dataset']['manifest']['removed']} / ~{r['dataset']['manifest']['modified']} since import)</td></tr>
<tr><th>Detector counts</th><td>{_e(json.dumps(r['dataset']['statistics']))}</td></tr></table>
<h3>Source-level aggregation</h3><table><tr><th>Contributor</th><th>Batch</th><th>Samples</th><th>Label flags</th><th>OOD</th><th>Duplicates</th><th>Trigger</th><th>Anomaly rate</th></tr>{rows_src}</table>
<h2>5. Model</h2><table class="kv"><tr><th>Deployed</th><td>{_e(dep['file'])} · {_e(dep['format'])} · access: {_e(dep['access'])}</td></tr>
<tr><th>Deployed SHA-256</th><td><code>{_e(dep['sha256'])}</code></td></tr><tr><th>Registered</th><td>{_e(reg.get('model_id'))} <code>{_e(reg.get('sha256'))}</code> · match: {_e(m.get('digest_match'))}</td></tr>
<tr><th>Reference accuracy</th><td>{m.get('reference_accuracy', 0):.1%}</td></tr><tr><th>Fingerprint</th><td>{_e(json.dumps(m.get('fingerprint')))}</td></tr>
<tr><th>Trigger search space</th><td>{_e(m.get('trigger_search_space'))}</td></tr></table>
<table><tr><th>Origin</th><th>Pattern</th><th>Pos</th><th>Target</th><th>Flip rate</th><th>Control</th></tr>{tt}</table>
<h2>6. Distribution shift</h2><p>Status {_badge(ds_shift.get('status', '—'))} — {_e(ds_shift.get('attribution'))}. MMD p = {_e(ds_shift.get('mmd_p_value'))}, brightness PSI = {_e(ds_shift.get('brightness_psi'))}.</p>
<table><tr><th>Statistic</th><th>Reference mean</th><th>Current mean</th><th>KS D</th><th>p (Bonferroni)</th></tr>{shift_rows}</table>
<h2>7. Inference integrity</h2><p>{inf['valid']} / {inf['total']} records valid · {inf['invalid']} invalid · {inf['rejected_submissions']} rejected submissions. By category: {_e(json.dumps(inf['by_category']))}</p>
<h2>8. Audit trail</h2><p>Hash chain {'intact' if audit_v['valid'] else 'BROKEN at #' + str(audit_v['first_break_seq'])} · {audit_v['records']} records · head <code>{_e(audit_v['head_hash'])}</code></p>
<h2>9. Coverage</h2><h3>Supported attack classes</h3><ul>{li(r['supported_attack_classes'])}</ul>
<h3>Unsupported attack classes</h3><ul>{li(r['unsupported_attack_classes'])}</ul>
<table><tr><th>Pillar</th><th>Capability</th><th>Status</th><th>Notes</th></tr>{caps}</table>
<h2>10. Assumptions &amp; limitations</h2><h3>Assumptions</h3><ul>{li(r['assumptions'])}</ul><h3>Limitations</h3><ul>{li(r['limitations'])}</ul>
<h2>11. Attack Lab context <span class="b b-DEMO--SIMULATED">DEMO / SIMULATED</span></h2><p class="m">{_e(sc['label'])}</p><ul>{score or '<li>none</li>'}</ul>
<h2>12. Recommended disposition: {_badge(r['recommended_disposition'])}</h2>
<h2>Report integrity</h2><p class="m">SHA-256 <code>{_e(r['integrity']['report_sha256'])}</code><br>Ed25519 signature <code>{_e(r['integrity']['signature'])}</code><br>Key {_e(r['integrity']['key_id'])}</p>
</body></html>"""
