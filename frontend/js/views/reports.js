// Assurance reports: generate (signed JSON + printable HTML), list, open.
import { api, badge, esc, post, short, toast, withBusy } from "../ui.js";

export async function render(el) {
  const [reports, cases, runs] = await Promise.all([api("/api/reports"), api("/api/cases"), api("/api/runs")]);
  el.innerHTML = `
    <div class="page-h"><div><h1>Assurance reports</h1><p>Structured report: case, assessment time, dataset and model information and hashes, findings, evidence, confidence, severity, shift and inference-integrity results, audit history, supported and unsupported attack classes, assumptions, limitations and the recommended disposition. It is exported as JSON and as HTML. For a PDF, open the HTML and use Print → Save as PDF. Every report is SHA-256 hashed and Ed25519 signed.</p></div></div>
    <div class="card"><div class="row"><select class="select" id="target">
        ${cases.map((c) => `<option value="${esc(c.id)}">${esc(c.id)} — ${esc(c.title)}</option>`).join("")}
        ${runs.length ? `<option value="">Latest assessment (${esc(runs[runs.length - 1].run_id)}, ${esc(runs[runs.length - 1].overall)})</option>` : ""}</select>
      <button class="btn btn-primary" id="gen" ${runs.length ? "" : "disabled"}>Generate report</button>
      <span class="muted small">${runs.length ? "" : "Run an assurance check first."}</span></div></div>
    <div class="card section">${reports.length ? `<table class="tbl"><tr><th>Report</th><th>Generated (UTC)</th><th>Case</th><th>Overall</th><th>Disposition</th><th>SHA-256</th><th></th></tr>
      ${reports.map((r) => `<tr><td class="mono" style="color:var(--accent)">${esc(r.report_id)}</td><td class="mono small">${esc(r.generated_at.slice(0, 19).replace("T", " "))}</td><td class="mono">${esc(r.case || "—")}</td><td>${badge(r.overall)}</td><td>${badge(r.disposition)}</td><td class="hash">${short(r.sha256, 16)}</td>
        <td><a class="btn btn-sm" href="/api/reports/${esc(r.report_id)}.html" target="_blank" rel="noopener">Open HTML</a> <a class="btn btn-sm" href="/api/reports/${esc(r.report_id)}.json" download>JSON</a></td></tr>`).join("")}</table>` : `<div class="empty">No reports yet.</div>`}</div>`;
  el.querySelector("#gen").onclick = (e) => withBusy(e.target, async () => {
    const v = el.querySelector("#target").value;
    const r = await post("/api/reports", v ? { case_id: v } : {});
    toast(`${r.report_id} generated and signed`);
    window.open(`/api/reports/${r.report_id}.html`, "_blank");
    render(el);
  });
}
