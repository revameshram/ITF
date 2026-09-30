// Training-data integrity view.
import { $, api, badge, bindFindingClicks, esc, findingItem, img, method, pct, short } from "../ui.js";

export async function render(el) {
  const d = await api("/api/dataset");
  const lr = d.last_run;
  const s = d.summary;
  const flagged = new Set((d.findings || []).filter((f) => f.severity !== "INFO").flatMap((f) => f.tags?.sample_ids || []));
  const batches = [...new Set(d.samples.map((x) => x.batch))].sort();
  const manOk = d.manifest_digest === d.registered_manifest_digest;
  el.innerHTML = `
    <div class="page-h"><div><h1>Datasets</h1><p>Contributed training data: parsed through the ${esc(s.format)} adapter, fingerprinted with a SHA-256 manifest, and audited for label, duplicate, out-of-distribution and trigger anomalies — then aggregated by contributor and batch.</p></div></div>
    <div class="grid g4">
      <div class="card"><div class="muted small">Dataset</div><h2 style="margin-top:4px">${esc(s.name)}</h2><div class="muted small">${esc(s.format)} · ${s.num_samples} samples · classes ${esc(s.classes.join(", "))}</div><div style="margin-top:6px">${badge("DEMO / SIMULATED")}</div></div>
      <div class="card"><div class="muted small">Contributors</div><h2 style="margin-top:4px">${Object.keys(s.contributors).length}</h2><div class="muted small">${Object.entries(s.contributors).map(([k, v]) => `${esc(k)} (${v})`).join(" · ")}</div></div>
      <div class="card"><div class="muted small">Batches</div><h2 style="margin-top:4px">${s.batches}</h2><div class="muted small">provenance: ${s.has_provenance ? "available (aegis_source / sources.csv)" : "missing — aggregation unavailable"}</div></div>
      <div class="card"><div class="muted small">Manifest (SHA-256)</div><div class="hash" style="margin-top:6px">${esc(short(d.manifest_digest, 32))}</div>
        <div class="small" style="margin-top:4px">${manOk ? '<span style="color:var(--pass)">matches accepted manifest</span>' : '<span style="color:var(--warn)">differs from accepted manifest</span>'}${lr ? ` · +${lr.manifest.added} −${lr.manifest.removed} ~${lr.manifest.modified}` : ""}</div></div>
    </div>
    ${!lr ? `<div class="note section">Run the assurance check to populate detector results.</div>` : `
    <div class="grid g2 section">
      <div class="card"><div class="card-h"><h2>Source-level aggregation</h2><span class="muted small">contributor → batch → suspicious samples</span></div>
        <div class="tbl-wrap"><table class="tbl"><tr><th>Contributor</th><th>Batch</th><th>n</th><th>Label</th><th>OOD</th><th>Dup</th><th>Trigger</th><th>p (label)</th><th>Anomaly rate</th></tr>
        ${lr.source_table.sort((a, b) => b.anomaly_rate - a.anomaly_rate).map((r) => `<tr class="click ${r.anomaly_rate >= .1 ? "bad" : ""}" data-batch="${esc(r.batch)}"><td>${esc(r.contributor)}</td><td class="mono" style="white-space:nowrap">${esc(r.batch)}</td><td>${r.samples}</td><td>${r.label_flags || ""}</td><td>${r.ood || ""}</td><td>${r.duplicates || ""}</td><td>${r.trigger || ""}</td>
          <td class="mono small">${r.label_p_value != null ? Number(r.label_p_value).toExponential(1) : ""}</td><td style="min-width:120px"><div class="row" style="gap:6px"><div class="bar ${r.anomaly_rate >= .1 ? "fail" : ""}" style="flex:1"><i style="width:${Math.min(100, r.anomaly_rate * 100)}%"></i></div>${pct(r.anomaly_rate)}</div></td></tr>`).join("")}</table></div>
        <div class="muted tiny" style="margin-top:6px">p (label): one-sided binomial test of the batch's label-disagreement count against the ${pct(lr.calibration.baseline_label_flag_rate, 1)} rate measured on trusted data. Click a row to view its images.</div></div>
      <div class="card"><div class="card-h"><h2>Dataset findings</h2></div><div class="flist" id="ds-f">${d.findings.length ? d.findings.map(findingItem).join("") : `<div class="empty">No findings.</div>`}</div>
        <h3 style="margin:14px 0 6px">Checks performed</h3>
        <table class="tbl">${d.checks.map((c) => `<tr><td class="mono">${esc(c.check)}</td><td>${badge(c.status)}</td><td>${method(c.method_status)}</td><td class="small">${esc(c.detail)}</td></tr>`).join("")}</table>
        <div class="muted tiny" style="margin-top:6px">Calibrated on ${esc(lr.calibration.calibrated_on)}.</div></div>
    </div>`}
    <div class="card section"><div class="card-h"><h2>Samples</h2><select class="select" id="batch-sel">${batches.map((b) => `<option ${b === (lr?.source_table?.[0]?.batch) ? "selected" : ""}>${esc(b)}</option>`).join("")}</select>
      <span class="muted small" id="batch-meta"></span><span class="spacer"></span><span class="small"><span class="dot dot-fail"></span> flagged by a MEDIUM+ finding</span></div><div class="gallery" id="gal"></div></div>`;
  const showBatch = (b) => {
    const items = d.samples.filter((x) => x.batch === b);
    $("#batch-meta", el).textContent = `${items.length} images · ${esc(items[0]?.contributor || "")} · ${items.filter((x) => flagged.has(x.sample_id)).length} flagged`;
    $("#gal", el).innerHTML = items.map((x) => `<div class="thumb ${flagged.has(x.sample_id) ? "flag" : ""}" title="${esc(x.sample_id)}">${img(x.path, 80, "")}<div class="lbl">${esc(x.label)}</div></div>`).join("");
  };
  const sel = $("#batch-sel", el);
  sel.onchange = () => showBatch(sel.value);
  showBatch(sel.value);
  el.querySelectorAll("[data-batch]").forEach((r) => (r.onclick = () => { sel.value = r.dataset.batch; showBatch(r.dataset.batch); sel.scrollIntoView({ behavior: "smooth", block: "center" }); }));
  bindFindingClicks(el);
}
