// Inference provenance view: signed records, live verification, ingest log.
import { $$, api, badge, bindFindingClicks, esc, findingItem, img, post, short, time, toast, withBusy } from "../ui.js";

export async function render(el, _p, ctx) {
  const d = await api("/api/inferences");
  const recs = [...d.records].reverse();
  const invalid = recs.filter((r) => r.verdict === "INVALID");
  const lastFindings = (await api("/api/findings")).filter((f) => f.pillar === "inference");
  el.innerHTML = `
    <div class="page-h"><div><h1>Inference provenance</h1><p>Every inference produces a signed record. Changing any bound element after signing (the image, the model, the configuration or the output) makes verification fail. Verification below is recomputed live from the database.</p></div></div>
    <div class="card">
      <div class="row" style="gap:6px;font-size:12px;justify-content:center;flex-wrap:wrap">
        ${["input image SHA-256", "model / weights SHA-256", "preprocess config SHA-256", "inference config SHA-256", "output SHA-256", "timestamp + nonce + seq", "prev record hash"].map((x) => `<span class="b b-neutral" style="text-transform:none;font-weight:600">${x}</span>`).join('<span class="muted">+</span>')}
        <span class="muted">→</span><span class="b b-info" style="text-transform:none">record hash (SHA-256)</span><span class="muted">→</span><span class="b b-pass" style="text-transform:none">Ed25519 signature</span></div>
    </div>
    <div class="grid g4 section">
      <div class="card"><div class="muted small">Records (stream cam-01)</div><h1 style="margin-top:4px">${d.summary.total}</h1></div>
      <div class="card"><div class="muted small">Valid (live check)</div><h1 style="margin-top:4px;color:var(--pass)">${d.summary.valid}</h1></div>
      <div class="card"><div class="muted small">Invalid (live check)</div><h1 style="margin-top:4px;color:${d.summary.invalid ? "var(--fail)" : "var(--text)"}">${d.summary.invalid}</h1></div>
      <div class="card"><div class="muted small">Rejected at ingest (replay / forged)</div><h1 style="margin-top:4px;color:${d.ingest_log.some((x) => !x.accepted) ? "var(--warn)" : "var(--text)"}">${d.ingest_log.filter((x) => !x.accepted).length}</h1></div>
    </div>
    <div class="grid section" style="grid-template-columns:minmax(0,1.6fr) minmax(0,1fr)">
      <div class="card"><div class="card-h"><h2>Signed inference records</h2><span class="spacer"></span>
        <span class="muted small">simulate camera frames:</span><button class="btn btn-sm" data-run="day">+10 day</button><button class="btn btn-sm" data-run="night">+10 night</button><button class="btn btn-sm" data-run="triggered">+10 w/ sticker ${badge("DEMO / SIMULATED")}</button></div>
        <div class="tbl-wrap" style="max-height:640px;overflow-y:auto"><table class="tbl"><tr><th>#</th><th>Input</th><th>Time</th><th>Output</th><th>Model digest</th><th>Signer</th><th>Verdict</th><th></th></tr>
        ${recs.map((r) => `<tr class="${r.verdict === "INVALID" ? "bad" : ""}"><td class="mono">${r.seq}</td><td>${img(r.input_ref, 30)}</td><td class="mono small">${time(r.timestamp)}</td><td><b>${esc(r.label)}</b> <span class="muted small">${Number(r.confidence).toFixed(2)}</span></td>
          <td class="hash">${short(r.model_sha256, 10)}</td><td class="mono small">${esc(r.signer.slice(0, 8))}</td><td>${badge(r.verdict)}${r.failures.length ? `<div class="muted tiny">${esc(r.failures.join(", "))}</div>` : ""}</td><td><button class="btn btn-sm" data-verify="${esc(r.record_id)}">Verify</button></td></tr>`).join("")}</table></div></div>
      <div style="display:grid;gap:14px;align-content:start">
        <div class="card"><div class="card-h"><h2>Integrity failures</h2></div>
          ${invalid.length ? invalid.map((r) => `<div class="row" style="margin-bottom:6px"><span class="mono">#${r.seq}</span><span class="mono small">${esc(r.record_id)}</span>${badge("INVALID")}<span class="spacer"></span><button class="btn btn-sm btn-danger" data-verify="${esc(r.record_id)}">Show proof</button><div class="muted tiny" style="width:100%">${esc(r.failures.join(", "))}</div></div>`).join("") : `<div class="empty">All records verify.</div>`}
          ${lastFindings.length ? `<h3 style="margin:12px 0 6px">Findings (last run)</h3><div class="flist">${lastFindings.map(findingItem).join("")}</div>` : ""}</div>
        <div class="card"><div class="card-h"><h2>Ingest log</h2><span class="muted small">nonce registry + monotonic sequence</span></div>
          ${d.ingest_log.length ? `<table class="tbl"><tr><th>Time</th><th>Record</th><th>Result</th></tr>${d.ingest_log.map((x) => `<tr class="${x.accepted ? "" : "bad"}"><td class="mono small">${time(x.ts)}</td><td class="mono small">${esc(x.record_id)}</td><td>${badge(x.accepted ? "PASS" : "FAIL")}<div class="small muted">${esc(x.reason || "accepted")}</div></td></tr>`).join("")}</table>` : `<div class="empty">No external submissions yet. The Attack Lab "Replay attack" scenario submits replayed records here.</div>`}
          <div class="muted tiny" style="margin-top:6px">Trusted signer keys: ${d.trusted_keys.map((k) => `<span class="mono">${esc(k)}</span>`).join(", ")}</div></div>
      </div>
    </div>`;
  $$("[data-run]", el).forEach((b) => (b.onclick = () => withBusy(b, async () => {
    const r = await post("/api/inferences/run", { frames: b.dataset.run, count: 10 });
    toast(`${r.created} new signed records (${b.dataset.run} frames)`);
    ctx.rerender();
  })));
  bindFindingClicks(el);
}
