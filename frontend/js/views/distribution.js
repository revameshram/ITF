// Distribution-shift view: reference vs current operational inputs.
import { api, bindFindingClicks, esc, findingItem, img, method, pct } from "../ui.js";

export async function render(el) {
  const [inf, fs] = await Promise.all([api("/api/inferences"), api("/api/findings")]);
  const d = inf.distribution;
  const findings = fs.filter((f) => f.pillar === "distribution");
  const recent = inf.records.slice(-24);
  const refs = Array.from({ length: 24 }, (_, i) => `reference/images/ref_${String(i * 6).padStart(4, "0")}.png`);
  const status = d?.status || "NOT ASSESSED";
  const expl = {
    PASS: "No statistically significant difference between the current inputs and the reference distribution.",
    DRIFT: "Significant, global and coherent change across most frames. This points to changed operating conditions (lighting, sensor, season), not tampering. Model guarantees may not hold.",
    SUSPICIOUS: "A localised pattern appears in a subset of frames while the rest of each frame looks normal. This is more consistent with a sticker, overlay or trigger than with environmental change.",
    INCONCLUSIVE: "The inputs differ significantly, but the evidence cannot separate operational drift from manipulation.",
    INSUFFICIENT_DATA: "Not enough recent frames to assess shift.",
  }[status] || "Run the assurance check to assess the current input window.";
  el.innerHTML = `
    <div class="page-h"><div><h1>Distribution shift</h1><p>Compares what the deployed model is seeing now (the inputs bound in the latest ${d?.window_size ?? 60} inference records) with the trusted reference distribution. A shift is not automatically an attack; the attribution below is labelled as a heuristic.</p></div></div>
    <div class="grid" style="grid-template-columns:300px 1fr">
      <div class="verdict s-${status === "PASS" ? "pass" : ["DRIFT", "INCONCLUSIVE"].includes(status) ? "warn" : status === "SUSPICIOUS" ? "fail" : "none"}">
        <div class="v-label">Current window</div><div class="v-val" style="font-size:22px">${esc(status)}</div><div class="small">${esc(d?.attribution || "")}</div></div>
      <div class="card"><div class="card-h"><h2>Interpretation</h2>${method("HEURISTIC")}</div><div>${esc(expl)}</div>
        ${d ? `<div class="kv" style="margin-top:10px"><div>MMD permutation test</div><div>p = ${Number(d.mmd_p_value).toFixed(3)} ${method("REAL")}</div><div>Brightness PSI</div><div>${Number(d.brightness_psi).toFixed(2)} ${d.brightness_psi > 0.25 ? "(major shift)" : d.brightness_psi > 0.1 ? "(moderate)" : "(stable)"}</div>
        ${d.model_view ? `<div>Model confidence</div><div>${Number(d.model_view.reference_mean_confidence).toFixed(2)} → ${Number(d.model_view.current_mean_confidence).toFixed(2)} (class-mix TV distance ${Number(d.model_view.class_mix_tv_distance).toFixed(2)})</div>` : ""}
        <div>Localised frames</div><div>${d.localized_frames} · recurring stamped patches: ${d.recurring_patches?.length || 0}</div></div>` : ""}</div>
    </div>
    ${d?.tests ? `<div class="grid g2 section">
      <div class="card"><div class="card-h"><h2>Two-sample tests per image statistic</h2>${method("REAL")}</div>
        <table class="tbl"><tr><th>Statistic</th><th>Reference</th><th>Current</th><th>Δ</th><th>Outside ref. 1–99%</th><th>KS D</th><th>p (Bonf.)</th></tr>
        ${d.tests.map((t) => `<tr class="${t.p_bonferroni < 0.01 ? "bad" : ""}"><td>${esc(t.feature.replace("_", " "))}</td><td>${t.reference_mean}</td><td>${t.current_mean}</td><td>${(t.relative_change * 100).toFixed(0)}%</td><td>${pct(t.fraction_outside_ref_1_99)}</td><td>${t.ks_d}</td><td class="mono small">${Number(t.p_bonferroni).toExponential(1)}</td></tr>`).join("")}</table></div>
      <div class="card"><div class="card-h"><h2>Findings</h2></div><div class="flist">${findings.length ? findings.map(findingItem).join("") : `<div class="empty">No shift findings.</div>`}</div>
        <div class="note warn" style="margin-top:10px">Distribution shift ≠ attack. The reference battery only represents daytime conditions.</div></div>
    </div>` : ""}
    <div class="grid g2 section">
      <div class="card"><div class="card-h"><h2>Reference distribution</h2><span class="muted small">trusted battery (sample)</span></div><div class="gallery">${refs.map((p) => `<div class="thumb">${img(p, 72, "")}</div>`).join("")}</div></div>
      <div class="card"><div class="card-h"><h2>Current operational inputs</h2><span class="muted small">latest records</span></div><div class="gallery">${recent.map((r) => `<div class="thumb ${r.verdict === "INVALID" ? "flag" : ""}">${img(r.input_ref, 72, "")}<div class="lbl">#${r.seq} ${esc(r.label)}</div></div>`).join("")}</div></div>
    </div>`;
  bindFindingClicks(el);
}
