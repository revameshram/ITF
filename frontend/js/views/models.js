// Model integrity view.
import { api, badge, bindFindingClicks, esc, findingItem, method, pct, post, toast, withBusy } from "../ui.js";

export async function render(el, _p, ctx) {
  const d = await api("/api/models");
  const m = d.last_run;
  const dep = d.deployed;
  const active = d.registry.find((r) => r.active);
  const match = active && active.sha256 === dep.sha256;
  el.innerHTML = `
    <div class="page-h"><div><h1>Models</h1><p>Is the model itself trustworthy? File digest against a signed registry, behavioural fingerprint on a trusted reference battery, white-box parameter/activation statistics, and controlled trigger tests. Model-agnostic adapters: ${d.formats.map((f) => `${esc(f.format)} ${f.available ? "✓" : "(" + esc(f.runtime) + ")"}`).join(" · ")}.</p></div>
      <span class="spacer"></span>
      <div><div class="muted tiny" style="margin-bottom:4px">Assessment access level</div><div class="seg" id="acc"><button data-a="white-box" class="${d.access === "white-box" ? "on" : ""}">White-box</button><button data-a="black-box" class="${d.access === "black-box" ? "on" : ""}">Black-box</button></div></div></div>
    <div class="grid g2">
      <div class="card"><div class="card-h"><h2>Deployed model</h2>${badge(match ? "PASS" : "FAIL")}<span class="muted small">${match ? "digest matches registry" : "digest NOT in active registry entry"}</span></div>
        <div class="kv"><div>File</div><div class="mono">${esc(dep.path)}</div><div>Format / runtime</div><div>${esc(dep.format)}</div>
        <div>SHA-256</div><div class="hash">${esc(dep.sha256)}</div><div>Metadata (card)</div><div>${esc(dep.card.name)} v${esc(dep.card.version)} · ${esc(dep.card.architecture || "")}</div>
        <div>Access</div><div>${esc(dep.access)} — parameters ${dep.capabilities.parameters ? "✓" : "✕"}, activations ${dep.capabilities.activations ? "✓" : "✕"}</div>
        <div>Preprocessing</div><div class="mono small">${esc(JSON.stringify(dep.card.preprocess))}</div></div>
        <div class="note" style="margin-top:10px">Name and version metadata are self-reported by the file and can be forged. Only the digest and the behavioural checks count as evidence.</div></div>
      <div class="card"><div class="card-h"><h2>Trusted model registry</h2><span class="muted small">Ed25519-signed manifests</span></div>
        <table class="tbl"><tr><th>ID</th><th>SHA-256</th><th>Ref. acc</th><th>Lineage</th><th>Manifest</th><th></th></tr>
        ${d.registry.map((r) => `<tr><td class="mono">${esc(r.model_id)}</td><td class="hash">${esc(r.sha256.slice(0, 16))}…</td><td>${pct(r.reference_accuracy, 1)}</td>
          <td class="small">${r.lineage?.previous_version ? `from ${esc(r.lineage.previous_version)}; ` : ""}${r.lineage?.new_sources?.length ? `+ ${esc(r.lineage.new_sources.join(", "))}` : "baseline"}</td>
          <td>${badge(r.manifest_valid ? "VALID" : "INVALID")}</td><td>${r.active ? badge("ACTIVE", "") : ""}</td></tr>`).join("")}</table>
        <div class="muted tiny" style="margin-top:6px">Lineage records which data sources each version was trained on; the correlation engine uses it.</div></div>
    </div>
    ${!m ? `<div class="note section">Run the assurance check to see the model assessment.</div>` : `
    <div class="grid g2 section">
      <div class="card"><div class="card-h"><h2>Checks performed</h2><span class="muted small">last run · access ${esc(m.deployed.access)}</span></div>
        <table class="tbl">${d.checks.map((c) => `<tr class="${c.status === "unavailable" ? "" : ""}"><td class="mono">${esc(c.check)}</td><td>${c.status === "unavailable" ? '<span class="b b-neutral">UNAVAILABLE</span>' : badge(c.status)}</td><td>${method(c.method_status)}</td><td class="small">${esc(c.detail)}</td></tr>`).join("")}</table>
        <h3 style="margin:14px 0 6px">Model findings</h3><div class="flist">${d.findings.length ? d.findings.map(findingItem).join("") : `<div class="empty">No model findings.</div>`}</div></div>
      <div class="card"><div class="card-h"><h2>Controlled trigger tests</h2>${method("HEURISTIC")}</div>
        <div class="muted small" style="margin-bottom:8px">Each candidate patch is stamped onto ${m.fingerprint ? "150" : ""} trusted reference images of other classes; "flip" = share forced into one class. A neutral grey patch at the same spot is the control. Search space: ${esc(m.trigger_search_space)}.</div>
        <div class="tbl-wrap"><table class="tbl"><tr><th>Pattern</th><th>Position</th><th>→ class</th><th style="width:30%">Flip rate</th><th>Control</th></tr>
        ${m.trigger_tests.slice(0, 10).map((t) => `<tr class="${t.flip_rate >= .5 && t.flip_rate - t.control_flip_rate >= .3 ? "bad" : ""}"><td>${t.origin === "dataset_candidate" ? `<b>from training data</b> <span class="muted small">(${esc(t.candidate_source)})</span>` : esc(t.pattern_name)}</td><td class="small">${esc(t.corner || "")} (${t.x},${t.y})</td><td>${esc(t.target)}</td>
          <td><div class="row" style="gap:6px"><div class="bar ${t.flip_rate >= .5 ? "fail" : ""}" style="flex:1"><i style="width:${t.flip_rate * 100}%"></i></div>${pct(t.flip_rate)}</div></td><td>${pct(t.control_flip_rate)}</td></tr>`).join("")}</table></div>
        <div class="note warn" style="margin-top:8px">A clean result only covers the tested patterns. It does <b>not</b> prove the model is free of backdoors.</div></div>
    </div>
    <div class="grid g3 section">
      <div class="card"><div class="card-h"><h2>Behavioural fingerprint</h2>${method("REAL")}</div>
        ${m.fingerprint ? `<div class="kv"><div>Agreement</div><div>${pct(m.fingerprint.agreement, 1)} with registered predictions</div><div>Mean |Δp|</div><div>${m.fingerprint.mean_abs_prob_diff.toFixed(4)}</div><div>Accuracy</div><div>${pct(m.fingerprint.registered_accuracy, 1)} → ${pct(m.fingerprint.deployed_accuracy, 1)}</div>
        ${m.version_diff ? `<div>vs ${esc(m.version_diff.previous)}</div><div>${pct(m.version_diff.agreement_with_previous, 1)} agreement (prev. acc ${pct(m.version_diff.previous_accuracy, 1)})</div>` : ""}</div>` : '<div class="muted">No registered fingerprint.</div>'}
        <div class="muted tiny" style="margin-top:8px">A backdoored model can match its predecessor almost perfectly on clean inputs. That is why the trigger tests exist.</div></div>
      <div class="card"><div class="card-h"><h2>Parameter statistics</h2>${method("REAL")}</div>
        ${m.param_stats ? `<table class="tbl"><tr><th>Tensor</th><th>Shape</th><th>L2</th><th>Kurtosis</th><th>Δ vs reg.</th></tr>${Object.entries(m.param_stats).map(([k, v]) => `<tr><td class="mono small">${esc(k)}</td><td class="small">${esc(v.shape.join("×"))}</td><td>${v.l2.toFixed(2)}</td><td>${v.kurtosis.toFixed(2)}</td><td>${m.param_deltas?.[k] ? pct(m.param_deltas[k].l2_rel_change, 1) : "—"}</td></tr>`).join("")}</table>`
          : `<div class="note">Unavailable. Parameter statistics require white-box access.</div>`}</div>
      <div class="card"><div class="card-h"><h2>Activation statistics</h2>${method("REAL")}</div>
        ${m.activation_stats ? Object.entries(m.activation_stats).map(([k, v]) => `<div class="kv"><div>Layer</div><div class="mono">${esc(k)}</div><div>Neurons</div><div>${v.neurons}</div><div>Dead fraction</div><div>${pct(v.dead_fraction, 1)}</div><div>Cosine to registered baseline</div><div>${v.cosine_to_registered_baseline?.toFixed(3) ?? "—"}</div></div>`).join("")
          : `<div class="note">Unavailable. Activation statistics require white-box access.</div>`}</div>
    </div>`}`;
  el.querySelectorAll("#acc button").forEach((b) => (b.onclick = () => withBusy(b, async () => {
    await post("/api/models/access", { access: b.dataset.a });
    toast(`Access level set to ${b.dataset.a}. Run the assurance check to re-assess.`);
    ctx.rerender();
  })));
  bindFindingClicks(el);
}
