// Dashboard: overall assurance status + interconnected pipeline map (original design) + cases/findings/timeline.
import { $, $$, api, badge, bindFindingClicks, esc, findingItem, pct, post, short, timeline, toast, tone, withBusy } from "../ui.js";

const POS = { dataset: [300, 112], model: [130, 262], inference: [470, 262], core: [300, 400] };

function pillarTone(s) { return s ? tone(s) : "none"; }

export async function render(el, _params, ctx) {
  const [d, latest] = await Promise.all([api("/api/dashboard"), api("/api/runs/latest/full")]);
  const run = latest && latest.run_id ? latest : null;
  const st = d.run ? d.run.statuses : null;
  const ov = d.overall;
  const tiles = [
    ["dataset", "Dataset", st?.dataset.status, st ? `${st.dataset.findings} finding(s)` : "not assessed", "#/datasets"],
    ["model", "Model", st?.model.status, st ? `coverage: ${st.model.coverage}` : "not assessed", "#/models"],
    ["inference", "Inference", st?.inference.status, st ? `${st.inference.valid}/${st.inference.total} records valid` : "not assessed", "#/inferences"],
    ["distribution", "Distribution", st?.distribution.status, st ? st.distribution.attribution || "" : "not assessed", "#/distribution"],
    ["governance", "Audit trail", st?.governance.status, st ? "hash chain + signed head" : "not assessed", "#/audit"],
  ];
  el.innerHTML = `
    <div class="hero">
      <div class="verdict s-${ov === "NOT ASSESSED" ? "none" : tone(ov)}">
        <div class="v-label">Overall assurance status</div>
        <div class="v-val">${esc(ov)}</div>
        <div class="muted small">${d.run ? `${esc(d.run.run_id)} · ${esc(d.run.finished.slice(11, 19))} UTC · ${d.run.seconds}s` : "Run the assurance check to assess the pipeline."}</div>
        ${d.pending_scenarios.length ? `<div class="note demo" style="margin-top:6px">${d.pending_scenarios.length} Attack Lab scenario(s) injected since the last check — run the assurance check.</div>` : ""}
      </div>
      <div class="grid g5">${tiles.map(([k, label, s, sub, href]) => `
        <a class="tile s-${s ? pillarTone(s) : "none"}" href="${href}" style="text-decoration:none;color:inherit">
          <div class="t-label">${label}</div><div class="t-val">${esc(s || "—")}</div><div class="t-sub">${esc(sub)}</div></a>`).join("")}</div>
    </div>

    <div class="map-wrap section">
      <div class="map" id="map"></div>
      <div class="panel-detail" id="map-detail"></div>
    </div>

    <div class="grid g3 section">
      <div class="card"><div class="card-h"><h2>Active cases</h2><span class="spacer"></span><a href="#/cases" class="small">all cases →</a></div>
        ${d.cases.length ? d.cases.map((c) => `<a href="#/cases/${esc(c.id)}" class="fitem" style="display:block;text-decoration:none;color:inherit;margin-bottom:8px">
          <div class="f-top"><span class="mono" style="color:var(--accent)">${esc(c.id)}</span>${badge(c.status)}<span class="spacer"></span><span class="sev sev-${esc(c.severity)}">${esc(c.severity)}</span></div>
          <div class="f-title">${esc(c.title)}</div><div class="f-meta">risk ${Number(c.risk_score).toFixed(2)} · recommended ${esc(c.recommended_disposition)}</div></a>`).join("") : `<div class="empty">No cases. Cases open automatically when an assurance run produces findings of MEDIUM severity or higher.</div>`}
      </div>
      <div class="card"><div class="card-h"><h2>Recent findings</h2><span class="spacer"></span><a href="#/evidence" class="small">evidence graph →</a></div>
        <div class="flist" id="dash-findings">${d.findings.length ? d.findings.map(findingItem).join("") : `<div class="empty">No findings.</div>`}</div></div>
      <div class="card"><div class="card-h"><h2>Audit timeline</h2><span class="spacer"></span><a href="#/audit" class="small">full log →</a></div>
        <div style="max-height:420px;overflow-y:auto">${timeline([...d.timeline].reverse())}</div></div>
    </div>

    <div class="grid g2 section">
      <div class="card" id="demo-guide"></div>
      <div class="card"><div class="card-h"><h2>Offline / air-gapped status</h2><span class="spacer"></span><button class="btn btn-sm" id="egress">Test egress block</button></div>
        <div class="kv">
          <div>Mode</div><div><span class="b b-pass">${esc(d.network.mode)}</span></div>
          <div>Network guard</div><div>${d.network.guard_installed ? "installed — non-loopback sockets are refused" : "not installed"}</div>
          <div>Blocked attempts</div><div id="blocked">${d.network.blocked_count}</div>
          <div>Browser policy</div><div class="mono small">Content-Security-Policy: default-src 'self'</div>
          <div>External assets</div><div>none (graph library vendored locally)</div>
          <div>Audit head</div><div class="hash">${esc(d.audit_head ? `#${d.audit_head.seq} ${short(d.audit_head.hash, 24)} (signed)` : "—")}</div>
        </div>
        <div class="muted tiny" style="margin-top:8px">${esc(d.network.scope)}</div></div>
    </div>`;

  drawMap($("#map", el), d, run);
  showNode("core", d, run);
  bindFindingClicks($("#dash-findings", el));
  $("#egress", el).onclick = async (e) => withBusy(e.target, async () => {
    const r = await post("/api/system/netcheck");
    $("#blocked", el).textContent = r.status.blocked_count;
    toast(r.blocked ? "Outbound connection attempt was BLOCKED by the offline guard ✓" : r.detail, 4000);
  });
  demoGuide($("#demo-guide", el), d, run, ctx);
}

// ------------------------------------------------------------------ map
function drawMap(host, d, run) {
  const st = d.run?.statuses;
  const s = {
    dataset: st ? pillarTone(st.dataset.status) : "none",
    model: st ? pillarTone(st.model.status) : "none",
    inference: st ? (pillarTone(st.inference.status) === "fail" || pillarTone(st.distribution.status) === "fail" ? "fail" : pillarTone(st.inference.status) === "warn" || pillarTone(st.distribution.status) === "warn" ? "warn" : pillarTone(st.inference.status)) : "none",
    core: d.overall === "NOT ASSESSED" ? "none" : tone(d.overall),
  };
  const statusText = {
    dataset: st?.dataset.status, model: st?.model.status,
    inference: st ? `${st.inference.status} · SHIFT ${st.distribution.status}` : null, core: d.overall,
  };
  const stats = run?.stats || {};
  // satellites from real data
  const srcTable = stats.dataset?.source_table || [];
  const dsSats = srcTable.map((r) => ({ flag: r.anomaly_rate >= 0.1, label: `${r.contributor}/${r.batch}` }));
  const modelSats = (d.pipeline.model.versions || []).map((v) => ({ flag: !v.manifest_valid, label: `${v.model_id}${v.active ? " (active)" : ""}` }));
  const invalid = new Set((stats.inference?.invalid_records || []).map((r) => r.record_id));
  const nrec = d.pipeline.inference.records;
  const nsat = Math.min(nrec, 18), nbad = Math.min(invalid.size, nsat);
  const infSats = [...Array(nsat)].map((_, i) => ({ flag: i < nbad, label: i < nbad ? "invalid record" : "record" }));
  const coreSats = (run?.finding_summary || []).filter((f) => f.severity !== "INFO").map((f) => ({ flag: ["HIGH", "CRITICAL"].includes(f.severity), warn: f.severity === "MEDIUM" }));

  const sat = (key, items, radius, start, span) => {
    const [cx, cy] = POS[key];
    const n = items.length;
    return items.map((it, i) => {
      const a = (start + (n === 1 ? span / 2 : (span * i) / (n - 1))) * Math.PI / 180;
      const x = cx + radius * Math.cos(a), y = cy + radius * Math.sin(a);
      return `<line class="sat-link" x1="${cx + 50 * Math.cos(a)}" y1="${cy + 50 * Math.sin(a)}" x2="${x}" y2="${y}"/><circle class="sat ${it.flag ? "flag" : ""}" cx="${x}" cy="${y}" r="${it.flag ? 5 : 3.6}" ${it.warn ? 'style="fill:rgba(217,164,65,.35);stroke:#d9a441"' : ""}><title>${esc(it.label || "")}</title></circle>`;
    }).join("");
  };
  const link = (a, b, toneTo, curve = 0) => {
    const [x1, y1] = POS[a], [x2, y2] = POS[b];
    const mx = (x1 + x2) / 2 + curve, my = (y1 + y2) / 2;
    const dpath = `M${x1},${y1} Q${mx},${my} ${x2},${y2}`;
    return `<path class="link" d="${dpath}"/><path class="flow ${toneTo === "fail" ? "fail" : toneTo === "warn" ? "warn" : ""}" d="${dpath}"/>`;
  };
  const node = (key, title, sub) => {
    const [x, y] = POS[key];
    const t = s[key];
    return `<g class="node" data-node="${key}" transform="translate(${x},${y})">
      <circle class="halo s-${t}-c" r="60" style="fill:none;stroke-dasharray:2 5"/>
      <circle class="ring s-${t}-c" r="46" style="fill:var(--map-ring)"/>
      <text class="n-title" text-anchor="middle" y="5">${title}</text>
      <text class="n-sub" text-anchor="middle" y="64">${esc(sub)}</text>
      <text class="n-stat s-${t}-c" text-anchor="middle" y="${key === "dataset" ? -92 : 81}" style="stroke:none">${esc(statusText[key] || "NOT ASSESSED")}</text></g>`;
  };
  let grid = "";
  for (let x = 20; x < 600; x += 28) for (let y = 20; y < 500; y += 28) grid += `<circle cx="${x}" cy="${y}" r=".8" style="fill:var(--map-dot)"/>`;
  host.innerHTML = `<div class="map-title">Assured pipeline · live</div>
    <svg viewBox="0 0 600 500" preserveAspectRatio="xMidYMid meet">${grid}
      ${link("dataset", "model", s.model, -30)}${link("dataset", "inference", s.inference, 30)}${link("model", "inference", s.inference)}
      ${link("model", "core", s.core, -20)}${link("inference", "core", s.core, 20)}
      ${sat("dataset", dsSats, 74, 200, 140)}${sat("model", modelSats, 70, 150, 60)}${sat("inference", infSats, 72, -70, 140)}${sat("core", coreSats, 68, 190, 160)}
      ${node("dataset", "DATASET", `${d.pipeline.dataset.samples} samples · ${d.pipeline.dataset.batches} batches`)}
      ${node("model", "MODEL", `${d.pipeline.model.active || "—"} · ${d.pipeline.model.access}`)}
      ${node("inference", "INFERENCE", `${d.pipeline.inference.stream} · ${d.pipeline.inference.records} records`)}
      ${node("core", "ASSURANCE", "core · correlated evidence")}
    </svg>
    <div class="legend"><span><span class="dot dot-pass"></span> pass</span><span><span class="dot dot-warn"></span> review</span><span><span class="dot dot-fail"></span> fail / integrity break</span><span>satellites = real assets (batches, records, findings)</span></div>`;
  $$(".node", host).forEach((g) => (g.onclick = () => {
    $$(".node", host).forEach((x) => x.classList.remove("sel"));
    g.classList.add("sel");
    showNode(g.dataset.node, d, run);
  }));
}

function showNode(key, d, run) {
  const box = $("#map-detail");
  const stats = run?.stats || {};
  const fs = (p) => (run?.finding_summary || []).filter((f) => p.includes(f.pillar));
  const list = (items) => items.length ? `<div class="flist">${items.map(findingItem).join("")}</div>` : `<div class="muted small">No findings.</div>`;
  let html = "";
  if (!run) {
    html = `<h2>Pipeline not yet assessed</h2><p class="muted">The clean demo pipeline is loaded: ${d.pipeline.dataset.samples} contributed images, model ${esc(d.pipeline.model.active)} and ${d.pipeline.inference.records} signed inference records. Click <b>Run assurance check</b> to audit it.</p>`;
  } else if (key === "dataset") {
    const top = [...(stats.dataset?.source_table || [])].sort((a, b) => b.anomaly_rate - a.anomaly_rate).slice(0, 5);
    const m = stats.dataset?.manifest || {};
    html = `<div class="row"><h2>Dataset</h2>${badge(run.statuses.dataset.status)}</div>
      <div class="kv" style="margin:10px 0"><div>Samples</div><div>${stats.dataset.summary.num_samples} · ${esc(stats.dataset.summary.format)}</div>
      <div>Contributors</div><div>${Object.entries(stats.dataset.summary.contributors).map(([k, v]) => `${esc(k)} (${v})`).join(", ")}</div>
      <div>Manifest</div><div>+${m.added} added · −${m.removed} removed · ~${m.modified} modified since import</div></div>
      <h3 style="margin:10px 0 6px">Most anomalous sources</h3>
      <table class="tbl"><tr><th>source</th><th>n</th><th>anomaly rate</th></tr>${top.map((r) => `<tr class="${r.anomaly_rate >= .1 ? "bad" : ""}"><td>${esc(r.contributor)} / ${esc(r.batch)}</td><td>${r.samples}</td><td><div class="bar ${r.anomaly_rate >= .1 ? "fail" : ""}"><i style="width:${Math.min(100, r.anomaly_rate * 100)}%"></i></div> ${pct(r.anomaly_rate)}</td></tr>`).join("")}</table>
      <h3 style="margin:12px 0 6px">Dataset findings</h3>${list(fs(["dataset"]))}<div style="margin-top:10px"><a href="#/datasets">Open dataset view →</a></div>`;
  } else if (key === "model") {
    const m = stats.model || {};
    const best = (m.trigger_tests || [])[0];
    html = `<div class="row"><h2>Model</h2>${badge(run.statuses.model.status)}</div>
      <div class="kv" style="margin:10px 0"><div>Deployed digest</div><div class="hash">${esc(short(m.deployed?.sha256, 24))}</div>
      <div>Registered</div><div>${esc(m.registered?.model_id || "—")} · ${m.digest_match ? "digest match ✓" : "<b style='color:var(--fail)'>MISMATCH</b>"}</div>
      <div>Access</div><div>${esc(m.deployed?.access)} · coverage ${esc(run.statuses.model.coverage)}</div>
      <div>Reference accuracy</div><div>${pct(m.reference_accuracy, 1)}</div>
      <div>Fingerprint</div><div>${m.fingerprint ? `${pct(m.fingerprint.agreement, 1)} agreement with registration` : "—"}</div>
      <div>Strongest trigger test</div><div>${best ? `${pct(best.flip_rate)} → ${esc(best.target)} (control ${pct(best.control_flip_rate)})` : "—"}</div></div>
      <h3 style="margin:10px 0 6px">Model findings</h3>${list(fs(["model"]))}<div style="margin-top:10px"><a href="#/models">Open model view →</a></div>`;
  } else if (key === "inference") {
    const i = stats.inference || {};
    const dist = stats.distribution || {};
    html = `<div class="row"><h2>Inference provenance</h2>${badge(run.statuses.inference.status)}</div>
      <div class="kv" style="margin:10px 0"><div>Records</div><div>${i.valid} valid / ${i.total} total</div>
      <div>Invalid</div><div>${i.invalid ? Object.entries(i.by_category).map(([k, v]) => `${esc(k)} ×${v}`).join(", ") : "none"}</div>
      <div>Rejected at ingest</div><div>${i.rejected_submissions}</div>
      <div>Input distribution</div><div>${badge(dist.status || "—")} ${esc(dist.attribution || "")}</div></div>
      ${(i.invalid_records || []).slice(0, 6).map((r) => `<div class="row" style="margin:4px 0"><span class="mono">#${r.seq} ${esc(r.record_id)}</span>${badge("INVALID")}<span class="muted tiny">${esc(r.categories.join(", "))}</span><span class="spacer"></span><button class="btn btn-sm" data-verify="${esc(r.record_id)}">Verify</button></div>`).join("")}
      <h3 style="margin:12px 0 6px">Inference &amp; shift findings</h3>${list(fs(["inference", "distribution"]))}
      <div style="margin-top:10px"><a href="#/inferences">Open inference view →</a> · <a href="#/distribution">distribution →</a></div>`;
  } else {
    const strong = (run.correlations || []).filter((l) => l.strength === "strong");
    html = `<div class="row"><h2>Assurance core</h2>${badge(run.overall)}</div>
      <p class="muted small" style="margin:6px 0 10px">Correlates evidence from every pillar into cases. Correlations come from explicit rules, each with a stated reason.</p>
      <div class="kv"><div>Findings</div><div>${run.finding_summary.length} (${run.finding_summary.filter((f) => f.method_status === "REAL").length} deterministic, ${run.finding_summary.filter((f) => f.method_status === "HEURISTIC").length} heuristic)</div>
      <div>Strong correlations</div><div>${strong.length}</div><div>Case</div><div>${run.case_id ? `<a href="#/cases/${esc(run.case_id)}">${esc(run.case_id)} →</a>` : "none"}</div>
      <div>Audit chain</div><div>${badge(run.statuses.governance.status)}</div></div>
      ${strong.slice(0, 5).map((l) => `<div class="note" style="margin-top:6px"><span class="mono">${esc(l.a)} ↔ ${esc(l.b)}</span> <span class="muted">${esc(l.rule)}</span><div class="small">${esc(l.reason)}</div></div>`).join("")}
      ${run.scenarios?.length ? `<h3 style="margin:12px 0 6px">Attack Lab scorecard ${badge("DEMO / SIMULATED")}</h3>${d.scorecard.map((s) => `<div class="small"><b>${esc(s.scenario)}</b>: ${s.expected.map((x) => `${x.detected ? "✓" : "✕"} <span class="mono">${esc(x.category)}</span>`).join(" · ")}</div>`).join("")}` : ""}`;
  }
  box.innerHTML = html;
  bindFindingClicks(box);
}

// ------------------------------------------------------------------ judge demo guide
async function demoGuide(box, d, run, ctx) {
  const runs = await api("/api/runs");
  const scenarioRun = runs.find((r) => r.case_id);
  const cleanRun = runs.find((r) => r.overall === "TRUSTED");
  const pending = d.pending_scenarios.length > 0;
  const steps = [
    ["Launch AegisVision — clean demo pipeline loaded", true, ""],
    ["Run the assurance check → all pillars PASS (TRUSTED)", !!cleanRun, `<button class="btn btn-sm" data-act="run">Run check</button>`],
    ["Open Attack Lab → inject “Controlled Data Poisoning + Inference Tampering”", pending || !!scenarioRun, `<a class="btn btn-sm" href="#/attack-lab">Attack Lab</a>`],
    ["Run assurance again → Dataset WARNING · Model REVIEW · Inference FAILED", !!scenarioRun, `<button class="btn btn-sm" data-act="run">Run check</button>`],
    ["Open the automatically created case", false, scenarioRun ? `<a class="btn btn-sm" href="#/cases/${esc(scenarioRun.case_id)}">${esc(scenarioRun.case_id)}</a>` : ""],
    ["Explore the evidence graph and timeline", false, `<a class="btn btn-sm" href="#/evidence">Evidence</a>`],
    ["Verify the tampered inference record (cryptographic proof)", false, `<a class="btn btn-sm" href="#/inferences">Inferences</a>`],
    ["Generate the signed assurance report", false, `<a class="btn btn-sm" href="#/reports">Reports</a>`],
  ];
  box.innerHTML = `<div class="card-h"><h2>Judge demo (≈3 min)</h2><span class="spacer"></span><button class="btn btn-sm btn-ghost" data-act="reset">Reset demo</button></div>
    <div class="steps">${steps.map(([t, done, act]) => `<div class="step-i ${done ? "done" : ""}"><span style="flex:1">${t}</span>${act}</div>`).join("")}</div>`;
  box.querySelectorAll("[data-act=run]").forEach((b) => (b.onclick = () => ctx.runAssurance(b)));
  box.querySelector("[data-act=reset]").onclick = (e) => withBusy(e.target, async () => {
    await post("/api/demo/reset");
    toast("Demo reset: clean pipeline restored");
    await ctx.refreshStatus();
    ctx.rerender();
  });
}
