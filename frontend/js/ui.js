// Shared UI helpers for AegisVision (no framework, no network beyond this local server).

export async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: {} };
  if (opts.body !== undefined) { init.body = JSON.stringify(opts.body); init.headers["Content-Type"] = "application/json"; }
  const r = await fetch(path, init);
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error((data && (data.detail || data.error)) || r.statusText);
  return data;
}
export const post = (p, body = {}) => api(p, { method: "POST", body });

export const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
export const pct = (x, d = 0) => (x == null ? "—" : `${(x * 100).toFixed(d)}%`);
export const short = (h, n = 12) => (h ? `${String(h).slice(0, n)}…` : "—");
export const time = (ts) => (ts ? ts.slice(11, 19) : "");
export const ago = (ts) => {
  if (!ts) return "";
  const s = (Date.now() - new Date(ts).getTime()) / 1000;
  if (s < 60) return `${Math.max(1, Math.round(s))}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
};

const PASS = ["PASS", "TRUSTED", "VALID", "ACCEPT", "CLOSED — ACCEPTED", "ran", "pass", "REAL"];
const WARN = ["WARNING", "REVIEW", "DRIFT", "INCONCLUSIVE", "REVIEW REQUIRED", "UNDER REVIEW", "MEDIUM", "HEURISTIC", "partial (black-box)"];
const FAIL = ["FAIL", "FAILED", "SUSPICIOUS", "UNTRUSTED", "QUARANTINE", "QUARANTINED", "QUARANTINE RECOMMENDED", "INVALID", "HIGH", "CRITICAL", "fail"];
export function tone(s) {
  if (PASS.includes(s)) return "pass";
  if (WARN.includes(s)) return "warn";
  if (FAIL.includes(s)) return "fail";
  if (s === "DEMO / SIMULATED") return "demo";
  if (s === "NOT IMPLEMENTED" || s === "unavailable" || s === "skipped") return "neutral";
  return "neutral";
}
export const badge = (s, extra = "") => `<span class="b b-${tone(s)} ${extra}">${esc(s)}</span>`;
export const sev = (s) => `<span class="sev sev-${esc(s)}">${esc(s)}</span>`;
export function method(ms) {
  const cls = ms === "REAL" ? "b-real" : ms === "HEURISTIC" ? "b-heur" : ms === "NOT IMPLEMENTED" ? "b-ni" : "b-demo";
  const tip = { REAL: "Deterministic / cryptographic / exact computation", HEURISTIC: "Real computation; the conclusion is a heuristic, uncalibrated score", "DEMO / SIMULATED": "Produced to demonstrate a capability", "NOT IMPLEMENTED": "Future enhancement" }[ms] || "";
  return `<span class="b ${cls}" title="${esc(tip)}">${esc(ms)}</span>`;
}
export const pillarName = (p) => ({ dataset: "Training data", model: "Model", inference: "Inference", distribution: "Distribution", governance: "Governance" }[p] || p);

export function toast(msg, ms = 2600) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.remove("show"), ms);
}

export function openDrawer(html) {
  const d = $("#drawer");
  $("#drawer-inner").innerHTML = `<button class="btn btn-sm drawer-close" data-close>Close ✕</button>` + html;
  d.classList.add("open");
  d.setAttribute("aria-hidden", "false");
  $("[data-close]", d).onclick = closeDrawer;
  return $("#drawer-inner");
}
export function closeDrawer() { $("#drawer").classList.remove("open"); $("#drawer").setAttribute("aria-hidden", "true"); }
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

export async function withBusy(btn, fn) {
  const old = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="spin"></span> ${old}`;
  try { return await fn(); } finally { btn.disabled = false; btn.innerHTML = old; }
}

export const img = (path, size = 64, cls = "px") => `<img class="${cls}" src="/api/image?path=${encodeURIComponent(path)}" width="${size}" height="${size}" alt="" loading="lazy">`;

export function patchDataURL(pattern, scale = 8) {
  const n = pattern.length, c = document.createElement("canvas");
  c.width = c.height = n * scale;
  const g = c.getContext("2d");
  pattern.forEach((row, y) => row.forEach((px, x) => { g.fillStyle = `rgb(${px[0]},${px[1]},${px[2]})`; g.fillRect(x * scale, y * scale, scale, scale); }));
  return c.toDataURL();
}

// ------------------------------------------------------------------ icons
const I = (d) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
export const icons = {
  dashboard: I('<circle cx="12" cy="5" r="2.2"/><circle cx="5" cy="15" r="2.2"/><circle cx="19" cy="15" r="2.2"/><circle cx="12" cy="20" r="1.6"/><path d="M11 7 6 13M13 7l5 6M7 15h10M6.5 16.8 10.8 19.2M17.5 16.8l-4.3 2.4"/>'),
  datasets: I('<ellipse cx="12" cy="5.5" rx="7" ry="2.5"/><path d="M5 5.5v13c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5v-13M5 12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5"/>'),
  models: I('<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9z"/><path d="m4 7.5 8 4.5 8-4.5M12 12v9"/>'),
  inferences: I('<path d="M4 12h10M11 8l4 4-4 4"/><rect x="15.5" y="6" width="5" height="12" rx="1.5"/><path d="M3 5v14"/>'),
  distribution: I('<path d="M3 18c3 0 3-9 6-9s3 6 6 6 3-8 6-8"/><path d="M3 21h18"/>'),
  cases: I('<rect x="3" y="7" width="18" height="13" rx="2"/><path d="M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M3 12h18"/>'),
  evidence: I('<circle cx="6" cy="6" r="2.2"/><circle cx="18" cy="7" r="2.2"/><circle cx="8" cy="18" r="2.2"/><circle cx="17" cy="17" r="2.2"/><path d="M8 6.5 15.8 7M7 8l1 7.8M10 18h5M17.5 9.2 17 14.8M7.6 7.6l7.8 7.8"/>'),
  attack: I('<path d="M9 3h6M10 3v6L5 18.5A1.5 1.5 0 0 0 6.3 21h11.4a1.5 1.5 0 0 0 1.3-2.5L14 9V3"/><path d="M7.5 15h9"/>'),
  audit: I('<rect x="4" y="3" width="7" height="5" rx="1"/><rect x="13" y="10" width="7" height="5" rx="1"/><rect x="4" y="16" width="7" height="5" rx="1"/><path d="M7.5 8v8M11 5.5h5.5V10M16.5 15v3.5H11"/>'),
  reports: I('<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>'),
  coverage: I('<path d="M12 3 4.5 6v6c0 4.5 3.2 8 7.5 9 4.3-1 7.5-4.5 7.5-9V6z"/><path d="m9 12 2 2 4-4"/>'),
};

// ------------------------------------------------------------------ findings
export function findingItem(f) {
  return `<div class="fitem" data-finding="${esc(f.id)}">
    <div class="f-top">${sev(f.severity)}<span class="mono muted">${esc(f.id)}</span><span class="b b-neutral">${esc(pillarName(f.pillar))}</span>${method(f.method_status)}
      <span class="spacer"></span><span class="muted tiny">conf ${Number(f.confidence).toFixed(2)}</span></div>
    <div class="f-title">${esc(f.title)}</div></div>`;
}
export function bindFindingClicks(root) {
  $$("[data-finding]", root).forEach((el) => (el.onclick = (e) => { e.stopPropagation(); showFinding(el.dataset.finding); }));
}

export async function showFinding(fid) {
  const f = await api(`/api/findings/${fid}`);
  const inner = openDrawer(`
    <div class="row" style="margin-bottom:6px">${sev(f.severity)}<span class="mono muted">${esc(f.id)}</span><span class="b b-neutral">${esc(pillarName(f.pillar))}</span>${method(f.method_status)}<span class="muted tiny mono">${esc(f.category)}</span></div>
    <h1 style="margin:4px 0 14px">${esc(f.title)}</h1>
    <div class="qa">
      <div><h4>What we found</h4><div>${esc(f.what)}</div></div>
      <div><h4>Why we flagged it</h4><div>${esc(f.why)}</div></div>
      <div><h4>Confidence / severity</h4>
        <div class="conf"><span>confidence</span><div class="bar ${f.confidence >= .8 ? "fail" : f.confidence >= .5 ? "warn" : ""}"><i style="width:${f.confidence * 100}%"></i></div><b>${Number(f.confidence).toFixed(2)}</b></div>
        <div class="muted small" style="margin-top:4px">${esc(f.confidence_basis)}</div></div>
      <div><h4>Method</h4><div>${esc(f.method)} ${method(f.method_status)}</div></div>
      <div><h4>Affected assets</h4><div class="row">${f.affected.map((a) => `<span class="b b-neutral">${esc(a)}</span>`).join("")}</div></div>
      <div><h4>Limitations</h4><ul>${f.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul></div>
      ${f.recommendation ? `<div><h4>Recommended action</h4><div>${esc(f.recommendation)}</div></div>` : ""}
      <div><h4>Evidence (${f.evidence_docs.length})</h4><div class="grid">${f.evidence_docs.map(evidenceBlock).join("")}</div></div>
    </div>`);
  hydratePatches(inner);
}

export function evidenceBlock(e) {
  return `<div class="card" style="background:var(--panel-2)">
    <div class="row"><span class="mono" style="color:var(--accent)">${esc(e.id)}</span><b>${esc(e.title)}</b><span class="spacer"></span><span class="muted tiny" title="SHA-256 of this evidence record">sha256 ${short(e.sha256, 10)}</span></div>
    <div class="muted small" style="margin:3px 0 8px">${esc(e.summary)}</div>${evidencePayload(e)}</div>`;
}

function sampleGrid(samples, extraKey) {
  return `<div class="gallery">${samples.map((s) => `<div class="thumb">${img(s.path, 72, "")}<div class="lbl" title="${esc(s.sample_id)}">${esc(s.label)}${s[extraKey] ? ` → ${esc(s[extraKey])}` : ""}</div><div class="lbl muted">${esc(s.batch || "")}</div></div>`).join("")}</div>`;
}

export function evidencePayload(e) {
  const p = e.payload || {};
  switch (e.kind) {
    case "sample_list":
      if (p.samples) return sampleGrid(p.samples.slice(0, 24), "reference_vote") + (p.total > 24 ? `<div class="muted tiny" style="margin-top:4px">+ ${p.total - 24} more</div>` : "");
      if (p.frames) return `<div class="gallery">${p.frames.slice(0, 24).map((f) => `<div class="thumb">${img(f.path, 72, "")}<div class="lbl mono">${esc(f.record_id.slice(4, 12))}</div></div>`).join("")}</div>` + (p.matches_dataset_trigger ? `<div class="note warn" style="margin-top:8px">Pattern matches the trigger candidate found in the training data.</div>` : "");
      return json(p);
    case "trigger_candidate": {
      const c = p.candidate;
      return `<div class="row" style="align-items:flex-start"><div><div class="muted tiny">recovered patch (${c.size}×${c.size} @ ${c.x},${c.y})</div><img class="px" data-patch='${esc(JSON.stringify(c.pattern))}' width="72" height="72" alt="patch"></div>
        <div class="kv" style="flex:1"><div>labels</div><div>${esc(JSON.stringify(p.label_distribution))}</div><div>label disagreements</div><div>${p.label_disagreements}</div><div>by source</div><div>${esc(JSON.stringify(p.by_source))}</div></div></div>
        <div style="margin-top:8px">${sampleGrid(p.samples.slice(0, 16))}</div>`;
    }
    case "duplicate_clusters":
      return p.clusters.slice(0, 4).map((c) => `<div class="muted tiny" style="margin:6px 0 3px">cluster of ${c.size}</div>${sampleGrid(c.members.slice(0, 8))}`).join("") + `<div class="muted tiny" style="margin-top:6px">${esc(p.method)}</div>`;
    case "statistical_test":
      if (p.tests) return `<div class="tbl-wrap"><table class="tbl"><tr><th>statistic</th><th>reference</th><th>current</th><th>Δ</th><th>KS D</th><th>p (Bonf.)</th></tr>${p.tests.map((t) => `<tr class="${t.p_bonferroni < 0.01 ? "bad" : ""}"><td>${esc(t.feature)}</td><td>${t.reference_mean}</td><td>${t.current_mean}</td><td>${(t.relative_change * 100).toFixed(0)}%</td><td>${t.ks_d}</td><td class="mono">${t.p_bonferroni.toExponential(1)}</td></tr>`).join("")}</table></div><div class="muted small" style="margin-top:6px">MMD permutation p = ${Number(p.mmd_p_value).toFixed(3)} · brightness PSI = ${Number(p.brightness_psi).toFixed(2)} · ${esc(p.reference)} vs ${esc(p.current)}</div>`;
      return `<div class="kv"><div>test</div><div>${esc(p.test)}</div><div>flagged / total</div><div>${p.k} / ${p.n}</div><div>baseline rate</div><div>${pct(p.baseline, 1)} (trusted data)</div><div>p-value</div><div class="mono">${Number(p.p_value).toExponential(2)}</div><div>confusion pairs</div><div>${esc(JSON.stringify(p.confusion_pairs))}</div></div>`;
    case "hash_comparison":
      return `<div class="kv"><div>registered</div><div class="hash">${esc(p.registered_sha256)}</div><div>deployed</div><div class="hash" style="color:var(--fail)">${esc(p.deployed_sha256)}</div><div>registered model</div><div>${esc(p.registered_model)}</div><div>matches other version</div><div>${esc(p.matches_other_registered || "no — unknown artefact")}</div></div>`;
    case "fingerprint":
      return `<div class="kv"><div>agreement</div><div>${pct(p.agreement, 1)}</div><div>mean |Δp|</div><div>${Number(p.mean_abs_prob_diff).toFixed(4)}</div><div>accuracy</div><div>${pct(p.registered_accuracy, 1)} → ${pct(p.deployed_accuracy, 1)}</div></div>`;
    case "trigger_test": {
      const rows = p.top_tests.map((t) => `<tr><td>${esc(t.origin === "dataset_candidate" ? "from training data" : t.pattern_name)}</td><td>${esc(t.corner || `(${t.x},${t.y})`)}</td><td>${esc(t.target)}</td><td><div class="bar ${t.flip_rate >= .5 ? "fail" : ""}"><i style="width:${t.flip_rate * 100}%"></i></div></td><td>${pct(t.flip_rate)}</td><td>${pct(t.control_flip_rate)}</td></tr>`).join("");
      const a = p.activation_response;
      return `<div class="tbl-wrap"><table class="tbl"><tr><th>pattern</th><th>position</th><th>→ class</th><th></th><th>flip</th><th>control</th></tr>${rows}</table></div>
        ${a ? `<div class="muted small" style="margin-top:6px">White-box: ${a.neurons_z_gt_3} hidden neurons in <code>${esc(a.layer)}</code> respond with z &gt; 3 to the trigger (top: ${a.top_neurons.map((n) => `#${n.neuron} z=${n.z}`).join(", ")}).</div>` : `<div class="muted small" style="margin-top:6px">Activation response: unavailable (black-box access).</div>`}
        <div class="muted tiny" style="margin-top:4px">Search space: ${esc(p.search_space)}</div>`;
    }
    case "verification":
      return p.results.slice(0, 4).map((r) => `<div style="margin-bottom:8px"><div class="row"><b class="mono">#${r.seq} ${esc(r.record_id)}</b>${badge(r.verdict)}</div>${checksList(r.checks)}</div>`).join("");
    case "ingest_log":
      return `<table class="tbl"><tr><th>time</th><th>record</th><th>reason</th></tr>${p.rejected.map((r) => `<tr class="bad"><td class="mono">${time(r.ts)}</td><td class="mono">${esc(r.record_id)}</td><td>${esc(r.reason)}</td></tr>`).join("")}</table>`;
    case "audit_verification":
      return `<table class="tbl"><tr><th>seq</th><th>problem</th><th>detail</th></tr>${p.problems.map((x) => `<tr class="bad"><td>#${x.seq}</td><td>${esc(x.problem)}</td><td>${esc(x.detail)}</td></tr>`).join("")}</table>`;
    case "manifest_diff":
      return json(p);
    case "signature_check":
      return json(p);
    default:
      return json(p);
  }
}

export function checksList(checks) {
  return `<div class="checks">${checks.map((c) => `<div class="check ${c.status}"><span class="ic">${c.status === "pass" ? "✓" : c.status === "fail" ? "✕" : "–"}</span><span class="mono">${esc(c.check)}</span><span>${esc(c.detail)}</span></div>`).join("")}</div>`;
}

export const json = (o) => `<pre class="json">${esc(JSON.stringify(o, null, 2))}</pre>`;

export function hydratePatches(root) {
  $$("img[data-patch]", root).forEach((el) => { try { el.src = patchDataURL(JSON.parse(el.dataset.patch)); } catch (e) { /* ignore */ } });
}

// ------------------------------------------------------------------ timeline
export function timeline(events) {
  if (!events || !events.length) return `<div class="empty">No events yet.</div>`;
  const kind = (t) => t.startsWith("finding") ? "k-finding" : t.startsWith("case") ? "k-case" : t.startsWith("attacklab") ? "k-attack" : t.startsWith("assurance") ? "k-run" : t.includes("registered") || t.includes("verified") ? "k-ok" : "";
  return `<div class="tl">${events.map((e) => `<div class="tl-item ${kind(e.event_type)}"><div class="tl-time">${time(e.ts)}</div><div class="tl-mark"><i></i></div>
    <div class="tl-ev"><span class="mono">${esc(e.event_type)}</span> <span class="muted">· ${esc(e.actor)}${e.asset ? ` · ${esc(e.asset)}` : ""}</span>${tlDetail(e)}</div></div>`).join("")}</div>`;
}
function tlDetail(e) {
  const d = e.details || {};
  const s = d.title || d.summary || d.name || (d.overall ? `overall ${d.overall}` : "") || (d.count ? `${d.count} records` : "") || (d.verdict ? d.verdict : "") || (d.disposition ? d.disposition : "");
  return s ? `<div class="muted small">${esc(String(s).slice(0, 140))}</div>` : "";
}

// ------------------------------------------------------------------ evidence graph (Cytoscape, vendored locally)
const NODE_STYLE = {
  AssuranceCore: { shape: "hexagon", color: "#5fb8c2", size: 46 },
  Dataset: { shape: "round-rectangle", color: "#6f93b8", size: 38 },
  Contributor: { shape: "ellipse", color: "#8a9bb0", size: 22 },
  Batch: { shape: "rectangle", color: "#7a8a9c", size: 20 },
  Sample: { shape: "ellipse", color: "#566574", size: 10 },
  Model: { shape: "diamond", color: "#5fb8c2", size: 34 },
  ModelVersion: { shape: "diamond", color: "#e0625b", size: 32 },
  Stream: { shape: "round-tag", color: "#6f93b8", size: 30 },
  ObservationWindow: { shape: "barrel", color: "#6f93b8", size: 26 },
  InferenceRecord: { shape: "round-rectangle", color: "#e0625b", size: 18 },
  Finding: { shape: "ellipse", color: "#d9a441", size: 26 },
  Evidence: { shape: "tag", color: "#a7b4c2", size: 14 },
  Case: { shape: "octagon", color: "#e0625b", size: 42 },
  AttackScenario: { shape: "star", color: "#9d8cf0", size: 30 },
};
const SEV_COLOR = { CRITICAL: "#ff6b62", HIGH: "#e0625b", MEDIUM: "#d9a441", LOW: "#6f93b8", INFO: "#56626e" };

const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

export function renderGraph(container, graph, { onSelect, hideTypes = [] } = {}) {
  if (!window.cytoscape) { container.innerHTML = `<div class="empty">Graph library not loaded.</div>`; return null; }
  const C = { label: cssVar("--text-2"), panel: cssVar("--panel"), line: cssVar("--line-2"), muted: cssVar("--muted"),
              fail: cssVar("--fail"), accent: cssVar("--accent"), demo: cssVar("--demo") };
  const nodes = graph.nodes.filter((n) => !hideTypes.includes(n.type));
  const keep = new Set(nodes.map((n) => n.id));
  const els = [
    ...nodes.map((n) => ({ data: { id: n.id, label: n.label, type: n.type, sev: n.props?.severity, raw: n } })),
    ...graph.edges.filter((e) => keep.has(e.source) && keep.has(e.target)).map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target, rel: e.rel, strength: e.props?.strength, gt: e.props?.ground_truth, raw: e } })),
  ];
  container.innerHTML = "";
  const cy = window.cytoscape({
    container, elements: els, minZoom: 0.2, maxZoom: 3,
    style: [
      { selector: "node", style: {
        "background-color": (n) => (n.data("type") === "Finding" ? SEV_COLOR[n.data("sev")] || "#d9a441" : NODE_STYLE[n.data("type")]?.color || "#777"),
        shape: (n) => NODE_STYLE[n.data("type")]?.shape || "ellipse",
        width: (n) => NODE_STYLE[n.data("type")]?.size || 18, height: (n) => NODE_STYLE[n.data("type")]?.size || 18,
        label: "data(label)", color: C.label, "font-size": 8, "text-valign": "bottom", "text-margin-y": 3, "text-wrap": "ellipsis", "text-max-width": 110,
        "border-width": 1.5, "border-color": C.panel, "background-opacity": 0.92 } },
      { selector: "node[type='AttackScenario']", style: { "border-style": "dashed", "border-color": "#9d8cf0", "border-width": 2 } },
      { selector: "node[type='Case']", style: { "font-size": 10, "font-weight": 700, color: C.fail } },
      { selector: "node[type='AssuranceCore']", style: { "font-size": 10, "font-weight": 700 } },
      { selector: "edge", style: { width: 1, "line-color": C.line, "target-arrow-color": C.line, "target-arrow-shape": "triangle", "arrow-scale": 0.6, "curve-style": "bezier", label: "data(rel)", "font-size": 6.5, color: C.muted, "text-rotation": "autorotate", "text-background-color": C.panel, "text-background-opacity": 0.8, "text-background-padding": 1 } },
      { selector: "edge[rel='correlates_with']", style: { width: 2.5, "line-color": "#e0625b", "target-arrow-color": "#e0625b", color: C.fail, "font-size": 7.5 } },
      { selector: "edge[strength='context']", style: { "line-style": "dashed", width: 1.4, "line-color": "#8a6d2f", "target-arrow-color": "#8a6d2f", color: "#b99a57" } },
      { selector: "edge[rel='violates']", style: { "line-color": "#e0625b", "target-arrow-color": "#e0625b" } },
      { selector: "edge[gt]", style: { "line-style": "dotted", "line-color": "#9d8cf0", "target-arrow-color": "#9d8cf0", color: "#9d8cf0" } },
      { selector: ":selected", style: { "border-color": C.accent, "border-width": 3 } },
      { selector: ".faded", style: { opacity: 0.18 } },
    ],
    layout: { name: "cose", animate: false, nodeRepulsion: () => 9000, idealEdgeLength: () => 60, edgeElasticity: () => 80, gravity: 0.35, numIter: 1500, padding: 24, randomize: true },
  });
  cy.on("tap", "node", (ev) => {
    const n = ev.target;
    cy.elements().addClass("faded");
    n.closedNeighborhood().removeClass("faded");
    onSelect && onSelect(n.data("raw"), n.connectedEdges().map((e) => e.data("raw")));
  });
  cy.on("tap", (ev) => { if (ev.target === cy) cy.elements().removeClass("faded"); });
  return cy;
}

export function graphLegend(types) {
  return `<div class="g-legend">${types.map((t) => `<span><span class="dot" style="background:${NODE_STYLE[t]?.color || "#999"}"></span>${t}</span>`).join("")}
    <span><span class="dot" style="background:#e0625b"></span>correlates_with</span><span><span class="dot" style="background:#9d8cf0"></span>ground truth (DEMO)</span></div>`;
}

export function nodeDetail(n, edges) {
  const p = n.props || {};
  const rel = edges.map((e) => `<div class="small"><span class="mono muted">${esc(e.source)}</span> <b>${esc(e.rel)}</b> <span class="mono muted">${esc(e.target)}</span>${e.props?.reason ? `<div class="muted tiny">${esc(e.props.reason)}</div>` : ""}</div>`).join("");
  let open = "";
  if (n.type === "Finding") open = `<button class="btn btn-sm" data-finding="${esc(n.id.split(":")[1])}">Open finding</button>`;
  if (n.type === "Case") open = `<a class="btn btn-sm" href="#/cases/${esc(n.id.split(":")[1])}">Open case</a>`;
  if (n.type === "Evidence") open = `<button class="btn btn-sm" data-evidence="${esc(n.id.split(":")[1])}">Show evidence</button>`;
  if (n.type === "InferenceRecord") open = `<button class="btn btn-sm" data-verify="${esc(n.id.split(":")[1])}">Verify record</button>`;
  return `<div class="row"><span class="b b-neutral">${esc(n.type)}</span>${p.demo ? badge("DEMO / SIMULATED") : ""}</div>
    <h2 style="margin:6px 0">${esc(n.label)}</h2><div class="mono muted tiny">${esc(n.id)}</div>
    ${Object.keys(p).length ? `<div class="kv" style="margin-top:8px">${Object.entries(p).map(([k, v]) => `<div>${esc(k)}</div><div>${esc(typeof v === "object" ? JSON.stringify(v) : v)}</div>`).join("")}</div>` : ""}
    <div style="margin-top:8px">${open}</div>
    <h3 style="margin:12px 0 6px">Relationships (${edges.length})</h3><div class="grid" style="gap:6px">${rel}</div>`;
}

export async function showEvidence(eid) {
  const e = await api(`/api/evidence/${eid}`);
  const inner = openDrawer(`<h1 style="margin-bottom:10px">${esc(e.id)} · ${esc(e.title)}</h1><div class="muted small">from finding <a href="#" data-finding="${esc(e.finding_id)}">${esc(e.finding_id)}</a> · kind ${esc(e.kind)} · sha256 <span class="hash">${esc(e.sha256)}</span></div><div style="margin-top:10px">${evidenceBlock(e)}</div>`);
  hydratePatches(inner);
  bindFindingClicks(inner);
}

export async function showVerify(recordId) {
  const inner = openDrawer(`<h1>Verifying ${esc(recordId)}…</h1>`);
  const v = await post(`/api/inferences/${recordId}/verify`);
  const r = v.record || {};
  inner.innerHTML = `<button class="btn btn-sm drawer-close" data-close>Close ✕</button>
    <div class="row"><h1>Record #${esc(r.seq)} · ${esc(recordId)}</h1>${badge(v.verdict)}</div>
    <div class="muted small" style="margin:4px 0 12px">Every check is recomputed now from the stored record, the trusted public key and the referenced input image.</div>
    <div class="row" style="align-items:flex-start;gap:16px">${r.input_ref ? `<div>${img(r.input_ref, 112)}<div class="muted tiny">bound input</div></div>` : ""}
      <div class="kv" style="flex:1"><div>output</div><div><b>${esc(r.output?.label)}</b> (${esc(r.output?.confidence)})</div><div>timestamp</div><div class="mono">${esc(r.timestamp)}</div><div>nonce</div><div class="hash">${esc(r.nonce)}</div><div>signer key</div><div class="mono">${esc(r.signer?.key_id)}</div><div>record hash</div><div class="hash">${esc(r.record_hash)}</div><div>prev record</div><div class="hash">${esc(r.prev_record_hash)}</div></div></div>
    <h3 style="margin:14px 0 6px">Verification checks</h3>${checksList(v.checks || [])}
    <h3 style="margin:14px 0 6px">Cryptographic bindings</h3><div class="kv">${Object.entries(r.bindings || {}).map(([k, x]) => `<div>${esc(k)}</div><div class="hash">${esc(x)}</div>`).join("")}</div>
    <h3 style="margin:14px 0 6px">Stored record (as found in the database)</h3>${json(r)}`;
  $("[data-close]", inner).onclick = closeDrawer;
}

// global delegated handlers for buttons rendered inside drawers / panels
document.addEventListener("click", (e) => {
  const f = e.target.closest("[data-finding]");
  if (f && f.tagName !== "DIV") { e.preventDefault(); showFinding(f.dataset.finding); return; }
  const ev = e.target.closest("[data-evidence]");
  if (ev) { e.preventDefault(); showEvidence(ev.dataset.evidence); return; }
  const vr = e.target.closest("[data-verify]");
  if (vr) { e.preventDefault(); showVerify(vr.dataset.verify); }
});
