// Cases list + forensic investigation view.
import { $, $$, api, assetChip, badge, bindFindingClicks, closeDrawer, esc, graphLegend, invalidateCaches, method, notProve, pillarName, post, renderGraph, scoreLabel, scoreShort, setTrailRoot, sev, showAsset, showFinding, timeline, timelineLegend, toast, withBusy } from "../ui.js";

const PILLAR_ORDER = ["dataset", "model", "distribution", "inference", "governance"];

export async function render(el, params, ctx) {
  if (params[0]) return renderCase(el, params[0], ctx);
  const cases = await api("/api/cases");
  el.innerHTML = `<div class="page-h"><div><h1>Cases</h1><p>A case opens automatically when an assurance run produces findings of MEDIUM severity or higher. It groups correlated evidence, a timeline and a recommended disposition.</p></div></div>
    ${cases.length ? `<div class="card"><table class="tbl"><tr><th>Case</th><th>Title</th><th>Severity</th><th>Status</th><th>Risk</th><th>Recommended</th><th>Analyst</th><th>Findings</th><th>Created</th></tr>
      ${cases.map((c) => `<tr class="click" data-href="#/cases/${esc(c.id)}"><td class="mono" style="color:var(--accent)">${esc(c.id)}</td><td><b>${esc(c.title)}</b></td><td>${sev(c.severity)}</td><td>${badge(c.status)}</td>
        <td>${Number(c.risk_score).toFixed(2)}</td><td>${badge(c.recommended_disposition)}</td><td>${c.disposition ? badge(c.disposition) : '<span class="muted">pending</span>'}</td><td>${c.findings.length}</td><td class="mono small">${esc(c.created_at.slice(0, 19).replace("T", " "))}</td></tr>`).join("")}</table></div>`
      : `<div class="empty">No cases yet. Inject a scenario in the <a href="#/attack-lab">Attack Lab</a> and run the assurance check.</div>`}`;
  $$("[data-href]", el).forEach((r) => (r.onclick = () => (location.hash = r.dataset.href)));
}

function chainFlow(ch, fmap) {
  const fs = ch.findings.map((id) => fmap[id]).filter(Boolean).sort((a, b) => PILLAR_ORDER.indexOf(a.pillar) - PILLAR_ORDER.indexOf(b.pillar));
  const src = fs.find((f) => f.tags?.primary_source)?.tags.primary_source;
  const steps = [];
  if (src) steps.push(`<span class="step">${esc(src.replace("/", " → "))}</span>`);
  fs.forEach((f) => steps.push(`<span class="step" data-finding="${esc(f.id)}" style="cursor:pointer"><span class="sev sev-${f.severity}">${f.severity[0]}</span> ${esc(f.id)} ${esc(f.title.length > 46 ? f.title.slice(0, 46) + "…" : f.title)}</span>`));
  return `<div class="chain"><div class="row"><b>${esc(ch.chain_id)}</b><span class="b b-neutral">${esc(ch.pillars.map(pillarName).join(" + "))}</span>${ch.strength === "strong" ? '<span class="b b-warn" title="Findings share specific evidence (same source, trigger location, lineage or record chain). Correlation is not proof of causation.">correlated</span>' : '<span class="b b-neutral">single finding</span>'}</div>
    <div class="chain-flow">${steps.join('<span class="arrow">→</span>')}</div><div class="muted small" style="margin-top:6px">${esc(ch.narrative)}</div></div>`;
}

// Four-way split of what the case establishes. Only uses data the backend produced:
// REAL findings + run-level verification results -> KNOW; HEURISTIC findings -> SUSPECT;
// backend unknowns + method limits -> DON'T KNOW / DOES NOT PROVE.
function assessment(c, run) {
  const rel = c.finding_docs.filter((f) => f.severity !== "INFO");
  const st = run?.stats || {};
  const know = [];
  if (st.audit) know.push([`Audit chain ${st.audit.valid ? "intact" : `broken at #${st.audit.first_break_seq}`}`, `${st.audit.records} hash-chained records at assessment time`]);
  if (st.inference) know.push([`${st.inference.valid} of ${st.inference.total} inference records verify`, st.inference.invalid ? `${st.inference.invalid} fail cryptographic verification` : "no record fails verification"]);
  if (st.model?.registered) know.push([`Deployed model digest ${st.model.digest_match ? "matches" : "does NOT match"} registered ${st.model.registered.model_id}`, `SHA-256 ${String(st.model.deployed?.sha256 || "").slice(0, 16)}…`]);
  if (st.dataset?.manifest) { const m = st.dataset.manifest; know.push([`Dataset manifest: +${m.added} added, −${m.removed} removed, ~${m.modified} modified since the accepted snapshot`, "SHA-256 manifest comparison"]); }
  rel.filter((f) => f.method_status === "REAL").forEach((f) => know.push([`${f.id}: ${f.title}`, f.what]));
  const heur = rel.filter((f) => f.method_status !== "REAL");
  const suspect = heur.map((f) => [`${f.id}: ${f.title}`, `${scoreShort(f)} ${Number(f.confidence).toFixed(2)} (uncalibrated) · observed: ${f.what}`]);
  const strong = c.chains.filter((ch) => ch.strength === "strong" && ch.findings.length > 1);
  if (strong.length) suspect.push(["The linked findings are related", "They share specific evidence (source batch, trigger location, lineage or record chain). That is a correlation, not an established cause."]);
  const unknown = (c.summary.unknowns || []).filter((u) => !/^F-\d+: conclusion is heuristic/.test(u))
    .map((u) => u.startsWith("Attacker identity") ? "Who performed these actions, and whether any of them were intentional" : u);
  if (strong.length) unknown.push("Whether the correlated findings share a single cause");
  unknown.push("Whether other attack types or untested triggers are present. No finding does not mean no attack.");
  const np = new Map();
  rel.forEach((f) => notProve(f).forEach((x) => np.set(x, [...(np.get(x) || []), f.id])));
  const npList = [...np.entries()].map(([x, ids]) => [x, ids.join(", ")]);
  if (st.model?.digest_match && heur.some((f) => f.pillar === "model")) npList.unshift(["Valid hashes and signatures do not make the model behaviourally trustworthy", `the deployed model is correctly registered, yet ${heur.filter((f) => f.pillar === "model").map((f) => f.id).join(", ")} flags its behaviour`]);
  const li = (items, icon) => items.map(([a, b]) => `<li><i>${icon}</i><div>${esc(a)}${b ? `<div class="sub">${esc(b)}</div>` : ""}</div></li>`).join("");
  return `<div class="kq" id="case-assessment">
    <div class="k-know"><h4>What we know</h4><div class="muted tiny" style="margin-bottom:6px">directly observed or cryptographically verified</div><ul>${li(know, "✓")}</ul></div>
    <div class="k-sus"><h4>What we suspect</h4><div class="muted tiny" style="margin-bottom:6px">heuristic interpretation of observed measurements</div><ul>${suspect.length ? li(suspect, "⚠") : '<li><i>–</i><div class="muted">no heuristic findings</div></li>'}</ul></div>
    <div class="k-unk"><h4>What we don't know</h4><div class="muted tiny" style="margin-bottom:6px">cannot be established from the evidence</div><ul>${li(unknown.map((u) => [u]), "?")}</ul></div>
    <div class="k-np"><h4>What this does NOT prove</h4><div class="muted tiny" style="margin-bottom:6px">limits of the methods used</div><ul>${li(npList.slice(0, 9), "✗")}</ul></div>
  </div>`;
}

async function renderCase(el, id, ctx) {
  invalidateCaches();
  const c = await api(`/api/cases/${id}`);
  const run = await api(`/api/runs/${c.run_id}`).catch(() => null);
  const fmap = Object.fromEntries(c.finding_docs.map((f) => [f.id, f]));
  const main = c.finding_docs.filter((f) => f.severity !== "INFO").sort((a, b) => PILLAR_ORDER.indexOf(a.pillar) - PILLAR_ORDER.indexOf(b.pillar));
  const evFor = (f) => f.evidence.map((e) => `<a href="#" class="ev-id" data-evidence="${esc(e)}">${esc(e)}</a>`).join(", ");
  const s = c.summary;
  el.innerHTML = `
    <div class="inv-head">
      <div style="flex:1;min-width:260px"><div class="case-id">${esc(c.id)} · INVESTIGATION · ${esc(c.run_id)}</div><div class="case-title">${esc(c.title)}</div>
        <div class="muted small" style="margin-top:4px">opened ${esc(c.created_at.slice(0, 19).replace("T", " "))} UTC · ${c.findings.length} findings · ${c.evidence.length} evidence items</div></div>
      <div class="inv-stat"><span class="l">Status</span><span class="v">${badge(c.status)}</span></div>
      <div class="inv-stat"><span class="l">Severity</span><span class="v">${sev(c.severity)}${c.severity_escalated ? ' <span class="muted tiny" title="escalated: one corroborated chain spans ≥3 pillars">▲</span>' : ""}</span></div>
      <div class="inv-stat"><span class="l">Risk score</span><span class="v" title="${esc(c.risk_method)}">${Number(c.risk_score).toFixed(2)}</span><span class="muted tiny">heuristic aggregate · not a probability</span></div>
      <div class="inv-stat"><span class="l">Recommended</span><span class="v">${badge(c.recommended_disposition)}</span></div>
      <div class="inv-stat"><span class="l">Analyst decision</span><span class="v">${c.disposition ? badge(c.disposition) : '<span class="muted">pending</span>'}</span></div>
    </div>
    ${assessment(c, run)}
    <div class="inv-grid">
      <div class="card" style="padding:12px"><div class="card-h"><h2>Evidence</h2><span class="spacer"></span><span class="muted tiny">click to inspect</span></div>
        <div class="grid" style="gap:8px">${main.map((f) => `<div class="ev-card" data-f="${esc(f.id)}">
          <div class="row"><span>${evFor(f)}</span><span class="spacer"></span>${method(f.method_status)}</div>
          <div class="ev-t">${esc(f.title)}</div>
          <div class="row small" style="margin-bottom:4px"><span class="muted">${esc(f.id)} · ${esc(pillarName(f.pillar))}</span><span class="spacer"></span>${sev(f.severity)}</div>
          <div class="conf" title="${esc(scoreLabel(f))}"><span>${scoreShort(f)}</span><div class="bar ${f.confidence >= .8 ? "fail" : f.confidence >= .5 ? "warn" : ""}"><i style="width:${f.confidence * 100}%"></i></div><b>${Number(f.confidence).toFixed(2)}</b></div></div>`).join("")}</div>
        ${c.informational_findings.length ? `<div class="muted tiny" style="margin-top:8px">+ ${c.informational_findings.length} informational finding(s) not counted in the risk score</div>` : ""}
      </div>
      <div style="display:grid;gap:14px;min-width:0">
        <div class="graph-box" id="case-graph"></div>
        <div class="card"><div class="card-h"><h2>How the evidence is connected</h2><span class="muted small">shared evidence · correlation is not causation</span></div><div class="grid" style="gap:8px">${c.chains.map((ch) => chainFlow(ch, fmap)).join("")}</div></div>
      </div>
      <div style="display:grid;gap:14px;align-content:start">
        <div class="card"><div class="card-h"><h2>Disposition</h2></div>
          <div class="muted small" style="margin-bottom:8px">Recommended: <b>${esc(c.recommended_disposition)}</b> — ${esc(c.recommendation_reasons.join("; "))}</div>
          <textarea class="input" id="disp-note" rows="2" placeholder="Analyst note (recorded in the audit chain)"></textarea>
          <div class="disp" style="margin-top:8px"><button class="btn btn-ok" data-d="ACCEPT">Accept</button><button class="btn btn-warn" data-d="REVIEW">Review</button><button class="btn btn-danger" data-d="QUARANTINE">Quarantine</button><span class="spacer"></span><button class="btn btn-primary" id="gen-report">Generate report</button></div>
          ${c.disposition_history.length ? `<div style="margin-top:10px">${c.disposition_history.map((h) => `<div class="small"><span class="mono muted">${esc(h.ts.slice(11, 19))}</span> ${badge(h.disposition)} by ${esc(h.actor)} <span class="muted">audit #${h.audit_seq}</span>${h.note ? `<div class="muted">“${esc(h.note)}”</div>` : ""}</div>`).join("")}</div>` : ""}
        </div>
        <div class="card" id="case-timeline"><div class="card-h"><h2>Timeline</h2><span class="spacer"></span><span class="muted tiny">audit-chain timestamps</span></div>${timelineLegend()}<div style="max-height:460px;overflow-y:auto">${timeline(c.timeline)}</div></div>
      </div>
    </div>
    <div class="grid g2 section qa">
      <div class="card"><h4>What was observed</h4><div>${esc(s.what_happened)}</div></div>
      <div class="card"><h4>Where (click to follow)</h4><div class="row" style="gap:6px">${s.where.map((w) => w.includes(":") ? assetChip(w, c.run_id) : `<span class="muted small">${esc(w)}</span>`).join("")}</div></div>
      <div class="card"><h4>What evidence do we have?</h4><ul>${c.evidence_docs.map((e) => `<li>${assetChip(`evidence:${e.id}`)} ${esc(e.title)} <span class="muted small">(${esc(e.kind)}, for ${esc(e.finding_id)})</span></li>`).join("")}</ul></div>
      <div class="card"><h4>What should we do next?</h4><ol style="margin:0;padding-left:18px">${s.next_steps.map((n) => `<li>${esc(n)}</li>`).join("")}</ol></div>
    </div>
    ${c.attack_lab_context?.length ? `<div class="card section" style="border-color:rgba(157,140,240,.35)"><div class="card-h"><h2>Attack Lab ground truth</h2>${badge("DEMO / SIMULATED")}<span class="muted small">shown for evaluation only — no detector reads this</span></div>
      ${c.attack_lab_context.map((sc) => `<div class="small" style="margin-bottom:6px"><b>${esc(sc.name)}</b> — ${esc(sc.summary)}<div class="muted">expected detections: ${sc.expected.map((x) => `<span class="mono">${esc(x)}</span> ${c.finding_docs.some((f) => f.category === x) ? "✓" : "✕"}`).join(" · ")}</div></div>`).join("")}</div>` : ""}`;

  // graph
  const gbox = $("#case-graph", el);
  const types = [...new Set(c.graph.nodes.map((n) => n.type))];
  const cy = renderGraph(gbox, c.graph, {
    hideTypes: ["Sample"],
    onSelect: (n) => {
      setTrailRoot(`case:${id}`, id, closeDrawer);
      if (n.type === "Finding") return showFinding(n.id.split(":")[1]);
      showAsset(n.id, c.run_id);
    },
  });
  gbox.insertAdjacentHTML("beforeend", graphLegend(types));
  // any navigation started from this page begins the breadcrumb trail at the case
  el.addEventListener("click", (e) => {
    if (e.target.closest("[data-finding],[data-evidence],[data-asset],[data-verify],[data-f]")) setTrailRoot(`case:${id}`, id, closeDrawer);
  }, true);
  $$("[data-f]", el).forEach((card) => (card.onclick = (e) => {
    if (e.target.closest("[data-evidence]")) return;
    $$(".ev-card", el).forEach((x) => x.classList.remove("sel"));
    card.classList.add("sel");
    if (cy) {
      const n = cy.getElementById(`finding:${card.dataset.f}`);
      cy.elements().addClass("faded");
      n.closedNeighborhood().removeClass("faded");
      cy.animate({ center: { eles: n }, zoom: 1.4 }, { duration: 300 });
    }
    showFinding(card.dataset.f);
  }));
  bindFindingClicks(el);
  $$("[data-d]", el).forEach((b) => (b.onclick = () => withBusy(b, async () => {
    await post(`/api/cases/${id}/disposition`, { disposition: b.dataset.d, note: $("#disp-note", el).value });
    toast(`${id}: disposition ${b.dataset.d} recorded in the audit chain`);
    await ctx.refreshStatus();
    renderCase(el, id, ctx);
  })));
  $("#gen-report", el).onclick = (e) => withBusy(e.target, async () => {
    const r = await post("/api/reports", { case_id: id });
    toast(`${r.report_id} generated and signed`);
    window.open(`/api/reports/${r.report_id}.html`, "_blank");
  });
}
