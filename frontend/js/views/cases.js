// Cases list + forensic investigation view.
import { $, $$, api, badge, bindFindingClicks, esc, graphLegend, method, nodeDetail, openDrawer, pillarName, post, renderGraph, sev, showFinding, timeline, toast, withBusy } from "../ui.js";

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
  return `<div class="chain"><div class="row"><b>${esc(ch.chain_id)}</b><span class="b b-neutral">${esc(ch.pillars.map(pillarName).join(" + "))}</span>${ch.strength === "strong" ? '<span class="b b-fail">corroborated</span>' : '<span class="b b-neutral">single finding</span>'}</div>
    <div class="chain-flow">${steps.join('<span class="arrow">→</span>')}</div><div class="muted small" style="margin-top:6px">${esc(ch.narrative)}</div></div>`;
}

async function renderCase(el, id, ctx) {
  const c = await api(`/api/cases/${id}`);
  const fmap = Object.fromEntries(c.finding_docs.map((f) => [f.id, f]));
  const main = c.finding_docs.filter((f) => f.severity !== "INFO").sort((a, b) => PILLAR_ORDER.indexOf(a.pillar) - PILLAR_ORDER.indexOf(b.pillar));
  const evFor = (f) => f.evidence.join(", ");
  const s = c.summary;
  el.innerHTML = `
    <div class="inv-head">
      <div style="flex:1;min-width:260px"><div class="case-id">${esc(c.id)} · INVESTIGATION · ${esc(c.run_id)}</div><div class="case-title">${esc(c.title)}</div>
        <div class="muted small" style="margin-top:4px">opened ${esc(c.created_at.slice(0, 19).replace("T", " "))} UTC · ${c.findings.length} findings · ${c.evidence.length} evidence items</div></div>
      <div class="inv-stat"><span class="l">Status</span><span class="v">${badge(c.status)}</span></div>
      <div class="inv-stat"><span class="l">Severity</span><span class="v">${sev(c.severity)}${c.severity_escalated ? ' <span class="muted tiny" title="escalated: one corroborated chain spans ≥3 pillars">▲</span>' : ""}</span></div>
      <div class="inv-stat"><span class="l">Aggregated risk</span><span class="v" title="${esc(c.risk_method)}">${Number(c.risk_score).toFixed(2)}</span></div>
      <div class="inv-stat"><span class="l">Recommended</span><span class="v">${badge(c.recommended_disposition)}</span></div>
      <div class="inv-stat"><span class="l">Analyst decision</span><span class="v">${c.disposition ? badge(c.disposition) : '<span class="muted">pending</span>'}</span></div>
    </div>
    <div class="inv-grid">
      <div class="card" style="padding:12px"><div class="card-h"><h2>Evidence</h2><span class="spacer"></span><span class="muted tiny">click to inspect</span></div>
        <div class="grid" style="gap:8px">${main.map((f) => `<div class="ev-card" data-f="${esc(f.id)}">
          <div class="row"><span class="ev-id">${esc(evFor(f))}</span><span class="spacer"></span>${method(f.method_status)}</div>
          <div class="ev-t">${esc(f.title)}</div>
          <div class="row small" style="margin-bottom:4px"><span class="muted">${esc(f.id)} · ${esc(pillarName(f.pillar))}</span><span class="spacer"></span>${sev(f.severity)}</div>
          <div class="conf"><span>confidence</span><div class="bar ${f.confidence >= .8 ? "fail" : f.confidence >= .5 ? "warn" : ""}"><i style="width:${f.confidence * 100}%"></i></div><b>${Number(f.confidence).toFixed(2)}</b></div></div>`).join("")}</div>
        ${c.informational_findings.length ? `<div class="muted tiny" style="margin-top:8px">+ ${c.informational_findings.length} informational finding(s) not counted in the risk score</div>` : ""}
      </div>
      <div style="display:grid;gap:14px;min-width:0">
        <div class="graph-box" id="case-graph"></div>
        <div class="card"><div class="card-h"><h2>How the evidence is connected</h2></div><div class="grid" style="gap:8px">${c.chains.map((ch) => chainFlow(ch, fmap)).join("")}</div></div>
      </div>
      <div style="display:grid;gap:14px;align-content:start">
        <div class="card"><div class="card-h"><h2>Disposition</h2></div>
          <div class="muted small" style="margin-bottom:8px">Recommended: <b>${esc(c.recommended_disposition)}</b> — ${esc(c.recommendation_reasons.join("; "))}</div>
          <textarea class="input" id="disp-note" rows="2" placeholder="Analyst note (recorded in the audit chain)"></textarea>
          <div class="disp" style="margin-top:8px"><button class="btn btn-ok" data-d="ACCEPT">Accept</button><button class="btn btn-warn" data-d="REVIEW">Review</button><button class="btn btn-danger" data-d="QUARANTINE">Quarantine</button><span class="spacer"></span><button class="btn btn-primary" id="gen-report">Generate report</button></div>
          ${c.disposition_history.length ? `<div style="margin-top:10px">${c.disposition_history.map((h) => `<div class="small"><span class="mono muted">${esc(h.ts.slice(11, 19))}</span> ${badge(h.disposition)} by ${esc(h.actor)} <span class="muted">audit #${h.audit_seq}</span>${h.note ? `<div class="muted">“${esc(h.note)}”</div>` : ""}</div>`).join("")}</div>` : ""}
        </div>
        <div class="card"><div class="card-h"><h2>Timeline</h2><span class="spacer"></span><span class="muted tiny">from the audit chain</span></div><div style="max-height:440px;overflow-y:auto">${timeline(c.timeline)}</div></div>
      </div>
    </div>
    <div class="grid g3 section qa">
      <div class="card"><h4>What happened?</h4><div>${esc(s.what_happened)}</div></div>
      <div class="card"><h4>Where did it happen?</h4><div class="row">${s.where.map((w) => `<span class="b b-neutral">${esc(w)}</span>`).join("")}</div></div>
      <div class="card"><h4>What evidence do we have?</h4><ul>${c.evidence_docs.map((e) => `<li><a href="#" data-evidence="${esc(e.id)}">${esc(e.id)}</a> ${esc(e.title)} <span class="muted small">(${esc(e.kind)})</span></li>`).join("")}</ul></div>
      <div class="card"><h4>How confident are we?</h4><ul>${Object.entries(s.confidence).map(([fid, x]) => `<li><b>${esc(fid)}</b> ${Number(x.confidence).toFixed(2)} ${method(x.method_status)}<div class="muted small">${esc(x.basis)}</div></li>`).join("")}</ul></div>
      <div class="card"><h4>What is still unknown?</h4><ul>${s.unknowns.map((u) => `<li>${esc(u)}</li>`).join("")}</ul></div>
      <div class="card"><h4>What should we do next?</h4><ol style="margin:0;padding-left:18px">${s.next_steps.map((n) => `<li>${esc(n)}</li>`).join("")}</ol></div>
    </div>
    ${c.attack_lab_context?.length ? `<div class="card section" style="border-color:rgba(157,140,240,.35)"><div class="card-h"><h2>Attack Lab ground truth</h2>${badge("DEMO / SIMULATED")}<span class="muted small">shown for evaluation only — no detector reads this</span></div>
      ${c.attack_lab_context.map((sc) => `<div class="small" style="margin-bottom:6px"><b>${esc(sc.name)}</b> — ${esc(sc.summary)}<div class="muted">expected detections: ${sc.expected.map((x) => `<span class="mono">${esc(x)}</span> ${c.finding_docs.some((f) => f.category === x) ? "✓" : "✕"}`).join(" · ")}</div></div>`).join("")}</div>` : ""}`;

  // graph
  const gbox = $("#case-graph", el);
  const types = [...new Set(c.graph.nodes.map((n) => n.type))];
  const cy = renderGraph(gbox, c.graph, {
    hideTypes: ["Sample"],
    onSelect: (n, edges) => {
      if (n.type === "Finding") return showFinding(n.id.split(":")[1]);
      openDrawer(nodeDetail(n, edges));
    },
  });
  gbox.insertAdjacentHTML("beforeend", graphLegend(types));
  $$("[data-f]", el).forEach((card) => (card.onclick = () => {
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
