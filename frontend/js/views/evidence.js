// Evidence graph (latest run) + evidence register.
import { $, $$, api, bindFindingClicks, esc, graphLegend, nodeDetail, renderGraph, short } from "../ui.js";

const DEFAULT_HIDE = ["Sample", "Evidence"];

export async function render(el) {
  const [g, ev, runs] = await Promise.all([api("/api/graph"), api("/api/evidence"), api("/api/runs")]);
  const types = [...new Set(g.nodes.map((n) => n.type))].sort();
  const hide = new Set(DEFAULT_HIDE);
  const runId = runs.length ? runs[runs.length - 1].run_id : null;
  el.innerHTML = `
    <div class="page-h"><div><h1>Evidence graph</h1><p>The graph is built from real relationships in the data model: provenance metadata (contributed_by, belongs_to), registry lineage (derived_from), record bindings (produced_by), findings (affects, violates, verified_by) and explicit correlation rules (correlates_with, each with its reason). Attack Lab ground truth appears as dotted purple edges and is never used by a detector.</p></div></div>
    ${g.nodes.length ? `<div class="grid" style="grid-template-columns:minmax(0,1fr) 340px">
      <div><div class="row" style="margin-bottom:8px"><span class="muted small">${esc(runId || "")} · ${g.nodes.length} nodes · ${g.edges.length} edges · show:</span>
        ${types.map((t) => `<label class="small" style="display:inline-flex;gap:4px;align-items:center"><input type="checkbox" data-t="${esc(t)}" ${hide.has(t) ? "" : "checked"}>${esc(t)}</label>`).join("")}</div>
        <div class="graph-box" id="g" style="height:640px"></div></div>
      <div class="panel-detail" id="gd" style="max-height:680px"><h2>Select a node</h2><p class="muted">Click any node to see its properties and relationships. Red edges are evidence correlations. Dashed amber edges are context-only links (same pipeline, no causal evidence).</p></div>
    </div>
    <div class="card section"><div class="card-h"><h2>Evidence register</h2><span class="muted small">each item is hashed (SHA-256) when created</span></div>
      <table class="tbl"><tr><th>ID</th><th>Finding</th><th>Kind</th><th>Title</th><th>Summary</th><th>SHA-256</th></tr>
      ${ev.map((e) => `<tr class="click" data-evidence="${esc(e.id)}"><td class="mono" style="color:var(--accent)">${esc(e.id)}</td><td class="mono">${esc(e.finding_id)}</td><td>${esc(e.kind)}</td><td>${esc(e.title)}</td><td class="small muted">${esc(e.summary)}</td><td class="hash">${short(e.sha256, 12)}</td></tr>`).join("")}</table></div>`
      : `<div class="empty">No graph yet. Run the assurance check.</div>`}`;
  if (!g.nodes.length) return;
  const draw = () => {
    renderGraph($("#g", el), g, {
      hideTypes: [...hide],
      onSelect: (n, edges) => { $("#gd", el).innerHTML = nodeDetail(n, edges); bindFindingClicks($("#gd", el)); },
    });
    $("#g", el).insertAdjacentHTML("beforeend", graphLegend(types.filter((t) => !hide.has(t))));
  };
  $$("[data-t]", el).forEach((cb) => (cb.onchange = () => { cb.checked ? hide.delete(cb.dataset.t) : hide.add(cb.dataset.t); draw(); }));
  draw();
}
