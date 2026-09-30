// Coverage / limitations: what is real, heuristic, demo, or not implemented.
import { api, badge, esc, method, pillarName } from "../ui.js";

export async function render(el) {
  const c = await api("/api/coverage");
  const count = (s) => c.capabilities.filter((x) => x.status === s).length;
  const groups = [...new Set(c.capabilities.map((x) => x.pillar))];
  el.innerHTML = `
    <div class="page-h"><div><h1>Coverage &amp; limitations</h1><p>An assurance tool has to be clear about its own limits. This page lists every capability with its implementation status, the attack classes we can and cannot detect, and the assumptions behind the results.</p></div></div>
    <div class="grid g4">
      <div class="card"><div class="muted small">Real implementation</div><h1 style="margin-top:4px;color:var(--pass)">${count("REAL")}</h1><div class="small muted">deterministic, cryptographic or exact</div></div>
      <div class="card"><div class="muted small">Heuristic</div><h1 style="margin-top:4px;color:var(--warn)">${count("HEURISTIC")}</h1><div class="small muted">real computation, uncalibrated conclusion</div></div>
      <div class="card"><div class="muted small">Demo / simulated</div><h1 style="margin-top:4px;color:var(--demo)">${count("DEMO / SIMULATED")}</h1><div class="small muted">clearly labelled wherever shown</div></div>
      <div class="card"><div class="muted small">Not supported</div><h1 style="margin-top:4px;color:var(--muted)">${count("NOT SUPPORTED")}</h1><div class="small muted">not implemented in this prototype</div></div>
    </div>
    <div class="section"><h3 style="margin-bottom:8px">Status by area</h3><div class="pill-sum">${c.pillar_summary.map((x) => `<div><div class="ps-a">${esc(x.area)}</div>${badge(x.status)}<div class="small muted" style="margin-top:6px">${esc(x.notes)}</div></div>`).join("")}</div></div>
    <div class="card section"><table class="tbl"><tr><th>Area</th><th>Capability</th><th>Status</th><th>Notes</th></tr>
      ${groups.map((g) => c.capabilities.filter((x) => x.pillar === g).map((x, i) => `<tr><td>${i === 0 ? `<b>${esc(pillarName(g))}</b>` : ""}</td><td>${esc(x.capability)}</td><td>${method(x.status)}</td><td class="small muted">${esc(x.notes)}</td></tr>`).join("")).join("")}</table></div>
    <div class="grid g2 section">
      <div class="card"><div class="card-h"><h2>Supported attack classes</h2></div><ul>${c.supported_attack_classes.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>
      <div class="card"><div class="card-h"><h2>Not detected (out of scope)</h2></div><ul>${c.unsupported_attack_classes.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>
      <div class="card"><div class="card-h"><h2>Assumptions</h2></div><ul>${c.assumptions.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>
      <div class="card"><div class="card-h"><h2>Limitations</h2></div><ul>${c.limitations.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
        <h3 style="margin:10px 0 6px">Model runtimes on this machine</h3>${c.formats.map((f) => `<div class="small">${esc(f.format)}: ${f.available ? "available" : "not available"} <span class="muted">(${esc(f.runtime)})</span></div>`).join("")}</div>
    </div>`;
}
