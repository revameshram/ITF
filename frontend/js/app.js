// AegisVision SPA shell: navigation, routing, global status and the "Run assurance" action.
import { $, api, badge, esc, icons, post, toast, tone, withBusy, closeDrawer } from "./ui.js";
import * as dashboard from "./views/dashboard.js";
import * as datasets from "./views/datasets.js";
import * as models from "./views/models.js";
import * as inferences from "./views/inferences.js";
import * as distribution from "./views/distribution.js";
import * as cases from "./views/cases.js";
import * as evidence from "./views/evidence.js";
import * as attacklab from "./views/attacklab.js";
import * as audit from "./views/audit.js";
import * as reports from "./views/reports.js";
import * as coverage from "./views/coverage.js";

const NAV = [
  ["Overview", [["", "Dashboard", "dashboard", dashboard]]],
  ["Pipeline", [["datasets", "Datasets", "datasets", datasets], ["models", "Models", "models", models],
                ["inferences", "Inferences", "inferences", inferences], ["distribution", "Distribution", "distribution", distribution]]],
  ["Investigation", [["cases", "Cases", "cases", cases], ["evidence", "Evidence", "evidence", evidence],
                     ["audit", "Audit Log", "audit", audit], ["reports", "Assurance Reports", "reports", reports]]],
  ["Controlled testing", [["attack-lab", "Attack Lab", "attack", attacklab]]],
  ["Honesty", [["coverage", "Coverage / Limitations", "coverage", coverage]]],
];
const ROUTES = Object.fromEntries(NAV.flatMap(([, items]) => items.map(([r, label, , mod]) => [r, { label, mod }])));

function renderNav(active, caseCount) {
  $("#nav").innerHTML = NAV.map(([group, items]) => `<div class="nav-group">${group}</div>` + items.map(([r, label, icon]) =>
    `<a class="nav-item ${r === active ? "active" : ""}" href="#/${r}">${icons[icon]}<span>${label}</span>${r === "cases" && caseCount ? `<span class="count">${caseCount}</span>` : ""}</a>`).join("")).join("");
}

export const ctx = {
  async refreshStatus() {
    try {
      const [s, cs] = await Promise.all([api("/api/status"), api("/api/cases")]);
      const o = $("#overall");
      o.textContent = `SYSTEM STATUS: ${s.overall}`;
      o.className = `overall b-${tone(s.overall)}`;
      o.style.borderColor = "";
      $("#signer").innerHTML = `signer <span class="mono">${esc(s.signer.key_id)}</span> · Ed25519`;
      const open = cs.filter((c) => !c.disposition || c.disposition === "REVIEW").length;
      ctx._cases = open;
      renderNav(ctx._route, open);
      if (!s.network.guard_installed) $("#airgap").style.opacity = .4;
    } catch (e) { console.error(e); }
  },
  go(hash) { location.hash = hash; },
  rerender() { route(); },
};

async function route() {
  closeDrawer();
  const hash = location.hash.replace(/^#\/?/, "");
  const [head, ...rest] = hash.split("/");
  const r = ROUTES[head] ? head : "";
  ctx._route = r;
  renderNav(r, ctx._cases);
  $("#crumbs").innerHTML = `AegisVision / <b>${esc(ROUTES[r].label)}</b>${rest.length ? ` / <b>${esc(rest.join("/"))}</b>` : ""}`;
  const view = $("#view");
  view.innerHTML = `<div class="muted" style="padding:30px">Loading…</div>`;
  try {
    await ROUTES[r].mod.render(view, rest, ctx);
  } catch (e) {
    console.error(e);
    view.innerHTML = `<div class="note fail">Could not render this view: ${esc(e.message)}</div>`;
  }
  window.scrollTo(0, 0);
}

export async function runAssurance(btn) {
  const b = btn || $("#run-btn");
  return withBusy(b, async () => {
    const r = await post("/api/assurance/run");
    toast(`${r.run_id}: ${r.overall}${r.case_id ? ` — ${r.case_id} created` : ""} (${r.seconds}s)`, 4000);
    await ctx.refreshStatus();
    route();
    return r;
  });
}
ctx.runAssurance = runAssurance;

$("#run-btn").onclick = () => runAssurance();

function syncThemeButton() {
  const light = document.documentElement.getAttribute("data-theme") === "light";
  const label = light ? "Switch to dark mode" : "Switch to light mode";
  $("#theme-btn").setAttribute("aria-label", label);
  $("#theme-btn").title = label;
}
$("#theme-btn").onclick = () => {
  const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem("aegis-theme", next); } catch (e) { /* storage unavailable: theme lasts this visit only */ }
  syncThemeButton();
  const y = window.scrollY;
  Promise.resolve(route()).then(() => window.scrollTo(0, y));  // re-draw graphs with the new palette
};
syncThemeButton();
$("#airgap").onclick = async () => {
  const r = await post("/api/system/netcheck");
  toast(r.blocked ? `Egress test: outbound connection BLOCKED ✓ (${r.status.blocked_count} blocked so far)` : `Egress test: ${r.detail}`, 4500);
};
window.addEventListener("hashchange", route);
ctx.refreshStatus().then(route);
export { badge };
