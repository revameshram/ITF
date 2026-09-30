// Guided judge demonstration. Each step performs the same actions an analyst would do by hand,
// through the same local API. Nothing is pre-recorded; every result shown is produced live.
import { $, api, esc, post, showVerify, toast } from "./ui.js";

export const STEPS = [
  { title: "Clean system", desc: "Reset the demo and run the assurance check. Expect: TRUSTED, every pillar PASS.",
    run: async (ctx) => { await post("/api/demo/reset"); await ctx.navigate("#/"); await ctx.runAssurance(); } },
  { title: "Controlled Attack Lab", desc: "Inject the DEMO / SIMULATED scenario “Controlled Data Poisoning + Inference Tampering”.",
    run: async (ctx) => { await ctx.navigate("#/attack-lab"); await post("/api/attacklab/run/combined"); toast("Scenario injected (DEMO / SIMULATED)"); await ctx.navigate("#/attack-lab"); } },
  { title: "Re-run assurance", desc: "Run the same assurance check again. Expect: findings appear, overall UNTRUSTED.",
    run: async (ctx) => { await ctx.navigate("#/"); await ctx.runAssurance(); } },
  { title: "Evidence graph", desc: "Relationships between contributor, batch, findings, model, inference records and the case become visible.",
    run: async (ctx) => { await ctx.navigate("#/evidence"); } },
  { title: "Case", desc: "The case opened automatically. Read what we know, suspect, don't know, and what it does not prove.",
    run: async (ctx) => { const c = await latestCase(); await ctx.navigate(c ? `#/cases/${c}` : "#/cases"); document.querySelector("#case-assessment")?.scrollIntoView({ behavior: "smooth" }); } },
  { title: "Investigation", desc: "Follow the connected evidence and the timeline (observed · derived · DEMO / SIMULATED events).",
    run: async (ctx) => { const c = await latestCase(); await ctx.navigate(c ? `#/cases/${c}` : "#/cases"); document.querySelector("#case-timeline")?.scrollIntoView({ behavior: "smooth" }); } },
  { title: "Provenance verification", desc: "Re-verify the tampered inference record live. Expect: output/record-hash checks FAIL, signature still valid.",
    run: async (ctx) => {
      await ctx.navigate("#/inferences");
      const inf = await api("/api/inferences");
      const bad = inf.records.find((r) => r.failures.includes("TAMPERED_OUTPUT")) || inf.records.find((r) => r.verdict === "INVALID");
      if (bad) await showVerify(bad.record_id); else toast("No invalid record found. Run steps 2–3 first.");
    } },
  { title: "Report", desc: "Generate the signed assurance report for the case. It opens in a new tab.",
    run: async () => {
      const c = await latestCase();
      const r = await post("/api/reports", c ? { case_id: c } : {});
      toast(`${r.report_id} generated and signed`);
      window.open(`/api/reports/${r.report_id}.html`, "_blank");
    } },
];

async function latestCase() {
  const cases = await api("/api/cases");
  return cases.length ? cases[0].id : null;
}

const KEY = "aegis-demo-step";
const load = () => { try { const v = sessionStorage.getItem(KEY); return v === null ? null : +v; } catch (e) { return null; } };
const save = (v) => { try { v === null ? sessionStorage.removeItem(KEY) : sessionStorage.setItem(KEY, String(v)); } catch (e) { /* ignore */ } };

let step = null;

export function startDemo(ctx) { step = 0; save(0); renderBar(ctx); }
export function resumeDemo(ctx) { step = load(); if (step !== null) renderBar(ctx); }
export const currentStep = () => step;

function renderBar(ctx) {
  let bar = $("#demo-bar");
  if (step === null) { bar?.remove(); document.body.classList.remove("demo-on"); return; }
  if (!bar) { bar = document.createElement("div"); bar.id = "demo-bar"; bar.className = "demo-bar"; document.body.appendChild(bar); }
  document.body.classList.add("demo-on");
  const done = step >= STEPS.length;
  const s = STEPS[Math.min(step, STEPS.length - 1)];
  bar.innerHTML = `<div class="db-step">${done ? "Demo complete" : `Step ${step + 1} / ${STEPS.length}`}</div>
    <div><div class="db-title">${done ? "All eight steps shown" : esc(s.title)}</div><div class="db-desc">${done ? "Reset from the dashboard to run it again." : esc(s.desc)}</div>
      <div class="db-dots">${STEPS.map((_, i) => `<i class="${i < step ? "on" : ""}"></i>`).join("")}</div></div>
    <div class="db-actions">${step > 0 ? '<button class="btn btn-sm" data-db="back">◀ Back</button>' : ""}
      ${done ? "" : `<button class="btn btn-sm btn-primary" data-db="run">Run step ${step + 1}</button>`}
      <button class="btn btn-sm btn-ghost" data-db="exit">Exit</button></div>`;
  bar.querySelector("[data-db=exit]").onclick = () => { step = null; save(null); renderBar(ctx); };
  const back = bar.querySelector("[data-db=back]");
  if (back) back.onclick = () => { step -= 1; save(step); renderBar(ctx); };
  const run = bar.querySelector("[data-db=run]");
  if (run) run.onclick = async () => {
    run.disabled = true;
    run.innerHTML = '<span class="spin"></span> Running…';
    try { await STEPS[step].run(ctx); step += 1; save(step); } catch (e) { toast(`Step failed: ${e.message}`, 5000); }
    renderBar(ctx);
  };
}
