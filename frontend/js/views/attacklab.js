// Attack Lab: controlled, local, synthetic integrity-failure scenarios.
import { $$, api, badge, esc, post, toast, withBusy } from "../ui.js";

export async function render(el, _p, ctx) {
  const [sc, dash, run] = await Promise.all([api("/api/attacklab/scenarios"), api("/api/dashboard"), api("/api/runs/latest/full")]);
  const pending = dash.pending_scenarios;
  const featured = sc.find((s) => s.featured);
  const rest = sc.filter((s) => !s.featured);
  const card = (s) => `<div class="scen ${s.featured ? "featured" : ""}">
      <div class="row"><span class="s-name">${esc(s.name)}</span><span class="spacer"></span><span class="b b-neutral">${esc(s.pillar)}</span></div>
      <div class="small">${esc(s.description)}</div>
      <div class="s-exp">A correct audit should raise: ${s.expected.map((x) => `<span class="mono">${esc(x)}</span>`).join(", ")}</div>
      <div class="row" style="margin-top:4px"><button class="btn ${s.featured ? "btn-danger" : "btn-sm"}" data-sc="${esc(s.id)}">Inject scenario</button>${pending.some((p) => p.id === s.id) ? badge("INJECTED — PENDING AUDIT", "b-demo") : ""}</div></div>`;
  el.innerHTML = `
    <div class="page-h"><div><h1>Attack Lab</h1><p>A controlled test environment. Each scenario injects a known integrity failure into the local, synthetic demo pipeline. Then you run the assurance check and see whether it is detected: clean → audit → trusted → inject → audit → detect → evidence → case → report.</p></div>
      <span class="spacer"></span><button class="btn" id="reset">Reset to clean pipeline</button></div>
    <div class="lab-banner">${badge("DEMO / SIMULATED")}<div>All scenarios modify only the local workspace copy of the synthetic dataset, models and inference log on this machine. No network access, no real systems, no real data. The ground truth of each injection is kept separately and never read by any detector.</div></div>
    ${pending.length ? `<div class="note demo" style="margin-bottom:14px"><b>${pending.length} scenario(s) injected since the last assurance check:</b> ${pending.map((p) => esc(p.name)).join(", ")}.
      <button class="btn btn-sm btn-primary" id="run-now" style="margin-left:8px">Run assurance check now</button></div>` : ""}
    <div class="grid g3">${card(featured)}${rest.map(card).join("")}</div>
    <div class="card section" id="selftest"><div class="card-h"><h2>Provenance &amp; audit-chain self-test</h2><span class="b b-real">REAL</span>
      <span class="muted small">expected vs actual verification · isolated copies, the live log is never modified</span><span class="spacer"></span>
      <button class="btn btn-primary" id="run-selftest">Run self-test</button></div>
      <div class="muted small">For each test, five records are freshly signed with the real local key and exactly one thing is changed. The unchanged production verifier is then run on them.</div>
      <div id="selftest-out" style="margin-top:10px"></div></div>
    ${run?.scenarios?.length ? `<div class="card section"><div class="card-h"><h2>Scorecard of the last assurance run</h2><span class="muted small">${esc(run.run_id)} · ground truth vs detections</span></div>
      <table class="tbl"><tr><th>Scenario</th><th>Expected finding</th><th>Detected</th></tr>
      ${dash.scorecard.flatMap((s) => s.expected.map((x, i) => `<tr><td>${i === 0 ? `<b>${esc(s.scenario)}</b>` : ""}</td><td class="mono">${esc(x.category)}</td><td>${x.detected ? badge("PASS") + " detected" : badge("FAIL") + " missed"}</td></tr>`)).join("")}</table>
      <div class="row" style="margin-top:10px">${run.case_id ? `<a class="btn btn-primary" href="#/cases/${esc(run.case_id)}">Open ${esc(run.case_id)} →</a>` : ""}</div></div>` : ""}`;
  $$("[data-sc]", el).forEach((b) => (b.onclick = () => withBusy(b, async () => {
    const r = await post(`/api/attacklab/run/${b.dataset.sc}`);
    toast(`Injected: ${r.name}. Now run the assurance check.`, 4000);
    ctx.rerender();
  })));
  el.querySelector("#run-selftest").onclick = (e) => withBusy(e.target, async () => {
    const r = await post("/api/provenance/selftest");
    el.querySelector("#selftest-out").innerHTML = `
      <div class="note ${r.summary.all_as_expected ? "" : "fail"}" style="margin-bottom:10px">${r.summary.as_expected} of ${r.summary.tests} tests behaved as expected. ${esc(r.scope)}</div>
      <div class="tbl-wrap"><table class="tbl"><tr><th>Test</th><th>Modification applied</th><th>Expected</th><th>Actual</th><th>Status</th><th>Checks that failed</th></tr>
      ${r.results.map((t) => `<tr class="${["MISSED", "FALSE ALARM"].includes(t.status) ? "bad" : ""}"><td><b>${esc(t.test)}</b></td><td class="small">${esc(t.mutation)}</td>
        <td>${badge(t.expected)}</td><td>${badge(t.actual)}</td><td><span class="b ${t.status === "DETECTED" || t.status === "OK" ? "b-pass" : "b-fail"}">${esc(t.status)}</span></td>
        <td class="mono small">${esc(t.failed_checks.join(", ") || "—")}</td></tr>`).join("")}</table></div>
      <div class="note warn" style="margin-top:10px"><b>What a detected change does NOT prove:</b> ${r.does_not_prove.map(esc).join("; ")}.</div>`;
  });
  const rn = el.querySelector("#run-now");
  if (rn) rn.onclick = async () => { const r = await ctx.runAssurance(rn); if (r?.case_id) location.hash = `#/cases/${r.case_id}`; };
  el.querySelector("#reset").onclick = (e) => withBusy(e.target, async () => {
    await post("/api/demo/reset");
    toast("Clean demo pipeline restored (workspace, registry, inference log and audit chain reset)");
    await ctx.refreshStatus();
    ctx.rerender();
  });
}
