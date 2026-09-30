// Tamper-evident audit log view.
import { api, badge, esc, post, short, withBusy } from "../ui.js";

export async function render(el) {
  const [recs, v] = await Promise.all([api("/api/audit"), post("/api/audit/verify")]);
  const broken = new Set(v.problems.map((p) => p.seq));
  el.innerHTML = `
    <div class="page-h"><div><h1>Audit log</h1><p>Every action is appended to a SHA-256 hash chain: each record stores the hash of the previous one, and the chain head is signed with Ed25519. Editing, deleting or reordering any historical record breaks verification from that point.</p></div>
      <span class="spacer"></span><button class="btn btn-primary" id="verify">Verify chain now</button></div>
    <div class="grid g4">
      <div class="card"><div class="muted small">Chain status</div><h1 style="margin-top:4px;color:${v.valid ? "var(--pass)" : "var(--fail)"}">${v.valid ? "INTACT" : "BROKEN"}</h1><div class="small muted">${v.valid ? "all links and hashes verify" : `first break at #${v.first_break_seq}`}</div></div>
      <div class="card"><div class="muted small">Records</div><h1 style="margin-top:4px">${v.records}</h1></div>
      <div class="card"><div class="muted small">Signed head</div><div style="margin-top:6px">${badge(v.head_signature_valid ? "VALID" : v.head_signature_valid === false ? "INVALID" : "—")}</div><div class="hash" style="margin-top:4px">${esc(short(v.head_hash, 28))}</div></div>
      <div class="card"><div class="muted small">Method</div><div class="small" style="margin-top:6px">${esc(v.method)}</div></div>
    </div>
    ${v.problems.length ? `<div class="note fail section"><b>Integrity problems:</b><ul style="margin:4px 0 0">${v.problems.map((p) => `<li>#${p.seq} <span class="mono">${esc(p.problem)}</span> — ${esc(p.detail)}</li>`).join("")}</ul></div>` : ""}
    <div class="card section"><div class="tbl-wrap"><table class="tbl"><tr><th>#</th><th>Time (UTC)</th><th>Event</th><th>Actor</th><th>Asset</th><th>Details</th><th>prev_hash</th><th>hash</th></tr>
      ${[...recs].reverse().map((r) => `<tr class="${broken.has(r.seq) ? "bad" : ""}"><td class="mono">${r.seq}</td><td class="mono small">${esc(r.ts.slice(11, 23))}</td><td class="mono small">${esc(r.event_type)}</td><td class="small">${esc(r.actor)}</td><td class="small">${esc(r.asset || "")}</td>
        <td class="small muted" style="max-width:340px">${esc(JSON.stringify(r.details).slice(0, 150))}</td><td class="hash">${esc(r.prev_hash.slice(0, 10))}</td><td class="hash">${esc(r.hash.slice(0, 10))}</td></tr>`).join("")}</table></div></div>`;
  el.querySelector("#verify").onclick = (e) => withBusy(e.target, async () => render(el));
}
