/**
 * agent-firewall.ts — Agent Policy Firewall cockpit (/agent-firewall).
 * KPIs + the signed-receipt-chain integrity badge, a "test the gate" simulator (POST /evaluate), the
 * policy list (+ add/delete), and the action ledger with verdicts, blast-radius, replay/SoD flags and
 * pending-approval controls. All from /api/agent-firewall*.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function postJSON(u: string, b?: any): Promise<any> { const r = await fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return r.json().catch(() => ({})); }
async function delJSON(u: string): Promise<any> { const r = await fetch(u, { method: "DELETE", credentials: "same-origin" }); return r.json().catch(() => ({})); }

const blastColor = (n: number): string => (n >= 80 ? "#ef4444" : n >= 60 ? "#fb923c" : n >= 35 ? "#fbbf24" : "#22c55e");
let REF: any = { actionTypes: [], decisions: [], sensitivity: [] };
const opts = (arr: string[], sel?: string): string => arr.map((o) => `<option${sel === o ? " selected" : ""}>${esc(o)}</option>`).join("");
function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="af-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}

async function load(): Promise<void> {
  let d: any;
  try { d = await getJSON("/api/agent-firewall"); } catch (e) { $("af-body").innerHTML = `<div class="muted" style="padding:20px">Failed to load: ${esc(String(e))}</div>`; return; }
  REF = d; const s = d.summary || {}; const rc = d.receipts || { ok: true, total: 0, verified: 0 };
  if (!d.policies.length && !s.actions) {
    $("af-body").innerHTML = `<div class="frm"><div class="muted" style="margin-bottom:8px">No policies yet. Seed the default firewall policy set + sample actions to begin.</div><button class="btn" id="seed">Seed firewall</button></div>`;
    $("seed").onclick = async () => { await postJSON("/api/agent-firewall/seed"); load(); };
    return;
  }
  const cards = [
    card("Actions governed", String(s.actions ?? 0), "evaluated by the gate"),
    card("Allowed", String(s.allowed ?? 0), "auto + approved", "#22c55e"),
    card("Denied", String(s.denied ?? 0), "blocked before running", (s.denied ? "#f87171" : "#94a3b8")),
    card("Pending approval", String(s.pending ?? 0), "awaiting a human", (s.pending ? "#fbbf24" : "#94a3b8")),
    card("Avg blast radius", String(s.avgBlast ?? 0), "0–100", blastColor(s.avgBlast ?? 0)),
    card("Replay blocked", String(s.replayBlocked ?? 0), "duplicate actions", (s.replayBlocked ? "#fb923c" : "#94a3b8")),
    card("SoD violations", String(s.sodViolations ?? 0), "self-approval attempts", (s.sodViolations ? "#f87171" : "#94a3b8")),
    card("Receipt chain", rc.ok ? "✓ intact" : "✗ broken", `${rc.verified}/${rc.total} signed`, rc.ok ? "#22c55e" : "#f87171"),
  ].join("");

  $("af-body").innerHTML = `
    <div class="af-cards">${cards}</div>

    <div class="af-sec">Test the gate</div>
    <div class="frm">
      <div class="grid">
        <div><label>Action type</label><select class="in" id="t-type">${opts(REF.actionTypes)}</select></div>
        <div><label>Actor (agent)</label><input class="in" id="t-actor" placeholder="remediation-agent"></div>
        <div><label>Sensitivity</label><select class="in" id="t-sens">${opts(REF.sensitivity, "medium")}</select></div>
        <div style="grid-column:span 2"><label>Target</label><input class="in" id="t-target" placeholder="isolate prod database host"></div>
        <div style="grid-column:span 2"><label>Params (optional)</label><input class="in" id="t-params" placeholder="shutdown all sessions"></div>
      </div>
      <button class="btn" id="t-eval">&#9889; Evaluate action</button>
      <div id="t-out"></div>
    </div>

    <div class="af-sec">Policies</div>
    <div id="af-policies"></div>

    <div class="af-sec">Action ledger <span class="muted" style="font-weight:400;text-transform:none">— signed, tamper-evident</span></div>
    <div id="af-ledger" style="overflow-x:auto"></div>`;

  renderPolicies(d.policies);
  renderLedger(d.actions);
  $("t-eval").onclick = evalAction;
}

function renderPolicies(pols: any[]): void {
  const rows = pols.map((p) => `<tr>
    <td><b>${esc(p.name)}</b></td>
    <td><span class="tag">${esc(p.actionType || "*")}</span></td>
    <td>${esc(p.targetPattern || "—")}</td>
    <td>≥ ${p.minBlastRadius}</td>
    <td class="d-${p.decision === "deny" ? "denied" : p.decision === "approve" ? "pending" : "allowed"}">${esc(p.decision)}${p.decision === "approve" ? ` (${p.requireApprovers})` : ""}</td>
    <td>${p.enabled ? "✓" : "<span class='muted'>off</span>"}</td>
    <td><span class="xdel" data-delpol="${p.id}">✕</span></td></tr>`).join("") || `<tr><td colspan="7" class="muted">No policies.</td></tr>`;
  $("af-policies").innerHTML = `<table class="tt"><thead><tr><th>Policy</th><th>Action type</th><th>Target pattern</th><th>Min blast</th><th>Decision</th><th>On</th><th></th></tr></thead><tbody>${rows}</tbody></table>
    <div class="frm" style="margin-top:8px">
      <div class="grid">
        <div style="grid-column:span 2"><label>Name</label><input class="in" id="p-name" placeholder="Approve high-blast cloud actions"></div>
        <div><label>Action type</label><select class="in" id="p-type"><option value="*">* any</option>${opts(REF.actionTypes)}</select></div>
        <div><label>Target pattern</label><input class="in" id="p-target" placeholder="prod"></div>
        <div><label>Min blast radius</label><input class="in" id="p-blast" type="number" min="0" max="100" value="0"></div>
        <div><label>Decision</label><select class="in" id="p-dec">${opts(REF.decisions)}</select></div>
        <div><label>Approvers (if approve)</label><input class="in" id="p-appr" type="number" min="0" value="1"></div>
      </div>
      <button class="btn sm" id="p-add">+ Add policy</button>
    </div>`;
  document.querySelectorAll("[data-delpol]").forEach((el) => { (el as HTMLElement).onclick = async () => { await delJSON(`/api/agent-firewall/policy/${(el as HTMLElement).dataset.delpol}`); load(); }; });
  $("p-add").onclick = async () => {
    const name = ($("p-name") as HTMLInputElement).value.trim(); if (!name) return;
    await postJSON("/api/agent-firewall/policy", { name, actionType: ($("p-type") as HTMLSelectElement).value, targetPattern: ($("p-target") as HTMLInputElement).value, minBlastRadius: Number(($("p-blast") as HTMLInputElement).value), decision: ($("p-dec") as HTMLSelectElement).value, requireApprovers: Number(($("p-appr") as HTMLInputElement).value) });
    load();
  };
}

function renderLedger(acts: any[]): void {
  const rows = acts.map((a) => `<tr>
    <td><span class="tag">${esc(a.actionType)}</span></td>
    <td>${esc(a.target)}${a.policy ? `<div class="muted" style="font-size:10px">${esc(a.policy)}</div>` : ""}</td>
    <td>${esc(a.actor)}</td>
    <td><span class="blast" style="color:${blastColor(a.blastRadius)}">${a.blastRadius}<span class="blastbar"><i style="width:${a.blastRadius}%;background:${blastColor(a.blastRadius)}"></i></span></span></td>
    <td class="d-${esc(a.status)}">${esc(a.status)}${a.replay ? `<span class="flag">replay</span>` : ""}${a.sod ? `<span class="flag">SoD</span>` : ""}</td>
    <td class="muted" style="font-family:ui-monospace,monospace;font-size:10px">${esc(a.receipt)}…</td>
    <td>${a.status === "pending" ? `<button class="btn sm" data-appr="${a.id}">approve</button> <button class="btn danger sm" data-deny="${a.id}">deny</button>` : (a.approvedBy ? `<span class="muted" style="font-size:10px">✓ ${esc(a.approvedBy)}</span>` : "")}</td>
  </tr>`).join("") || `<tr><td colspan="7" class="muted">No actions evaluated yet — use “Test the gate”.</td></tr>`;
  $("af-ledger").innerHTML = `<table class="tt"><thead><tr><th>Type</th><th>Target</th><th>Actor</th><th>Blast</th><th>Verdict</th><th>Receipt</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  document.querySelectorAll("[data-appr]").forEach((el) => { (el as HTMLElement).onclick = async () => { const r = await postJSON(`/api/agent-firewall/action/${(el as HTMLElement).dataset.appr}/approve`); if (r && r.error) alert(r.error); load(); }; });
  document.querySelectorAll("[data-deny]").forEach((el) => { (el as HTMLElement).onclick = async () => { await postJSON(`/api/agent-firewall/action/${(el as HTMLElement).dataset.deny}/deny`); load(); }; });
}

async function evalAction(): Promise<void> {
  const target = ($("t-target") as HTMLInputElement).value.trim(); if (!target) { ($("t-target") as HTMLInputElement).focus(); return; }
  const out = await postJSON("/api/agent-firewall/evaluate", {
    actionType: ($("t-type") as HTMLSelectElement).value, actor: ($("t-actor") as HTMLInputElement).value || undefined,
    sensitivity: ($("t-sens") as HTMLSelectElement).value, target, params: ($("t-params") as HTMLInputElement).value || undefined,
  });
  const color = out.status === "denied" ? "#f87171" : out.status === "pending" ? "#fbbf24" : "#22c55e";
  $("t-out").innerHTML = `<div class="verdict"><b style="color:${color}">${esc((out.status || "").toUpperCase())}</b> · blast radius <b style="color:${blastColor(out.blastRadius)}">${out.blastRadius}</b>${out.replay ? ` · <span class="flag">replay blocked</span>` : ""}
    \n${esc(out.rationale || "")}
    \nSigned receipt: ${esc(String(out.receipt || "").slice(0, 24))}…</div>`;
  load();
}

document.addEventListener("DOMContentLoaded", load);
