/** soar.ts — SOAR cockpit (/soar). Orchestration playbooks (trigger→actions) + action catalogue +
 *  simulate/live run engine + run history. Reads /api/soar. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2800); }

interface Action { id: number; order: number; type: string; name: string; params: string; onFailure: string }
interface Playbook { id: number; name: string; description: string; trigger: string; category: string; enabled: boolean; runCount: number; lastRunAt: string | null; actions: Action[] }
interface Run { id: number; playbookId: number; playbookName: string; mode: string; status: string; steps: number; startedAt: string; summary: string }
interface Data {
  summary: { playbooks: number; enabled: number; actions: number; triggersCovered: number; triggersTotal: number; runs: number; successRuns: number; successRate: number | null; webhookTargets: number; externalConfigured: boolean };
  playbooks: Playbook[]; runs: Run[]; worklist: { label: string; severity: string }[];
  triggers: { id: string; label: string; severity: string }[]; actionCatalogue: { id: string; label: string }[]; webhooks: any[];
}
let DATA: Data | null = null;

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const statusPill = (s: string): string => `<span class="pill ${s === "success" ? "p-ok" : s === "partial" ? "p-warn" : s === "failed" ? "p-bad" : "p-off"}">${esc(s)}</span>`;

function pbHtml(p: Playbook): string {
  const trig = DATA!.triggers.find((t) => t.id === p.trigger)?.label || p.trigger;
  const steps = p.actions.length
    ? p.actions.map((a) => `<div class="step"><span class="stepn">${a.order}</span><span class="atype">${esc(a.type)}</span> <span>${esc(a.name)}</span>${a.params ? ` <span class="muted">— ${esc(a.params)}</span>` : ""}</div>`).join("")
    : `<div class="muted" style="font-size:12px;padding:3px 0">No actions — add some, or delete this playbook.</div>`;
  return `<div class="pb">
    <div class="pbh">
      <span class="nm">${esc(p.name)}</span>
      <span class="chiptrig">▶ ${esc(trig)}</span>${p.category ? `<span class="chipcat">${esc(p.category)}</span>` : ""}
      <span class="pill ${p.enabled ? "p-ok" : "p-off"}">${p.enabled ? "enabled" : "disabled"}</span>
      <span style="flex:1"></span>
      <span class="muted" style="font-size:11px">${p.runCount} run(s)</span>
      <button class="btn-sm2" data-run="${p.id}">▶ Run (simulate)</button>
      <button class="btn-sm2" data-toggle="${p.id}" data-on="${p.enabled ? 1 : 0}">${p.enabled ? "Disable" : "Enable"}</button>
      <button class="btn-sm2" data-del="${p.id}">✕</button>
    </div>
    ${p.description ? `<div class="muted" style="font-size:12px;margin:4px 0 6px">${esc(p.description)}</div>` : '<div style="height:4px"></div>'}
    ${steps}
  </div>`;
}

function render(): void {
  const d = DATA!; const s = d.summary;
  const cards = [
    card("Playbooks", String(s.playbooks), `${s.enabled} enabled · ${s.actions} actions`),
    card("Trigger coverage", `${s.triggersCovered}/${s.triggersTotal}`, "event types automated", s.triggersCovered >= s.triggersTotal ? "#34d399" : "#fbbf24"),
    card("Runs", String(s.runs), s.successRate != null ? `${s.successRate}% success` : "none yet", "#60a5fa"),
    card("Outbound targets", String(s.webhookTargets), s.externalConfigured ? "n8n/SOAR configured" : "simulate-only", s.externalConfigured ? "#34d399" : "#94a3b8"),
  ].join("");

  const work = d.worklist.length
    ? `<ul class="worklist">${d.worklist.map((w) => `<li><span class="sev sv-${["High", "Medium", "Low"].includes(w.severity) ? w.severity : "Low"}">${esc(w.severity)}</span> <span>${esc(w.label)}</span></li>`).join("")}</ul>`
    : `<div class="muted" style="padding:8px 0">✓ Every trigger has an enabled playbook.</div>`;

  const pbs = d.playbooks.length ? d.playbooks.map(pbHtml).join("") : `<div class="muted" style="padding:8px 0">No playbooks yet — create one with “+ New playbook”.</div>`;

  const cat = `<div class="grid2">
    <div class="panel"><h3 style="margin:0 0 6px;font-size:12px;color:#cbd5e1;text-transform:uppercase">Action catalogue</h3>${d.actionCatalogue.map((a) => `<div class="step"><span class="atype">${esc(a.id)}</span> <span>${esc(a.label)}</span></div>`).join("")}</div>
    <div class="panel"><h3 style="margin:0 0 6px;font-size:12px;color:#cbd5e1;text-transform:uppercase">Outbound targets</h3>${d.webhooks.length ? d.webhooks.map((w) => `<div class="step"><span class="pill ${w.enabled ? "p-ok" : "p-off"}">${w.enabled ? "on" : "off"}</span> <span>${esc(w.name)}</span> <span class="muted">${esc(w.host)} · ≥${esc(w.minSeverity)}</span></div>`).join("") : `<div class="muted" style="font-size:12px">No webhook target — runs stay in simulate mode. Add an n8n/SOAR webhook in Settings → SOAR.</div>`}</div>
  </div>`;

  const runs = d.runs.length
    ? `<table class="rt"><thead><tr><th>#</th><th>Playbook</th><th>Mode</th><th>Status</th><th>Steps</th><th>Summary</th><th></th></tr></thead><tbody>${d.runs.map((r) => `<tr>
        <td class="muted">${r.id}</td><td class="nm">${esc(r.playbookName)}</td><td><span class="pill ${r.mode === "live" ? "p-warn" : "p-off"}">${esc(r.mode)}</span></td>
        <td>${statusPill(r.status)}</td><td>${r.steps}</td><td class="muted">${esc(r.summary)}</td>
        <td><button class="btn-sm2" data-rundetail="${r.id}">View</button></td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">No runs yet — run a playbook (simulate) to see the orchestration.</div>`;

  $("body").innerHTML = `<div class="cards">${cards}</div>
    <div class="sec">🧩 Automation gaps (${d.worklist.length})</div><div class="panel">${work}</div>
    <div class="sec">⚙️ Playbooks (${d.playbooks.length})</div>${pbs}
    <div class="sec">📚 Catalogue &amp; targets</div>${cat}
    <div class="sec">🏃 Run history (${d.runs.length})</div><div class="panel">${runs}</div>`;
  wire();
}

function wire(): void {
  const on = (attr: string, fn: (id: number, el: HTMLElement) => void) =>
    Array.prototype.forEach.call(document.querySelectorAll(`[data-${attr}]`), (el: HTMLElement) => { el.onclick = () => fn(Number(el.getAttribute(`data-${attr}`)), el); });
  on("run", (id) => runPlaybook(id));
  on("toggle", (id, el) => act(`/api/soar/playbook/${id}/enabled`, "POST", { enabled: el.getAttribute("data-on") !== "1" }, "Updated"));
  on("del", (id) => { if (confirm("Delete this playbook?")) act(`/api/soar/playbook/${id}`, "DELETE", null, "Playbook deleted"); });
  on("rundetail", (id) => runDetail(id));
}

function act(url: string, method: string, body: unknown, okMsg: string): void {
  fetch(url, { method, headers: { "Content-Type": "application/json" }, body: body == null ? undefined : JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then(() => { toast(okMsg); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function closeModal(): void { $("modal").classList.remove("show"); }

function runPlaybook(id: number): void {
  fetch(`/api/soar/playbook/${id}/run`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode: "simulate" }) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((j: { runId: number; status: string }) => { toast("Simulated · " + j.status); runDetail(j.runId); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function runDetail(runId: number): void {
  fetch(`/api/soar/run/${runId}`).then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((d: { id: number; mode: string; status: string; summary: string; steps: any[] }) => {
      const steps = d.steps.map((s) => `<div class="step" style="align-items:flex-start"><span class="stepn">${s.order}</span>
        <div><span class="atype">${esc(s.type)}</span> <span>${esc(s.name)}</span> <span class="pill ${s.status === "success" ? "p-ok" : "p-off"}">${esc(s.status)}</span>
        <div class="muted" style="font-size:12px;margin-top:2px">${esc(s.output)}</div></div></div>`).join("");
      $("dlg").innerHTML = `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">Run #${d.id}</b><span class="pill ${d.mode === "live" ? "p-warn" : "p-off"}">${esc(d.mode)}</span><span style="flex:1"></span><button class="btn-sm2" id="dlg-close">Close</button></div>
        <div class="muted" style="font-size:12px;margin-bottom:8px">${esc(d.summary)}</div>${steps}`;
      $("modal").classList.add("show");
      ($("dlg-close") as HTMLButtonElement).onclick = closeModal;
    }).catch((e) => toast("⚠️ " + (e.message || e)));
}

let actionRows = 1;
function addActionRow(): void {
  const wrap = $("act-rows"); const i = actionRows++;
  const div = document.createElement("div"); div.className = "arow";
  div.innerHTML = `<select id="a-type-${i}">${DATA!.actionCatalogue.map((a) => `<option value="${esc(a.id)}">${esc(a.label)}</option>`).join("")}</select><input id="a-params-${i}" placeholder="params (optional)">`;
  wrap.appendChild(div);
}

function newDialog(): void {
  const d = DATA!;
  $("dlg").innerHTML = `<div style="display:flex;align-items:center;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">New SOAR playbook</b><span style="flex:1"></span><button class="btn-sm2" id="dlg-close">Close</button></div>
    <label>Name<input id="p-name" placeholder="e.g. Phishing auto-triage"></label>
    <label>Description<input id="p-desc" placeholder="optional"></label>
    <div style="display:flex;gap:8px"><label style="flex:1">Trigger<select id="p-trigger">${d.triggers.map((t) => `<option value="${esc(t.id)}">${esc(t.label)}</option>`).join("")}</select></label>
      <label style="flex:1">Category<input id="p-cat" placeholder="e.g. Email"></label></div>
    <label>Actions</label><div id="act-rows"></div>
    <button class="btn-sm2" id="add-act" style="margin-top:6px">+ Add action</button>
    <div style="display:flex;justify-content:flex-end;margin-top:12px"><button class="btn-sm2" id="p-save" style="border-color:#fb923c;color:#fdba74">Create playbook</button></div>`;
  $("modal").classList.add("show");
  ($("dlg-close") as HTMLButtonElement).onclick = closeModal;
  actionRows = 1; $("act-rows").innerHTML = ""; addActionRow(); addActionRow();
  ($("add-act") as HTMLButtonElement).onclick = addActionRow;
  ($("p-save") as HTMLButtonElement).onclick = () => {
    const name = ($("p-name") as HTMLInputElement).value.trim();
    if (!name) { toast("Name required"); return; }
    const actions: any[] = [];
    for (let i = 0; i < actionRows; i++) {
      const sel = document.getElementById(`a-type-${i}`) as HTMLSelectElement | null;
      if (sel) actions.push({ actionType: sel.value, params: (document.getElementById(`a-params-${i}`) as HTMLInputElement)?.value || "" });
    }
    fetch("/api/soar/playbook", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      name, description: ($("p-desc") as HTMLInputElement).value, triggerType: ($("p-trigger") as HTMLSelectElement).value, category: ($("p-cat") as HTMLInputElement).value, actions }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast("Playbook created"); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

function reload(): Promise<void> {
  return fetch("/api/soar").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => { DATA = d; });
}

document.addEventListener("DOMContentLoaded", () => {
  $("modal").addEventListener("click", (e) => { if (e.target === $("modal")) closeModal(); });
  ($("btn-new") as HTMLButtonElement).onclick = newDialog;
  reload().then(render).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e.message || e)}</div>`; });
});
