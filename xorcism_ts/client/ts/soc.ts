/** soc.ts — SOC Operations cockpit (/soc). MTTD/MTTA/MTTR KPIs, on-call roster + shifts, open-incident
 * queue with escalation procedure + IR playbooks (attach + step tracking). Reads /api/soc. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2800); }

interface Q { id: number; name: string; severity: string; status: string; tier: string; owner: string; detectedAt: string | null; ageMinutes: number | null; acknowledged: boolean; ackBreached: boolean; ackSlaMin: number; playbookId: number | null; playbookName: string | null; playbookDone: number; playbookTotal: number; escalations: number; }
interface Data { metrics: any; onCall: any[]; shifts: any[]; coverageNow: string[]; coverageGaps: string[]; queue: Q[]; worklist: any[]; escalation: { tiers: any[] }; playbooks: any[]; summary: any }

let DATA: Data | null = null;

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="so-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const scls = (s: string): string => `sv-${["Critical", "High", "Medium", "Low"].includes(s) ? s : "Low"}`;
const bar = (pct: number): string => `<span class="bar"><i style="width:${Math.max(0, Math.min(100, pct))}%"></i></span>`;
function age(m: number | null): string { if (m == null) return "—"; if (m < 60) return `${m}m`; const h = Math.floor(m / 60); return h < 24 ? `${h}h${m % 60 ? ` ${m % 60}m` : ""}` : `${Math.floor(h / 24)}d ${h % 24}h`; }
function mttd(v: number | null): string { if (v == null) return "—"; return v < 90 ? `${Math.round(v)} min` : `${(v / 60).toFixed(1)} h`; }

function queueRow(q: Q): string {
  const ackPill = q.acknowledged ? `<span class="pill p-ok">ack</span>` : q.ackBreached ? `<span class="pill p-bad">ack overdue</span>` : `<span class="pill p-warn">unack</span>`;
  const pb = q.playbookId ? `${bar(q.playbookTotal ? Math.round((q.playbookDone / q.playbookTotal) * 100) : 0)} <span class="muted" style="font-size:11px">${q.playbookDone}/${q.playbookTotal}</span>` : `<span class="muted">none</span>`;
  return `<tr>
    <td><span class="nm">${esc(q.name)}</span>${q.escalations ? ` <span class="muted" style="font-size:10px">↑${q.escalations}</span>` : ""}</td>
    <td><span class="sev ${scls(q.severity)}">${esc(q.severity || "—")}</span></td>
    <td><span class="tier">${esc(q.tier)}</span></td>
    <td>${esc(q.owner || "—")}</td>
    <td>${age(q.ageMinutes)}</td>
    <td>${ackPill}</td>
    <td>${q.playbookId ? `<a class="muted" style="cursor:pointer;color:#a5b4fc" data-pb="${q.id}">${esc(q.playbookName || "playbook")}</a><br>${pb}` : pb}</td>
    <td style="white-space:nowrap">
      ${q.acknowledged ? "" : `<button class="btn-sm2" data-ack="${q.id}">Ack</button> `}
      <button class="btn-sm2" data-esc="${q.id}">Escalate</button>
      <button class="btn-sm2" data-attach="${q.id}">Playbook</button>
    </td>
  </tr>`;
}

function render(): void {
  const d = DATA!; const m = d.metrics; const s = d.summary;
  const cards = [
    card("MTTD", mttd(m.mttdMinutes), `detect time · ${m.detectedCount} incidents`, m.mttdMinutes != null && m.mttdMinutes <= 60 ? "#4ade80" : "#fbbf24"),
    card("MTTA", mttd(m.mttaMinutes), `acknowledge · ${m.ackCount}`, m.mttaMinutes != null && m.mttaMinutes <= 30 ? "#4ade80" : "#fbbf24"),
    card("MTTR", m.mttrHours == null ? "—" : `${m.mttrHours} h`, `resolve · ${m.resolvedCount}`, m.mttrHours != null && m.mttrHours <= 24 ? "#4ade80" : "#fbbf24"),
    card("Open", String(s.openIncidents), `${s.criticalOpen} critical · ${s.ackBreached} overdue`, s.ackBreached ? "#f87171" : undefined),
    card("On-call now", String(s.onCallNow), s.coverageGaps ? `${s.coverageGaps} tier gap(s)` : "full coverage", s.coverageGaps ? "#fbbf24" : "#4ade80"),
    card("Escalations", String(s.escalationsToday), "today", "#60a5fa"),
  ].join("");

  const work = d.worklist.length
    ? `<ul class="worklist">${d.worklist.slice(0, 30).map((w) => `<li><span class="sev ${scls(w.severity)}">${esc(w.severity)}</span> <b style="color:#e2e8f0">${esc(w.name)}</b> — ${esc(w.reason)} <a class="muted" style="cursor:pointer;color:#a5b4fc;margin-left:auto" data-open="${w.id}">open ↗</a></li>`).join("")}</ul>`
    : `<div class="muted" style="padding:8px 0">✓ Nothing needs a SOC action right now.</div>`;

  const queue = d.queue.length
    ? `<table class="so"><thead><tr><th>Incident</th><th>Sev</th><th>Tier</th><th>Owner</th><th>Age</th><th>Ack</th><th>Playbook</th><th></th></tr></thead><tbody>${d.queue.map(queueRow).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">No open incidents in the queue.</div>`;

  const onCall = d.onCall.length
    ? d.onCall.map((o) => `<div class="oncall"><span class="tier">${esc(o.tier)}</span> <b style="color:#e2e8f0">${esc(o.person)}</b>${o.onCall ? ` <span class="pill p-ok">on-call</span>` : ""}<span style="flex:1"></span><span class="muted" style="font-size:11px">→ ${esc(o.end)}</span></div>`).join("")
    : `<div class="muted" style="padding:6px 0">No one on shift right now.</div>`;
  const cov = `<div style="margin-top:8px;font-size:12px;color:#94a3b8">Coverage: ${d.coverageNow.length ? d.coverageNow.map((t) => `<span class="tier">${esc(t)}</span>`).join(" ") : "<span class='pill p-bad'>none</span>"}${d.coverageGaps.length ? ` · gaps: ${d.coverageGaps.map((t) => `<span class="pill p-warn">${esc(t)}</span>`).join(" ")}` : ""}</div>`;

  const tiers = d.escalation.tiers.map((t) => `<div class="tierrow"><span class="tier">${esc(t.name)}</span> <b style="color:#e2e8f0">${esc(t.role)}</b><span style="flex:1"></span><span class="muted" style="font-size:11px">ack ${t.ack}m · resolve ${Math.round(t.resolve / 60)}h</span></div>`).join("");

  const shifts = d.shifts.length
    ? `<table class="so"><thead><tr><th>Analyst</th><th>Tier</th><th>Start</th><th>End</th><th>On-call</th></tr></thead><tbody>${d.shifts.map((sh) => `<tr><td><span class="nm">${esc(sh.person)}</span>${sh.active ? ` <span class="pill p-ok">now</span>` : ""}</td><td><span class="tier">${esc(sh.tier)}</span></td><td class="muted" style="font-size:12px">${esc(sh.start)}</td><td class="muted" style="font-size:12px">${esc(sh.end)}</td><td>${sh.onCall ? "✓" : ""}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">No shifts scheduled.</div>`;

  const pbs = d.playbooks.length
    ? `<div class="grid2">${d.playbooks.map((p) => `<div class="panel"><div style="display:flex;align-items:center;gap:8px;margin-bottom:4px"><span class="pbcat">${esc(p.category)}</span><span class="sev ${scls(p.severity)}">${esc(p.severity)}</span><span style="flex:1"></span><button class="btn-sm2" data-managepb="${p.id}">Manage</button></div><div class="nm">${esc(p.name)}</div><div class="muted" style="font-size:12px;margin-top:2px">${p.steps} steps · NIST SP 800-61</div></div>`).join("")}</div>`
    : `<div class="muted" style="padding:8px 0">No playbooks yet — create one with “+ New playbook”.</div>`;

  $("so-body").innerHTML = `<div class="so-cards">${cards}</div>
    <div class="so-section">SOC worklist (${d.worklist.length})</div>${work}
    <div class="so-section">Incident queue (${d.queue.length})</div>${queue}
    <div class="grid2" style="margin-top:8px">
      <div class="panel"><div class="so-section" style="margin-top:0">On-call now (${d.onCall.length})</div>${onCall}${cov}</div>
      <div class="panel"><div class="so-section" style="margin-top:0">Escalation procedure</div>${tiers}</div>
    </div>
    <div class="so-section">Shift schedule (${d.shifts.length})</div>${shifts}
    <div class="so-section" style="display:flex;align-items:center">IR playbook library (${d.playbooks.length})<span style="flex:1"></span><button class="btn-sm2" data-newpb="1">+ New playbook</button></div>${pbs}`;
  wire();
}

function wire(): void {
  const on = (attr: string, fn: (id: number, el: HTMLElement) => void) =>
    Array.prototype.forEach.call(document.querySelectorAll(`[data-${attr}]`), (el: HTMLElement) => { el.onclick = () => fn(Number(el.getAttribute(`data-${attr}`)), el); });
  on("ack", (id) => act(`/api/soc/incident/${id}/ack`, {}, "Acknowledged"));
  on("esc", (id) => { const reason = prompt("Escalation reason (escalates to the next tier):", "Past ack SLA / needs higher tier"); if (reason == null) return; act(`/api/soc/incident/${id}/escalate`, { reason }, "Escalated"); });
  on("attach", (id) => attachPlaybook(id));
  on("pb", (id) => openPlaybook(id));
  on("open", (id) => openPlaybook(id));
  on("newpb", () => newPlaybookDialog());
  on("managepb", (id) => managePlaybook(id));
}

const PB_PHASES = ["Detection & Analysis", "Containment", "Eradication", "Recovery", "Post-Incident"];
const PBFORM_CSS = `<style>.pbform label{display:block;font-size:12px;color:#94a3b8;margin-top:8px}
  .pbform input,.pbform select,.pbform textarea,.pbaddstep input,.pbaddstep select{box-sizing:border-box;background:#0f1117;border:1px solid #2d3250;color:#e2e8f0;border-radius:6px;padding:7px 9px;font-size:13px;font-family:inherit}
  .pbform input,.pbform select,.pbform textarea{width:100%;margin-top:3px}.pbform textarea{font-family:ui-monospace,monospace}</style>`;
function closeModal(): void { $("so-modal").classList.remove("show"); }

function newPlaybookDialog(): void {
  $("so-dlg").innerHTML = `${PBFORM_CSS}
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><span style="font-size:16px;color:#e7ebf3">New IR playbook</span><span style="flex:1"></span><button class="btn-sm2" id="so-close">Close</button></div>
    <div class="pbform">
      <label>Name<input id="npb-name" placeholder="e.g. DDoS / availability response"></label>
      <div style="display:flex;gap:8px">
        <label style="flex:1">Category<input id="npb-cat" placeholder="e.g. Availability"></label>
        <label style="flex:1">Severity<select id="npb-sev">${["Critical", "High", "Medium", "Low"].map((s) => `<option${s === "Medium" ? " selected" : ""}>${s}</option>`).join("")}</select></label>
      </div>
      <label>Description<input id="npb-desc" placeholder="optional"></label>
      <label>Steps <span class="muted" style="font-size:11px">one per line — <code>Phase | Title | Description</code> (phase &amp; description optional)</span>
        <textarea id="npb-steps" rows="7" placeholder="Detection & Analysis | Confirm the incident | Validate the alert and scope it&#10;Containment | Cut the path | Block the source / isolate the target"></textarea></label>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:10px"><button class="btn-sm2" id="npb-save" style="border-color:#fb923c;color:#fdba74">Create playbook</button></div>
    </div>`;
  $("so-modal").classList.add("show");
  $("so-close").onclick = closeModal;
  ($("npb-save") as HTMLButtonElement).onclick = () => {
    const name = ($("npb-name") as HTMLInputElement).value.trim();
    if (!name) { toast("Name required"); return; }
    const steps = ($("npb-steps") as HTMLTextAreaElement).value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => {
      const p = l.split("|").map((x) => x.trim());
      if (p.length >= 3) return { phase: p[0], title: p[1], description: p.slice(2).join(" | ") };
      if (p.length === 2) return { phase: p[0], title: p[1] };
      return { title: p[0] };
    });
    fetch("/api/soc/playbook", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, category: ($("npb-cat") as HTMLInputElement).value.trim(), severity: ($("npb-sev") as HTMLSelectElement).value, description: ($("npb-desc") as HTMLInputElement).value.trim(), steps }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast("Playbook created"); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

function managePlaybook(id: number): void {
  fetch("/api/soc/playbooks").then((r) => r.json()).then((d: { playbooks: any[] }) => {
    const pb = d.playbooks.find((p) => p.id === id);
    if (!pb) { toast("Playbook not found"); return; }
    const steps = pb.steps.length ? pb.steps.map((st: any) => `
      <div class="pstep" style="align-items:flex-start">
        <div class="pt"><div class="tt">${st.order}. ${esc(st.title)} <span class="muted" style="font-size:11px">· ${esc(st.phase)}</span></div><div class="dd">${esc(st.description)}</div></div>
        <button class="btn-sm2" data-delstep="${st.id}" title="Delete step">✕</button>
      </div>`).join("") : `<div class="muted" style="padding:6px 0">No steps yet — add one below.</div>`;
    $("so-dlg").innerHTML = `${PBFORM_CSS}
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px"><span style="font-size:16px;color:#e7ebf3">${esc(pb.name)}</span><span class="pbcat">${esc(pb.category)}</span><span class="sev ${scls(pb.severity)}">${esc(pb.severity)}</span><span style="flex:1"></span><button class="btn-sm2" id="so-close">Close</button></div>
      <div class="muted" style="font-size:12px;margin-bottom:8px">${pb.steps.length} step(s) · ${esc(pb.description || "NIST SP 800-61 playbook")}</div>
      ${steps}
      <div class="pbaddstep" style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-top:10px;border-top:1px solid #1e2133;padding-top:10px">
        <select id="as-phase">${PB_PHASES.map((p) => `<option>${p}</option>`).join("")}</select>
        <input id="as-title" placeholder="Step title" style="flex:1;min-width:150px">
        <input id="as-desc" placeholder="Description (optional)" style="flex:2;min-width:150px">
        <button class="btn-sm2" id="as-add">+ Add step</button>
      </div>
      <div style="display:flex;justify-content:flex-end;margin-top:12px"><button class="btn-sm2" id="pb-del" style="border-color:#7f1d1d;color:#fca5a5">Delete playbook</button></div>`;
    $("so-modal").classList.add("show");
    $("so-close").onclick = closeModal;
    Array.prototype.forEach.call(document.querySelectorAll("[data-delstep]"), (b: HTMLElement) => {
      b.onclick = () => fetch(`/api/soc/playbook-step/${b.getAttribute("data-delstep")}`, { method: "DELETE" })
        .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
        .then(() => { toast("Step deleted"); managePlaybook(id); reload().then(render); }).catch((e) => toast("⚠️ " + e));
    });
    ($("as-add") as HTMLButtonElement).onclick = () => {
      const title = ($("as-title") as HTMLInputElement).value.trim();
      if (!title) { toast("Title required"); return; }
      fetch(`/api/soc/playbook/${id}/step`, { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phase: ($("as-phase") as HTMLSelectElement).value, title, description: ($("as-desc") as HTMLInputElement).value.trim() }) })
        .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
        .then(() => { toast("Step added"); managePlaybook(id); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
    };
    ($("pb-del") as HTMLButtonElement).onclick = () => {
      if (!confirm(`Delete the playbook "${pb.name}" and all its steps?`)) return;
      fetch(`/api/soc/playbook/${id}`, { method: "DELETE" })
        .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
        .then(() => { toast("Playbook deleted"); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
    };
  }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function act(url: string, body: unknown, okMsg: string): void {
  fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then(() => { toast(okMsg); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function attachPlaybook(incidentId: number): void {
  const d = DATA!;
  if (!d.playbooks.length) { toast("No playbooks available"); return; }
  const list = d.playbooks.map((p, i) => `${i + 1}. ${p.name} (${p.category})`).join("\n");
  const pick = prompt(`Attach an IR playbook — enter the number:\n\n${list}`);
  if (!pick) return;
  const idx = Number(pick) - 1;
  if (!d.playbooks[idx]) { toast("Invalid choice"); return; }
  act(`/api/soc/incident/${incidentId}/playbook`, { playbookId: d.playbooks[idx].id }, "Playbook attached");
}

function openPlaybook(incidentId: number): void {
  const q = DATA!.queue.find((x) => x.id === incidentId);
  fetch(`/api/soc/incident/${incidentId}/playbook`).then((r) => r.json()).then((d: { phases: any[]; progress: any }) => {
    if (!d.phases.length) { toast("No playbook attached — use the Playbook button"); return; }
    const phases = d.phases.map((ph) => `<div class="phase"><div class="ph-head">${esc(ph.name)}</div>${ph.steps.map((st: any) => `
      <div class="pstep ${st.status === "done" ? "st-done" : ""}" data-step="${st.id}">
        <div class="pt"><div class="tt">${esc(st.title)}</div><div class="dd">${esc(st.description)}</div></div>
        <select class="pstep-status" data-step="${st.id}">
          ${[["todo", "To do"], ["in_progress", "In progress"], ["done", "Done"], ["na", "N/A"]].map(([v, l]) => `<option value="${v}"${st.status === v ? " selected" : ""}>${l}</option>`).join("")}
        </select>
      </div>`).join("")}</div>`).join("");
    $("so-dlg").innerHTML = `<div style="display:flex;align-items:center;gap:10px;margin-bottom:4px"><span style="font-size:16px;color:#e7ebf3">${esc(q?.name || "Incident #" + incidentId)}</span><span class="spacer" style="flex:1"></span><button class="btn-sm2" id="so-close">Close</button></div>
      <div class="muted" style="font-size:12px;margin-bottom:8px">IR playbook · ${bar(d.progress.pct)} ${d.progress.done}/${d.progress.total} steps (${d.progress.pct}%)</div>${phases}`;
    $("so-modal").classList.add("show");
    $("so-close").onclick = () => $("so-modal").classList.remove("show");
    Array.prototype.forEach.call(document.querySelectorAll(".pstep-status"), (sel: HTMLSelectElement) => {
      sel.onchange = () => {
        fetch(`/api/soc/playbook-step/${sel.getAttribute("data-step")}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: sel.value }) })
          .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
          .then(() => openPlaybook(incidentId)).then(() => reload().then(render)).catch((e) => toast("⚠️ " + e));
      };
    });
  }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function reload(): Promise<void> {
  return fetch("/api/soc").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => { DATA = d; });
}

document.addEventListener("DOMContentLoaded", () => {
  $("so-modal").addEventListener("click", (e) => { if (e.target === $("so-modal")) $("so-modal").classList.remove("show"); });
  reload().then(render).catch((e) => { $("so-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
});
