/**
 * tlpt.ts — TLPT / TIBER-EU cockpit (/tlpt).
 * List/create engagements, then per-engagement: the 3-phase milestone workflow with sign-offs, the
 * flags (reached/detected/prevented), the intelligence-led scenarios (+AI proposals), the findings +
 * remediation status, the team roster, the resilience scorecard, and a Test Summary Report. All from
 * /api/tlpt*. Phase/role terminology from the ECB TIBER-EU framework.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function postJSON(u: string, b?: any): Promise<any> { const r = await fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return r.json().catch(() => ({})); }
async function delJSON(u: string): Promise<any> { const r = await fetch(u, { method: "DELETE", credentials: "same-origin" }); return r.json().catch(() => ({})); }

const scoreColor = (n: number): string => (n >= 80 ? "#10b981" : n >= 50 ? "#fbbf24" : n >= 25 ? "#fb923c" : "#ef4444");
let REF: any = { phases: [], teamRoles: [], actorTypes: [], scenarioStatus: [], severity: [] };
let CUR = 0;

function card(lbl: string, val: string, foot: string, color?: string, cls = "tl-card"): string {
  return `<div class="${cls}"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}
const opts = (arr: string[], sel?: string): string => arr.map((o) => `<option${sel === o ? " selected" : ""}>${esc(o)}</option>`).join("");

// ── list view ──────────────────────────────────────────────────────────────
async function loadList(): Promise<void> {
  const d = await getJSON("/api/tlpt");
  REF = d;
  const rows = (d.engagements || []).map((e: any) => `<div class="mrow" data-open="${e.id}">
      <span class="nm">${esc(e.name)}</span>
      <span class="muted" style="font-size:11px">${esc(e.entity || "")}</span>
      <span class="pill fw">${esc(e.framework)}</span>
      <span class="muted" style="font-size:11px">${e.flags} flags · ${e.milestonesDone}/${e.milestones} milestones</span>
      <span class="pill st">${esc(e.status)}</span>
    </div>`).join("") || `<div class="muted" style="padding:14px">No TLPT engagements yet. Create one, or seed a demo.</div>`;
  $("tl-body").innerHTML = `
    <div class="tl-section">Engagements</div>
    <div class="frm open" style="margin-bottom:14px">
      <div class="grid">
        <div style="grid-column:span 2"><label>Name</label><input class="in" id="e-name" placeholder="e.g. TIBER-EU test — core payment services"></div>
        <div><label>Entity</label><input class="in" id="e-entity"></div>
        <div><label>Authority (TCT)</label><input class="in" id="e-auth"></div>
        <div><label>TI provider</label><input class="in" id="e-ti"></div>
        <div><label>Red-Team provider</label><input class="in" id="e-rt"></div>
        <div style="grid-column:1/-1"><label>Critical functions (comma-separated)</label><input class="in" id="e-cf" placeholder="Payment processing; SWIFT messaging; customer authentication"></div>
        <div style="grid-column:1/-1"><label>Scope</label><textarea class="in" id="e-scope" placeholder="Production systems in scope for the test."></textarea></div>
      </div>
      <button class="btn" id="e-create">+ Create engagement</button>
      <button class="btn sec" id="e-seed">Seed demo engagement</button>
    </div>
    <div id="e-list">${rows}</div>`;
  $("e-create").onclick = async () => {
    const name = ($("e-name") as HTMLInputElement).value.trim(); if (!name) { ($("e-name") as HTMLInputElement).focus(); return; }
    const out = await postJSON("/api/tlpt", { name, entity: ($("e-entity") as HTMLInputElement).value, authority: ($("e-auth") as HTMLInputElement).value, tiProvider: ($("e-ti") as HTMLInputElement).value, rtProvider: ($("e-rt") as HTMLInputElement).value, criticalFunctions: ($("e-cf") as HTMLInputElement).value, scope: ($("e-scope") as HTMLTextAreaElement).value });
    if (out.id) loadDetail(out.id);
  };
  $("e-seed").onclick = async () => { await postJSON("/api/tlpt/seed"); loadList(); };
  document.querySelectorAll("#e-list .mrow").forEach((el) => { (el as HTMLElement).onclick = () => loadDetail(Number((el as HTMLElement).dataset.open)); });
}

// ── detail view ──────────────────────────────────────────────────────────────
async function loadDetail(id: number): Promise<void> {
  CUR = id;
  const m = await getJSON(`/api/tlpt/${id}`);
  if (!m || !m.engagement) { loadList(); return; }
  const e = m.engagement; const c = m.scorecard || {};
  const cards = [
    card("Resilience", `${c.resilience ?? 0}`, "Prevent·Detect·Respond", scoreColor(c.resilience ?? 0), "tl-card tl-score"),
    card("Flags", `${c.reached ?? 0}/${c.flags ?? 0}`, "reached / total", scoreColor(100 - (c.detectRate ?? 0))),
    card("Detection", `${c.detectRate ?? 0}%`, `${c.detected ?? 0} of reached`, scoreColor(c.detectRate ?? 0)),
    card("Findings", `${c.findings ?? 0}`, `${c.critical ?? 0} crit · ${c.high ?? 0} high · ${c.openFindings ?? 0} open`, scoreColor(100 - Math.min(100, (c.critical ?? 0) * 25 + (c.high ?? 0) * 10))),
    card("Remediation", `${c.remediated ?? 0}%`, "findings closed", scoreColor(c.remediated ?? 0)),
    card("Process", `${c.milestonePct ?? 0}%`, `${c.milestonesDone ?? 0}/${c.milestones ?? 0} milestones`, scoreColor(c.milestonePct ?? 0)),
  ].join("");

  $("tl-body").innerHTML = `
    <div class="row"><button class="btn sec sm" id="back">&#8592; All engagements</button>
      <h2 style="margin:0;font-size:17px">${esc(e.name)}</h2>
      <span class="pill fw">${esc(e.framework)}</span><span class="pill st">${esc(e.status)}</span>
      <button class="btn danger sm" id="e-del" style="margin-left:auto">Delete</button></div>
    <div class="muted" style="font-size:12px;margin-bottom:10px">${esc([e.entity, e.authority, e.criticalFunctions && ("CF: " + e.criticalFunctions)].filter(Boolean).join(" · "))}${e.scope ? `<br>${esc(e.scope)}` : ""}</div>
    <div class="tl-cards">${cards}</div>

    <div class="tl-section">AI assist</div>
    <div class="frm open">
      <div class="row" style="margin-bottom:0">
        <button class="btn sec sm" id="ai-scen">&#9889; Propose TTI scenarios</button>
        <button class="btn sec sm" id="ai-report">&#128221; Test Summary Report</button>
        <span class="muted" style="font-size:11px">Local AI (Ollama) with deterministic offline fallback.</span>
      </div>
      <div id="ai-out"></div>
    </div>

    <div class="tl-section">Workflow &mdash; TIBER-EU phases &amp; milestones</div>
    <div id="phases">${(m.phases || []).map((p: any) => phaseBlock(p, m.milestones)).join("")}</div>

    <div class="tl-section">Flags <span class="muted" style="font-weight:400;text-transform:none">&mdash; critical-function targets (reached / detected / prevented)</span></div>
    <div id="flags">${flagsTable(m.flags)}</div>

    <div class="tl-section">Attack scenarios <span class="muted" style="font-weight:400;text-transform:none">&mdash; from the Targeted Threat Intelligence</span></div>
    <div id="scenarios">${scenarioTable(m.scenarios)}</div>

    <div class="tl-section">Findings &amp; remediation</div>
    <div id="findings">${findingTable(m.findings)}</div>

    <div class="tl-section">Team roster</div>
    <div id="teams">${teamTable(m.teams)}</div>`;

  $("back").onclick = loadList;
  $("e-del").onclick = async () => { if (confirm("Delete this engagement and all its data?")) { await delJSON(`/api/tlpt/${CUR}`); loadList(); } };
  wireDetail(m);
}

function phaseBlock(p: any, milestones: any[]): string {
  const ms = milestones.filter((m) => m.phase === p.phase);
  const done = ms.filter((m) => m.status === "completed").length;
  const rows = ms.map((m) => `<div class="ms ms-${esc(m.status)}">
      <span class="code">${esc(m.code)}</span>
      <span class="mn"><b>${esc(m.name)}</b><div class="dl">${esc(m.deliverable)}</div></span>
      <select class="in ms-sel" data-mid="${m.id}">${["pending", "in-progress", "completed"].map((s) => `<option value="${s}"${m.status === s ? " selected" : ""}>${s}</option>`).join("")}</select>
      <span class="ap">${m.signedBy ? `✓ ${esc(m.signedBy)} · ${esc((m.signedAt || "").slice(0, 10))}` : ""}</span>
    </div>`).join("");
  return `<div class="ph"><h4>Phase ${p.phase} — ${esc(p.name)} <span class="muted">${done}/${ms.length}</span></h4>${rows}</div>`;
}

function flagsTable(flags: any[]): string {
  const rows = (flags || []).map((f) => `<tr>
    <td><b>${esc(f.name)}</b>${f.criticalFunction ? `<div class="muted" style="font-size:11px">${esc(f.criticalFunction)}</div>` : ""}</td>
    <td><span class="chip flagtog ${f.reached ? "on" : ""}" data-fid="${f.id}" data-k="reached">${f.reached ? "● reached" : "○ reached"}</span></td>
    <td><span class="chip flagtog ${f.detected ? "on" : ""}" data-fid="${f.id}" data-k="detected">${f.detected ? "● detected" : "○ detected"}</span></td>
    <td><span class="chip flagtog ${f.prevented ? "on" : ""}" data-fid="${f.id}" data-k="prevented">${f.prevented ? "● prevented" : "○ prevented"}</span></td>
    <td>${f.timeToDetectHours != null ? `${esc(f.timeToDetectHours)}h` : "—"}</td>
    <td><span class="xdel" data-delflag="${f.id}">✕</span></td></tr>`).join("") || `<tr><td colspan="6" class="muted">No flags yet.</td></tr>`;
  return `<table class="tt"><thead><tr><th>Flag (target)</th><th>Reached</th><th>Detected</th><th>Prevented</th><th>TTD</th><th></th></tr></thead><tbody>${rows}</tbody></table>
    <button class="btn sec sm" id="addflag" style="margin-top:8px">+ add flag</button>
    <div class="frm" id="flagform">
      <div class="grid">
        <div style="grid-column:span 2"><label>Flag / target</label><input class="in" id="fl-name"></div>
        <div><label>Critical function</label><input class="in" id="fl-cf"></div>
        <div><label>Time-to-detect (h)</label><input class="in" id="fl-ttd" type="number" step="0.1"></div>
      </div>
      <div class="row"><label class="chip"><input type="checkbox" id="fl-reached"> reached</label><label class="chip"><input type="checkbox" id="fl-detected"> detected</label><label class="chip"><input type="checkbox" id="fl-prevented"> prevented</label>
        <button class="btn sm" id="fl-save">Save flag</button></div>
    </div>`;
}

function scenarioTable(scen: any[]): string {
  const rows = (scen || []).map((s) => `<tr>
    <td><b>${esc(s.name)}</b>${s.narrative ? `<div class="muted" style="font-size:11px">${esc(s.narrative)}</div>` : ""}</td>
    <td>${esc(s.threatActor || "")}${s.actorType ? `<div class="muted" style="font-size:11px">${esc(s.actorType)}</div>` : ""}</td>
    <td>${(s.attackTags || "").split(",").map((x: string) => x.trim()).filter(Boolean).map((x: string) => `<span class="tag">${esc(x)}</span>`).join(" ")}</td>
    <td><span class="tag">${esc(s.status)}</span></td>
    <td><span class="xdel" data-delscen="${s.id}">✕</span></td></tr>`).join("") || `<tr><td colspan="5" class="muted">No scenarios yet — add one, or use “Propose TTI scenarios”.</td></tr>`;
  return `<table class="tt"><thead><tr><th>Scenario</th><th>Threat actor</th><th>ATT&CK</th><th>Status</th><th></th></tr></thead><tbody>${rows}</tbody></table>
    <button class="btn sec sm" id="addscen" style="margin-top:8px">+ add scenario</button>
    <div class="frm" id="scenform">
      <div class="grid">
        <div style="grid-column:span 2"><label>Name</label><input class="in" id="sc-name"></div>
        <div><label>Threat actor</label><input class="in" id="sc-actor"></div>
        <div><label>Actor type</label><select class="in" id="sc-atype"><option value=""></option>${opts(REF.actorTypes || [])}</select></div>
        <div><label>Status</label><select class="in" id="sc-status">${opts(REF.scenarioStatus || [])}</select></div>
        <div><label>ATT&CK tags</label><input class="in" id="sc-tags" placeholder="T1566, T1078"></div>
        <div><label>Flags targeted</label><input class="in" id="sc-flags"></div>
        <div style="grid-column:1/-1"><label>Narrative</label><textarea class="in" id="sc-narr"></textarea></div>
      </div>
      <button class="btn sm" id="sc-save">Save scenario</button>
    </div>`;
}

function findingTable(fnd: any[]): string {
  const rows = (fnd || []).map((f) => `<tr>
    <td><b>${esc(f.title)}</b>${f.recommendation ? `<div class="muted" style="font-size:11px">→ ${esc(f.recommendation)}</div>` : ""}</td>
    <td class="sev-${esc(f.severity)}">${esc(f.severity || "—")}</td>
    <td>${esc(f.category || "")}</td>
    <td><select class="in find-st" data-fid="${f.id}">${["Open", "In progress", "Remediated", "Closed", "Accepted"].map((s) => `<option${f.status === s ? " selected" : ""}>${esc(s)}</option>`).join("")}</select></td>
    <td>${esc(f.remediationOwner || "")}</td>
    <td><span class="xdel" data-delfind="${f.id}">✕</span></td></tr>`).join("") || `<tr><td colspan="6" class="muted">No findings yet.</td></tr>`;
  return `<table class="tt"><thead><tr><th>Finding</th><th>Severity</th><th>Category</th><th>Status</th><th>Owner</th><th></th></tr></thead><tbody>${rows}</tbody></table>
    <button class="btn sec sm" id="addfind" style="margin-top:8px">+ add finding</button>
    <div class="frm" id="findform">
      <div class="grid">
        <div style="grid-column:span 2"><label>Title</label><input class="in" id="fd-title"></div>
        <div><label>Severity</label><select class="in" id="fd-sev">${opts(REF.severity || [])}</select></div>
        <div><label>Category</label><input class="in" id="fd-cat"></div>
        <div><label>Owner</label><input class="in" id="fd-owner"></div>
        <div><label>ATT&CK tags</label><input class="in" id="fd-tags"></div>
        <div style="grid-column:1/-1"><label>Description</label><textarea class="in" id="fd-desc"></textarea></div>
        <div style="grid-column:1/-1"><label>Recommendation</label><textarea class="in" id="fd-rec"></textarea></div>
      </div>
      <button class="btn sm" id="fd-save">Save finding</button>
    </div>`;
}

function teamTable(teams: any[]): string {
  const rows = (teams || []).map((m) => `<tr>
    <td><span class="tag">${esc(m.teamRole)}</span></td><td>${esc(m.memberName)}</td><td>${esc(m.organisation || "")}</td><td>${esc(m.contact || "")}</td>
    <td><span class="xdel" data-delteam="${m.id}">✕</span></td></tr>`).join("") || `<tr><td colspan="5" class="muted">No team members yet.</td></tr>`;
  return `<table class="tt"><thead><tr><th>Role</th><th>Member</th><th>Organisation</th><th>Contact</th><th></th></tr></thead><tbody>${rows}</tbody></table>
    <button class="btn sec sm" id="addteam" style="margin-top:8px">+ add member</button>
    <div class="frm" id="teamform">
      <div class="grid">
        <div><label>Team role</label><select class="in" id="tm-role">${opts(REF.teamRoles || [])}</select></div>
        <div><label>Member</label><input class="in" id="tm-name"></div>
        <div><label>Organisation</label><input class="in" id="tm-org"></div>
        <div><label>Contact</label><input class="in" id="tm-contact"></div>
      </div>
      <button class="btn sm" id="tm-save">Save member</button>
    </div>`;
}

// ── wiring ─────────────────────────────────────────────────────────────────
function toggle(el: HTMLElement | null): void { if (el) el.classList.toggle("open"); }
const val = (id: string): string => ($(id) as HTMLInputElement).value;
const chk = (id: string): boolean => ($(id) as HTMLInputElement).checked;

function wireDetail(m: any): void {
  // milestones
  document.querySelectorAll(".ms-sel").forEach((el) => { (el as HTMLSelectElement).onchange = async () => { await postJSON(`/api/tlpt/milestone/${(el as HTMLElement).dataset.mid}`, { status: (el as HTMLSelectElement).value }); loadDetail(CUR); }; });
  // flags
  $("addflag").onclick = () => toggle($("flagform"));
  $("fl-save").onclick = async () => { const name = val("fl-name").trim(); if (!name) return; await postJSON(`/api/tlpt/${CUR}/flag`, { name, criticalFunction: val("fl-cf"), timeToDetectHours: val("fl-ttd"), reached: chk("fl-reached"), detected: chk("fl-detected"), prevented: chk("fl-prevented") }); loadDetail(CUR); };
  document.querySelectorAll(".flagtog").forEach((el) => { (el as HTMLElement).onclick = async () => {
    const fid = (el as HTMLElement).dataset.fid, k = (el as HTMLElement).dataset.k!, now = el.classList.contains("on");
    await postJSON(`/api/tlpt/flag/${fid}/outcome`, { [k]: !now }); loadDetail(CUR);
  }; });
  document.querySelectorAll("[data-delflag]").forEach((el) => { (el as HTMLElement).onclick = async () => { await delJSON(`/api/tlpt/flag/${(el as HTMLElement).dataset.delflag}`); loadDetail(CUR); }; });
  // scenarios
  $("addscen").onclick = () => toggle($("scenform"));
  $("sc-save").onclick = async () => { const name = val("sc-name").trim(); if (!name) return; await postJSON(`/api/tlpt/${CUR}/scenario`, { name, threatActor: val("sc-actor"), actorType: val("sc-atype"), status: val("sc-status"), attackTags: val("sc-tags"), flagsTargeted: val("sc-flags"), narrative: val("sc-narr") }); loadDetail(CUR); };
  document.querySelectorAll("[data-delscen]").forEach((el) => { (el as HTMLElement).onclick = async () => { await delJSON(`/api/tlpt/scenario/${(el as HTMLElement).dataset.delscen}`); loadDetail(CUR); }; });
  // findings
  $("addfind").onclick = () => toggle($("findform"));
  $("fd-save").onclick = async () => { const title = val("fd-title").trim(); if (!title) return; await postJSON(`/api/tlpt/${CUR}/finding`, { title, severity: val("fd-sev"), category: val("fd-cat"), remediationOwner: val("fd-owner"), attackTags: val("fd-tags"), description: val("fd-desc"), recommendation: val("fd-rec") }); loadDetail(CUR); };
  document.querySelectorAll(".find-st").forEach((el) => { (el as HTMLSelectElement).onchange = async () => { await postJSON(`/api/tlpt/finding/${(el as HTMLElement).dataset.fid}/status`, { status: (el as HTMLSelectElement).value }); loadDetail(CUR); }; });
  document.querySelectorAll("[data-delfind]").forEach((el) => { (el as HTMLElement).onclick = async () => { await delJSON(`/api/tlpt/finding/${(el as HTMLElement).dataset.delfind}`); loadDetail(CUR); }; });
  // team
  $("addteam").onclick = () => toggle($("teamform"));
  $("tm-save").onclick = async () => { const name = val("tm-name").trim(); if (!name) return; await postJSON(`/api/tlpt/${CUR}/team`, { teamRole: val("tm-role"), memberName: name, organisation: val("tm-org"), contact: val("tm-contact") }); loadDetail(CUR); };
  document.querySelectorAll("[data-delteam]").forEach((el) => { (el as HTMLElement).onclick = async () => { await delJSON(`/api/tlpt/team/${(el as HTMLElement).dataset.delteam}`); loadDetail(CUR); }; });
  // AI
  $("ai-scen").onclick = async () => { aiOut("Proposing scenarios…"); renderScenProposals(await postJSON(`/api/tlpt/${CUR}/ai/scenarios`, {})); };
  $("ai-report").onclick = async () => { aiOut("Generating report…"); const d = await postJSON(`/api/tlpt/${CUR}/ai/report`, {}); aiOut(mdLite(d.report || "(no report)") + tag(d)); };
  void m;
}

function aiOut(html: string): void { $("ai-out").innerHTML = `<div class="ai-out">${html}</div>`; }
function tag(d: any): string { return `<div class="muted" style="font-size:10px;margin-top:8px">${d.offline ? "offline/deterministic" : "AI"} · ${esc(d.model || "")}</div>`; }
function mdLite(s: string): string {
  return esc(s).replace(/^#{1,3} (.*)$/gm, "<b style='font-size:14px'>$1</b>").replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/^- /gm, "• ");
}
function renderScenProposals(d: any): void {
  const ps = (d.proposals || []) as any[];
  if (!ps.length) { aiOut("No new scenario proposals — add critical functions/flags first." + tag(d)); return; }
  const rows = ps.map((p, i) => `<div class="prop"><span class="pt"><b>${esc(p.name)}</b> <span class="muted" style="font-size:10px">[${esc(p.actorType)}] ${esc(p.attackTags)}</span></span>
    <button class="btn sm acc-scen" data-i="${i}">accept</button></div>`).join("");
  aiOut(`<b>${ps.length} scenario starters</b> <button class="btn sm" id="acc-all" style="float:right">accept all</button><div style="margin:6px 0">${esc(d.commentary || "")}</div>${rows}${tag(d)}`);
  const accept = async (p: any) => { await postJSON(`/api/tlpt/${CUR}/scenario`, { name: p.name, threatActor: p.threatActor, actorType: p.actorType, attackTags: p.attackTags, flagsTargeted: p.flagsTargeted, narrative: p.narrative, status: "planned" }); };
  document.querySelectorAll(".acc-scen").forEach((el) => { (el as HTMLElement).onclick = async () => { await accept(ps[Number((el as HTMLElement).dataset.i)]); (el as HTMLButtonElement).textContent = "✓"; (el as HTMLButtonElement).disabled = true; }; });
  $("acc-all").onclick = async () => { for (const p of ps) await accept(p); loadDetail(CUR); };
}

loadList().catch((e) => { $("tl-body").innerHTML = `<div class="muted" style="padding:20px">Failed to load: ${esc(String(e))}</div>`; });
