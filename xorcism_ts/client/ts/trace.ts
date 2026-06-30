/**
 * trace.ts — TRACE threat-modeling cockpit (/trace).
 * List/create TRACE models, then per-model: the 6-phase workflow with approval gates, the five model
 * objects (actors/roles/assets/invariants/edges, evidence vs assumption), STRIDE threats traced to
 * objects, collusion surfaces, the coverage scorecard, and AI assist (extract / propose-STRIDE / report).
 * All data from /api/trace*. TRACE methodology © Oak Security, CC BY 4.0.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function postJSON(u: string, body?: any): Promise<any> { const r = await fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) }); return r.json().catch(() => ({})); }
async function delJSON(u: string): Promise<any> { const r = await fetch(u, { method: "DELETE", credentials: "same-origin" }); return r.json().catch(() => ({})); }

const OBJ_TYPES = ["actor", "role", "asset", "invariant", "edge"];
const OBJ_TITLE: Record<string, string> = { actor: "Threat actors", role: "Roles", asset: "Assets", invariant: "Critical invariants", edge: "Edges" };
const OBJ_FIELDS: Record<string, { k: string; label: string; type?: string }[]> = {
  actor: [{ k: "name", label: "Name" }, { k: "kind", label: "Kind" }, { k: "capability", label: "Capability" }, { k: "incentive", label: "Incentive" }],
  role: [{ k: "name", label: "Name" }, { k: "privilege", label: "Privilege" }],
  asset: [{ k: "name", label: "Name" }, { k: "kind", label: "Kind" }, { k: "value", label: "Value" }],
  invariant: [{ k: "name", label: "Name" }, { k: "statement", label: "Statement", type: "ta" }, { k: "category", label: "Category" }],
  edge: [{ k: "name", label: "Name" }, { k: "fromdomain", label: "From domain" }, { k: "todomain", label: "To domain" }, { k: "kind", label: "Kind" }],
};
const scoreColor = (n: number): string => (n >= 80 ? "#10b981" : n >= 50 ? "#fbbf24" : n >= 25 ? "#fb923c" : "#ef4444");

let REF: { phases: any[]; pillars: string[]; stride: string[] } = { phases: [], pillars: ["Protocol", "System", "Organisation"], stride: [] };
let CUR = 0;

function card(lbl: string, val: string, foot: string, color?: string, cls = "tr-card"): string {
  return `<div class="${cls}"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}

// ── list view ──────────────────────────────────────────────────────────────
async function loadList(): Promise<void> {
  const d = await getJSON("/api/trace");
  REF = { phases: d.phases || [], pillars: d.pillars || REF.pillars, stride: d.stride || [] };
  const models = (d.models || []) as any[];
  const rows = models.map((m) => `<div class="mrow" data-open="${m.id}">
      <span class="nm">${esc(m.name)}</span>
      <span class="pill pillar">${esc(m.pillar || "—")}</span>
      <span class="muted" style="font-size:11px">${m.objects} objects · phases ${m.phasesApproved}/${m.phasesTotal}</span>
      <span class="pill q">${esc(m.status)}</span>
    </div>`).join("") || `<div class="muted" style="padding:14px">No TRACE models yet. Create one, or seed a demo.</div>`;
  const pillarOpts = REF.pillars.map((p) => `<option>${esc(p)}</option>`).join("");
  $("tr-body").innerHTML = `
    <div class="tr-section">Models</div>
    <div class="frm open" style="margin-bottom:14px">
      <div class="grid">
        <div style="grid-column:span 2"><label>Name</label><input class="in" id="m-name" placeholder="e.g. Treasury multisig & deploy pipeline"></div>
        <div><label>Pillar</label><select class="in" id="m-pillar">${pillarOpts}</select></div>
      </div>
      <div style="margin-bottom:7px"><label style="font-size:10px;color:#94a3b8">Scope / description</label><textarea class="in" id="m-scope" placeholder="What is in scope: the system, protocol or organisation under analysis."></textarea></div>
      <button class="btn" id="m-create">+ Create TRACE model</button>
      <button class="btn sec" id="m-seed">Seed demo model</button>
    </div>
    <div id="m-list">${rows}</div>`;
  $("m-create").onclick = async () => {
    const name = ($("m-name") as HTMLInputElement).value.trim();
    if (!name) { ($("m-name") as HTMLInputElement).focus(); return; }
    const out = await postJSON("/api/trace", { name, pillar: ($("m-pillar") as HTMLSelectElement).value, scope: ($("m-scope") as HTMLTextAreaElement).value });
    if (out.id) loadDetail(out.id);
  };
  $("m-seed").onclick = async () => { await postJSON("/api/trace/seed"); loadList(); };
  document.querySelectorAll("#m-list .mrow").forEach((el) => { (el as HTMLElement).onclick = () => loadDetail(Number((el as HTMLElement).dataset.open)); });
}

// ── detail view ────────────────────────────────────────────────────────────
async function loadDetail(id: number): Promise<void> {
  CUR = id;
  const m = await getJSON(`/api/trace/${id}`);
  if (!m || !m.model) { loadList(); return; }
  const c = m.coverage || {};
  const cards = [
    card("Quality score", `${c.qualityScore ?? 0}`, "output quality", scoreColor(c.qualityScore ?? 0), "tr-card tr-score"),
    card("Objects", `${(c.actors ?? 0) + (c.roles ?? 0) + (c.assets ?? 0) + (c.invariants ?? 0) + (c.edges ?? 0)}`, `${c.actors ?? 0}A ${c.roles ?? 0}R ${c.assets ?? 0}As ${c.invariants ?? 0}I ${c.edges ?? 0}E`),
    card("STRIDE threats", `${c.threats ?? 0}`, `${c.traceabilityPct ?? 0}% traced`, scoreColor(c.traceabilityPct ?? 0)),
    card("Asset coverage", `${c.assetCoveragePct ?? 0}%`, `${c.assetsCovered ?? 0}/${c.assets ?? 0} assets`, scoreColor(c.assetCoveragePct ?? 0)),
    card("Attack trees", `${c.attackTrees ?? 0}`, "phase 4"),
    card("Phases approved", `${c.phasesApproved ?? 0}/${c.phasesTotal ?? 7}`, "approval gates", scoreColor(Math.round(((c.phasesApproved ?? 0) / (c.phasesTotal ?? 7)) * 100))),
  ].join("");

  $("tr-body").innerHTML = `
    <div class="row"><button class="btn sec sm" id="back">&#8592; All models</button>
      <h2 style="margin:0;font-size:17px">${esc(m.model.name)}</h2>
      <span class="pill pillar">${esc(m.model.pillar)}</span><span class="pill q">${esc(m.model.status)}</span></div>
    ${m.model.scope ? `<div class="muted" style="font-size:12px;margin-bottom:10px">${esc(m.model.scope)}</div>` : ""}
    <div class="tr-cards">${cards}</div>

    <div class="tr-section">Workflow &mdash; 6 phases (sequential approval gates)</div>
    <div class="phases" id="phases">${(m.phases || []).map(phaseCard).join("")}</div>

    <div class="tr-section">AI assist</div>
    <div class="frm open">
      <div class="row" style="margin-bottom:6px">
        <button class="btn sec sm" id="ai-stride">&#9889; Propose STRIDE threats</button>
        <button class="btn sec sm" id="ai-report">&#128221; Generate report</button>
        <span class="muted" style="font-size:11px">Local AI (Ollama) with deterministic offline fallback.</span>
      </div>
      <details><summary class="muted" style="font-size:12px;cursor:pointer">Extract objects from sources (paste text)&hellip;</summary>
        <textarea class="in" id="ai-src" style="margin-top:6px" placeholder="Paste source material (specs, docs, audit notes). TRACE extracts candidate actors/roles/assets/invariants/edges, each with its source sentence as evidence."></textarea>
        <button class="btn sm" id="ai-extract" style="margin-top:6px">Extract candidates</button>
      </details>
      <div id="ai-out"></div>
    </div>

    <div class="tr-section">Model objects</div>
    <div class="cols" id="objcols">${OBJ_TYPES.map((t) => objBox(t, m.objects[t] || [])).join("")}</div>

    <div class="tr-section">STRIDE threats <span class="muted" style="font-weight:400;text-transform:none">&mdash; phase 3</span></div>
    <div id="threats">${threatsTable(m)}</div>

    <div class="tr-section">Collusion &amp; coordination <span class="muted" style="font-weight:400;text-transform:none">&mdash; phase 5</span></div>
    <div id="collusion">${collusionBox(m.collusion || [])}</div>`;

  $("back").onclick = loadList;
  wireDetail(m);
}

function phaseCard(p: any): string {
  return `<div class="ph ph-${esc(p.status)}">
    <div class="pn">PHASE ${p.phase}</div><div class="pt">${esc(p.name)}</div>
    <select class="in ph-sel" data-phase="${p.phase}">
      ${["pending", "in-progress", "approved"].map((s) => `<option value="${s}"${p.status === s ? " selected" : ""}>${s}</option>`).join("")}
    </select>
    ${p.approvedBy ? `<div class="ap">✓ ${esc(p.approvedBy)} · ${esc((p.approvedAt || "").slice(0, 10))}</div>` : ""}
  </div>`;
}

function objBox(type: string, items: any[]): string {
  const rows = items.map((o) => `<div class="obj" data-id="${o.id}">
    <span class="xdel" data-deltype="${type}" data-delid="${o.id}" title="delete">&#10005;</span>
    <span class="on">${esc(o.name)}</span>${o.assumption ? `<span class="badge-asm" title="inferred assumption">ASSUMP</span>` : (o.evidence ? `<span class="badge-ev" title="${esc(o.evidence)}">EVID</span>` : "")}
    <div class="od">${esc(objDesc(type, o))}</div>
    ${o.evidence ? `<div class="ev">“${esc(o.evidence)}”</div>` : ""}
  </div>`).join("") || `<div class="muted" style="font-size:11px;padding:4px 0">none</div>`;
  return `<div class="objbox" data-type="${type}">
    <h4>${esc(OBJ_TITLE[type])} <span class="ct">${items.length}</span></h4>
    ${rows}
    <button class="btn sec sm addobj" data-type="${type}" style="margin-top:7px">+ add</button>
    <div class="frm" data-form="${type}">${objForm(type)}</div>
  </div>`;
}
function objDesc(type: string, o: any): string {
  if (type === "actor") return [o.kind, o.capability, o.incentive].filter(Boolean).join(" · ");
  if (type === "role") return o.privilege || "";
  if (type === "asset") return [o.kind, o.value && `value: ${o.value}`].filter(Boolean).join(" · ");
  if (type === "invariant") return [o.statement, o.category && `[${o.category}]`].filter(Boolean).join(" ");
  if (type === "edge") return [`${o.fromdomain || "?"} → ${o.todomain || "?"}`, o.kind].filter(Boolean).join(" · ");
  return "";
}
function objForm(type: string): string {
  const fields = OBJ_FIELDS[type].map((f) => f.type === "ta"
    ? `<div style="grid-column:1/-1"><label>${esc(f.label)}</label><textarea class="in fld" data-k="${f.k}" style="min-height:50px"></textarea></div>`
    : `<div><label>${esc(f.label)}</label><input class="in fld" data-k="${f.k}"></div>`).join("");
  return `<div class="grid">${fields}<div><label>Evidence (source)</label><input class="in fld" data-k="evidence" placeholder="source ref / quote"></div></div>
    <div class="row"><label style="font-size:11px;color:#cbd5e1"><input type="checkbox" class="fld-asm"> inferred assumption (no source)</label>
    <button class="btn sm savedobj" data-type="${type}">Save</button></div>`;
}

function threatsTable(m: any): string {
  const objIndex: Record<string, Record<number, string>> = {};
  for (const t of OBJ_TYPES) { objIndex[t] = {}; for (const o of (m.objects[t] || [])) objIndex[t][o.id] = o.name; }
  const trace = (t: any) => t.traceType && t.traceId != null
    ? `<span class="traced">${esc(t.traceType)}: ${esc(objIndex[t.traceType]?.[t.traceId] || t.traceId)}</span>`
    : `<span class="untraced">untraced</span>`;
  const rows = (m.threats || []).map((t: any) => `<tr>
    <td>${esc(t.title)}</td>
    <td><span class="stride">${esc(t.stride || "—")}</span></td>
    <td class="imp-${esc(t.impact)}">${esc(t.impact || "—")}</td>
    <td>${esc(t.likelihood || "—")}</td>
    <td>${trace(t)}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">No threats yet. Add one below, or use “Propose STRIDE threats”.</td></tr>`;
  return `<table class="tt"><thead><tr><th>Threat</th><th>STRIDE</th><th>Impact</th><th>Likelihood</th><th>Traces to</th></tr></thead><tbody>${rows}</tbody></table>
    <button class="btn sec sm" id="addthreat" style="margin-top:8px">+ add threat</button>
    <div class="frm" id="threatform">
      <div class="grid">
        <div style="grid-column:1/-1"><label>Title</label><input class="in" id="th-title"></div>
        <div><label>STRIDE</label><select class="in" id="th-stride"><option value="">—</option>${REF.stride.map((s) => `<option>${esc(s)}</option>`).join("")}</select></div>
        <div><label>Impact</label><select class="in" id="th-impact"><option>Low</option><option>Medium</option><option>High</option><option>Critical</option></select></div>
        <div><label>Likelihood</label><select class="in" id="th-like"><option>Low</option><option>Medium</option><option>High</option></select></div>
        <div><label>Traces to</label><select class="in" id="th-trace">${traceOpts(m)}</select></div>
      </div>
      <button class="btn sm" id="th-save">Save threat</button>
    </div>`;
}
function traceOpts(m: any): string {
  let o = `<option value="">— untraced —</option>`;
  for (const t of OBJ_TYPES) for (const obj of (m.objects[t] || [])) o += `<option value="${t}:${obj.id}">${esc(t)}: ${esc(obj.name)}</option>`;
  return o;
}

function collusionBox(items: any[]): string {
  const rows = items.map((x) => `<div class="prop">
    <span class="pt"><b>${esc(x.actors)}</b>${x.quorum ? ` <span class="muted">— quorum: ${esc(x.quorum)}</span>` : ""}${x.credible ? ` <span class="badge-asm" style="background:#3a1620;color:#fca5a5">CREDIBLE</span>` : ""}${x.notes ? `<div class="muted" style="font-size:11px">${esc(x.notes)}</div>` : ""}</span>
    <button class="btn danger sm delcoll" data-id="${x.id}">&#10005;</button></div>`).join("") || `<div class="muted" style="font-size:12px">No collusion/coordination surfaces recorded.</div>`;
  return `${rows}
    <button class="btn sec sm" id="addcoll" style="margin-top:8px">+ add collusion surface</button>
    <div class="frm" id="collform">
      <div class="grid">
        <div style="grid-column:span 2"><label>Colluding actors</label><input class="in" id="co-actors" placeholder="e.g. 3 of 5 multisig signers"></div>
        <div><label>Quorum / threshold assumption</label><input class="in" id="co-quorum"></div>
      </div>
      <div class="row"><label style="font-size:11px;color:#cbd5e1"><input type="checkbox" id="co-credible"> credible</label>
        <input class="in" id="co-notes" placeholder="notes" style="flex:1">
        <button class="btn sm" id="co-save">Save</button></div>
    </div>`;
}

// ── wiring ─────────────────────────────────────────────────────────────────
function toggle(el: HTMLElement | null): void { if (el) el.classList.toggle("open"); }

function wireDetail(m: any): void {
  // phases
  document.querySelectorAll(".ph-sel").forEach((el) => {
    (el as HTMLSelectElement).onchange = async () => {
      const phase = Number((el as HTMLElement).dataset.phase);
      const out = await postJSON(`/api/trace/${CUR}/phase`, { phase, status: (el as HTMLSelectElement).value });
      if (!out.ok) { alert(out.error || "phase update failed"); }
      loadDetail(CUR);
    };
  });
  // object add toggles + saves
  document.querySelectorAll(".addobj").forEach((el) => { (el as HTMLElement).onclick = () => toggle(document.querySelector(`.frm[data-form="${(el as HTMLElement).dataset.type}"]`)); });
  document.querySelectorAll(".savedobj").forEach((el) => {
    (el as HTMLElement).onclick = async () => {
      const type = (el as HTMLElement).dataset.type!;
      const form = (el as HTMLElement).closest(".objbox")!.querySelector(`.frm[data-form="${type}"]`)!;
      const body: any = { type };
      form.querySelectorAll(".fld").forEach((i) => { body[(i as HTMLElement).dataset.k!] = (i as HTMLInputElement).value; });
      body.assumption = (form.querySelector(".fld-asm") as HTMLInputElement)?.checked || false;
      if (!body.name) return;
      await postJSON(`/api/trace/${CUR}/object`, body);
      loadDetail(CUR);
    };
  });
  document.querySelectorAll(".xdel").forEach((el) => {
    (el as HTMLElement).onclick = async (e) => {
      e.stopPropagation();
      if (!confirm("Delete this object?")) return;
      await delJSON(`/api/trace/object/${(el as HTMLElement).dataset.deltype}/${(el as HTMLElement).dataset.delid}`);
      loadDetail(CUR);
    };
  });
  // threats
  $("addthreat").onclick = () => toggle($("threatform"));
  $("th-save").onclick = async () => {
    const title = ($("th-title") as HTMLInputElement).value.trim(); if (!title) return;
    const [tt, ti] = (($("th-trace") as HTMLSelectElement).value || ":").split(":");
    await postJSON(`/api/trace/${CUR}/threat`, { title, stride: ($("th-stride") as HTMLSelectElement).value, impact: ($("th-impact") as HTMLSelectElement).value, likelihood: ($("th-like") as HTMLSelectElement).value, traceType: tt || undefined, traceId: ti ? Number(ti) : undefined });
    loadDetail(CUR);
  };
  // collusion
  $("addcoll").onclick = () => toggle($("collform"));
  $("co-save").onclick = async () => {
    const actors = ($("co-actors") as HTMLInputElement).value.trim(); if (!actors) return;
    await postJSON(`/api/trace/${CUR}/collusion`, { actors, quorum: ($("co-quorum") as HTMLInputElement).value, credible: ($("co-credible") as HTMLInputElement).checked, notes: ($("co-notes") as HTMLInputElement).value });
    loadDetail(CUR);
  };
  document.querySelectorAll(".delcoll").forEach((el) => { (el as HTMLElement).onclick = async () => { await delJSON(`/api/trace/collusion/${(el as HTMLElement).dataset.id}`); loadDetail(CUR); }; });
  // AI
  $("ai-stride").onclick = async () => { aiOut("Proposing STRIDE threats…"); const d = await postJSON(`/api/trace/${CUR}/ai/stride`, {}); renderProposals(d); };
  $("ai-report").onclick = async () => { aiOut("Generating report…"); const d = await postJSON(`/api/trace/${CUR}/ai/report`, {}); aiOut(mdLite(d.report || "(no report)") + tag(d)); };
  $("ai-extract").onclick = async () => {
    const text = ($("ai-src") as HTMLTextAreaElement).value.trim(); if (!text) return;
    aiOut("Extracting candidates…");
    const d = await postJSON("/api/trace/ai/extract", { text, pillar: m.model.pillar });
    renderExtract(d);
  };
}

function aiOut(html: string): void { $("ai-out").innerHTML = `<div class="ai-out">${html}</div>`; }
function tag(d: any): string { return `<div class="muted" style="font-size:10px;margin-top:8px">${d.offline ? "offline/deterministic" : "AI"} · ${esc(d.model || "")}</div>`; }
function mdLite(s: string): string {
  return esc(s).replace(/^### (.*)$/gm, "<b style='font-size:14px'>$1</b>").replace(/^## (.*)$/gm, "<b style='font-size:14px'>$1</b>")
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/^- /gm, "• ");
}

function renderProposals(d: any): void {
  const ps = (d.proposals || []) as any[];
  if (!ps.length) { aiOut("No new STRIDE proposals — add some assets/edges/roles first, then retry." + tag(d)); return; }
  const rows = ps.map((p, i) => `<div class="prop"><span class="pt"><span class="stride">${esc(p.stride)}</span> ${esc(p.title)} <span class="muted" style="font-size:10px">(${esc(p.impact)}/${esc(p.likelihood)})</span></span>
    <button class="btn sm acc-prop" data-i="${i}">accept</button></div>`).join("");
  aiOut(`<b>${ps.length} STRIDE candidates</b> <button class="btn sm" id="acc-all" style="float:right">accept all</button><div style="margin:6px 0">${esc(d.commentary || "")}</div>${rows}${tag(d)}`);
  const accept = async (p: any) => { await postJSON(`/api/trace/${CUR}/threat`, { title: p.title, stride: p.stride, impact: p.impact, likelihood: p.likelihood, traceType: p.traceType, traceId: p.traceId }); };
  document.querySelectorAll(".acc-prop").forEach((el) => { (el as HTMLElement).onclick = async () => { await accept(ps[Number((el as HTMLElement).dataset.i)]); (el as HTMLButtonElement).textContent = "✓"; (el as HTMLButtonElement).disabled = true; }; });
  $("acc-all").onclick = async () => { for (const p of ps) await accept(p); loadDetail(CUR); };
}

function renderExtract(d: any): void {
  const o = d.objects || {};
  const total = OBJ_TYPES.reduce((a, t) => a + (o[t] || []).length, 0);
  if (!total) { aiOut("No candidates extracted." + tag(d)); return; }
  const blocks = OBJ_TYPES.filter((t) => (o[t] || []).length).map((t) => `<div style="margin-top:6px"><b>${esc(OBJ_TITLE[t])}</b> (${o[t].length})<br>${o[t].map((x: any, i: number) =>
    `<div class="prop"><span class="pt">${esc(x.name)}${x.evidence ? ` <span class="muted" style="font-size:10px">“${esc(String(x.evidence).slice(0, 80))}”</span>` : ""}</span><button class="btn sm acc-ext" data-t="${t}" data-i="${i}">add</button></div>`).join("")}</div>`).join("");
  aiOut(`<div style="color:#fbbf24;font-size:11px;margin-bottom:6px">${esc(d.note || "")}</div><b>${total} candidate objects</b> <button class="btn sm" id="acc-extall" style="float:right">add all</button>${blocks}${tag(d)}`);
  const add = async (t: string, x: any) => { await postJSON(`/api/trace/${CUR}/object`, { type: t, ...x, assumption: !!x.assumption }); };
  document.querySelectorAll(".acc-ext").forEach((el) => { (el as HTMLElement).onclick = async () => { const t = (el as HTMLElement).dataset.t!; await add(t, o[t][Number((el as HTMLElement).dataset.i)]); (el as HTMLButtonElement).textContent = "✓"; (el as HTMLButtonElement).disabled = true; }; });
  $("acc-extall").onclick = async () => { for (const t of OBJ_TYPES) for (const x of (o[t] || [])) await add(t, x); loadDetail(CUR); };
}

loadList().catch((e) => { $("tr-body").innerHTML = `<div class="muted" style="padding:20px">Failed to load: ${esc(String(e))}</div>`; });
