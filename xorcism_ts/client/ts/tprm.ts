/**
 * tprm.ts — Third-Party Risk Management cockpit (Panorays / Vendict style). Vendor inventory with
 * inherent-risk tier, outside-in posture grade, security-questionnaire conformance, combined residual
 * risk, findings, and local-AI copilots (vendor brief, questionnaire review, auto-draft answers).
 * Reads /api/tprm.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const e = $("toast"); e.textContent = m; e.className = "show"; setTimeout(() => { e.className = ""; }, 3000); }
function mdLite(s: string): string {
  return esc(s)
    .replace(/^### (.*)$/gm, '<b style="color:#cbd5e1">$1</b>')
    .replace(/^## (.*)$/gm, '<b style="color:#e7ebf3;font-size:14px">$1</b>')
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
    .replace(/^\s*[-*] /gm, "• ");
}

interface Vendor {
  id: number; name: string; domain: string; category: string; services: string; owner: string; contactEmail: string;
  status: string; tier: string; dataSensitivity: string; businessCriticality: string; usesAI: boolean; aiUse: string;
  inherentRisk: number | null; postureScore: number | null; postureGrade: string;
  questionnaireRunId: number | null; conformance: number | null; residualRisk: number | null; residualTier: string;
  lastAssessed: string; nextReview: string; reviewCadenceDays: number | null; overdue: boolean; openFindings?: number;
}
interface Finding { id: number; source: string; category: string; title: string; detail: string; severity: string; status: string; createdDate: string; }
interface RunLite { id: number; name: string; questionnaire: string; subject: string; conformance: number | null; status: string; }
interface Data { vendors: Vendor[]; questionnaireRuns: RunLite[]; summary: any }

let DATA: Data | null = null;

const tierCls = (t: string): string => `tier-${["Critical", "High", "Medium", "Low"].includes(t) ? t : "Low"}`;
const gradeCls = (g: string): string => g ? `g-${g}` : "g-none";
const riskColor = (n: number): string => n >= 75 ? "#ef4444" : n >= 50 ? "#fb923c" : n >= 25 ? "#fbbf24" : "#4ade80";
function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="tp-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}

function vendorRow(v: Vendor): string {
  const residual = v.residualRisk ?? v.inherentRisk ?? 0;
  const grade = v.postureGrade || "—";
  return `<div class="vn" data-id="${v.id}">
    <span class="grade ${gradeCls(v.postureGrade)}" title="External posture grade">${esc(grade)}</span>
    <div class="grow">
      <span class="nm">${esc(v.name)}</span> ${v.domain ? `<span class="dom">${esc(v.domain)}</span>` : ""}
      ${v.usesAI ? '<span class="ai-badge">AI</span>' : ""}
      <div class="meta">
        <span>${esc(v.category || "—")}</span>
        <span class="tier ${tierCls(v.tier)}">${esc(v.tier || "—")} inherent</span>
        <span>🔐 ${v.conformance != null ? `${v.conformance}% conformance` : "questionnaire pending"}</span>
        ${v.openFindings ? `<span>⚠ ${v.openFindings} open</span>` : ""}
        ${v.overdue ? '<span class="pill pill-warn">review overdue</span>' : (v.nextReview ? `<span>review ${esc(v.nextReview)}</span>` : "")}
      </div>
    </div>
    <span class="tier ${tierCls(v.residualTier)}">${esc(v.residualTier || "—")}</span>
    <div class="rbar"><i style="width:${Math.max(4, Math.min(100, residual))}%;background:${riskColor(residual)}"></i></div>
    <span class="pct" style="color:${riskColor(residual)}">${residual}</span>
  </div>`;
}

function renderOverview(): void {
  const d = DATA!; const s = d.summary;
  const cards = [
    card("Vendors", String(s.vendors), `${s.assessed} assessed`),
    card("Avg. residual risk", String(s.avgResidual), "across active vendors", riskColor(s.avgResidual)),
    card("Critical-tier", String(s.critical), "highest residual", s.critical ? "#f87171" : undefined),
    card("Using AI", String(s.usingAI), "in scope for AI-TRiSM", s.usingAI ? "#c7d2fe" : undefined),
    card("Open findings", String(s.openFindings), `${s.overdue} reviews overdue`, s.overdue ? "#fbbf24" : undefined),
  ].join("");
  const list = d.vendors.length ? d.vendors.map(vendorRow).join("") : '<div class="muted" style="padding:10px 0">No vendors yet — add your first third party.</div>';
  $("tp-body").innerHTML = `<div class="tp-cards">${cards}</div>
    <div class="tp-section">Vendor portfolio (${d.vendors.length})<span class="spacer"></span><button class="btn2 go" id="tp-new">+ New vendor</button></div>
    ${list}`;
  $("tp-new").onclick = openModal;
  Array.prototype.forEach.call(document.querySelectorAll(".vn"), (el: HTMLElement) => { el.onclick = () => openVendor(Number(el.getAttribute("data-id"))); });
}

// ── new-vendor modal ──
function openModal(): void {
  ["f-name", "f-domain", "f-category", "f-services", "f-owner", "f-contact", "f-aiuse"].forEach((i) => { ($(i) as HTMLInputElement).value = ""; });
  ($("f-ai") as HTMLInputElement).checked = false;
  ($("f-data") as HTMLSelectElement).value = "Confidential";
  ($("f-crit") as HTMLSelectElement).value = "Medium";
  $("tp-modal").classList.add("show");
}
function closeModal(): void { $("tp-modal").classList.remove("show"); }
function createVendor(): void {
  const name = ($("f-name") as HTMLInputElement).value.trim();
  if (!name) { toast("⚠️ Vendor name required"); return; }
  const body = {
    name, domain: ($("f-domain") as HTMLInputElement).value.trim(), category: ($("f-category") as HTMLInputElement).value.trim(),
    services: ($("f-services") as HTMLInputElement).value.trim(), owner: ($("f-owner") as HTMLInputElement).value.trim(),
    contactEmail: ($("f-contact") as HTMLInputElement).value.trim(),
    dataSensitivity: ($("f-data") as HTMLSelectElement).value, businessCriticality: ($("f-crit") as HTMLSelectElement).value,
    usesAI: ($("f-ai") as HTMLInputElement).checked, aiUse: ($("f-aiuse") as HTMLInputElement).value.trim(),
  };
  const btn = $("tp-create") as HTMLButtonElement; btn.disabled = true;
  fetch("/api/tprm/vendor", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((j) => { closeModal(); toast("✓ Vendor created"); reload().then(() => openVendor(j.id)); })
    .catch((e) => toast("⚠️ " + (e.message || e)))
    .finally(() => { btn.disabled = false; });
}

// ── vendor detail ──
function findingRow(f: Finding): string {
  const opts = ["open", "accepted", "remediated", "false-positive"].map((o) => `<option value="${o}"${f.status === o ? " selected" : ""}>${o}</option>`).join("");
  return `<div class="fnd st-${esc(f.status)}" data-fid="${f.id}">
    <span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span>
    <div class="ft"><b>${esc(f.title)}</b>${f.detail ? `<span>${esc(f.detail)}</span>` : ""}<span class="src">${esc(f.source)} · ${esc(f.category)}${f.createdDate ? ` · ${esc(f.createdDate)}` : ""}</span></div>
    <select class="fnd-status" data-fid="${f.id}">${opts}</select>
  </div>`;
}

function openVendor(id: number): void {
  $("tp-body").innerHTML = '<div class="muted" style="padding:24px;text-align:center">Loading vendor…</div>';
  fetch("/api/tprm/vendor/" + id).then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: { vendor: Vendor; findings: Finding[]; run: any }) => {
    const v = d.vendor;
    const residual = v.residualRisk ?? v.inherentRisk ?? 0;
    const runs = DATA!.questionnaireRuns;
    const runOpts = ['<option value="">— link a questionnaire run —</option>']
      .concat(runs.map((r) => `<option value="${r.id}"${v.questionnaireRunId === r.id ? " selected" : ""}>${esc(r.name)}${r.conformance != null ? ` (${r.conformance}%)` : ""}</option>`)).join("");
    const cards = [
      card("Inherent risk", String(v.inherentRisk ?? "—"), `${esc(v.tier)} · data ${esc(v.dataSensitivity)} × ${esc(v.businessCriticality)}`, riskColor(v.inherentRisk ?? 0)),
      `<div class="tp-card"><div class="lbl">External posture</div><div class="val"><span class="grade ${gradeCls(v.postureGrade)}" style="display:inline-flex">${esc(v.postureGrade || "—")}</span></div><div class="foot">${v.postureScore != null ? `${v.postureScore}/100` : "not scanned"}</div></div>`,
      card("Questionnaire", v.conformance != null ? `${v.conformance}%` : "—", v.conformance != null ? "conformance" : "not assessed", v.conformance != null ? riskColor(100 - v.conformance) : undefined),
      card("Residual risk", String(residual), esc(v.residualTier) + " · review " + (v.nextReview || "—"), riskColor(residual)),
    ].join("");
    $("tp-body").innerHTML = `
      <div class="tp-section"><button class="btn2" id="tp-back">← All vendors</button><span class="spacer"></span>
        <button class="btn2" id="tp-del" style="border-color:#7f1d1d;color:#fca5a5">Delete</button></div>
      <h2 style="font-size:18px;margin:6px 0 2px">${esc(v.name)} ${v.usesAI ? '<span class="ai-badge">AI</span>' : ""} <span class="tier ${tierCls(v.residualTier)}">${esc(v.residualTier)} residual</span></h2>
      <div class="muted" style="font-size:12.5px;margin-bottom:6px">
        ${v.domain ? `🌐 ${esc(v.domain)} · ` : ""}${esc(v.category || "—")}${v.services ? ` · ${esc(v.services)}` : ""}${v.owner ? ` · 👤 ${esc(v.owner)}` : ""} · status: ${esc(v.status)}
        ${v.usesAI && v.aiUse ? `<br><b style="color:#94a3b8">AI use:</b> ${esc(v.aiUse)}` : ""}</div>
      <div class="tp-cards">${cards}</div>
      <div class="acts">
        <button class="btn2 go" id="a-assess">🛰️ Assess external posture</button>
        <select class="btn2" id="a-link" style="padding:7px 10px">${runOpts}</select>
        <button class="btn2 ai" id="a-brief">🤖 AI vendor brief</button>
        ${v.questionnaireRunId ? '<button class="btn2 ai" id="a-review">🤖 AI questionnaire review</button>' : ""}
        <button class="btn2 ai" id="a-draft">🤖 AI draft answers</button>
        <button class="btn2" id="a-finding">+ Finding</button>
      </div>
      <div id="ai-panel"></div>
      <div class="panel"><div class="ph">⚠ Findings (${d.findings.length})</div>
        <div id="fnd-list">${d.findings.length ? d.findings.map(findingRow).join("") : '<div class="muted" style="padding:12px 14px">No findings — run the external assessment or the questionnaire.</div>'}</div></div>`;
    $("tp-back").onclick = () => reload().then(renderOverview);
    $("tp-del").onclick = () => { if (!confirm("Delete this vendor and its findings?")) return; api("DELETE", "/api/tprm/vendor/" + id).then(() => reload().then(renderOverview)).then(() => toast("✓ Vendor deleted")); };
    $("a-assess").onclick = () => assess(id);
    ($("a-link") as HTMLSelectElement).onchange = (e) => linkRun(id, (e.target as HTMLSelectElement).value);
    $("a-brief").onclick = () => aiBrief(v, d.findings);
    $("a-draft").onclick = () => aiDraft(v);
    const rev = document.getElementById("a-review"); if (rev) rev.onclick = () => aiReview(v.questionnaireRunId!);
    $("a-finding").onclick = () => addFinding(id);
    Array.prototype.forEach.call(document.querySelectorAll(".fnd-status"), (sel: HTMLSelectElement) => {
      sel.onchange = () => api("POST", "/api/tprm/finding/" + sel.getAttribute("data-fid"), { status: sel.value }).then(() => openVendor(id));
    });
  }).catch((e) => { $("tp-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function api(method: string, url: string, body?: any): Promise<any> {
  return fetch(url, { method, headers: body ? { "Content-Type": "application/json" } : undefined, body: body ? JSON.stringify(body) : undefined })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }));
}

function assess(id: number): void {
  toast("🛰️ Scanning the vendor's external surface…");
  api("POST", "/api/tprm/vendor/" + id + "/assess").then((r) => {
    toast(r.ok ? `✓ Posture: grade ${r.grade} (${r.posture}/100) · ${r.findings} issue(s)` : `⚠️ ${r.error}`);
    openVendor(id);
  }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function linkRun(id: number, runId: string): void {
  api("POST", "/api/tprm/vendor/" + id + "/link-run", { runId: runId || null }).then(() => { toast("✓ Questionnaire linked"); openVendor(id); }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function addFinding(id: number): void {
  const title = prompt("Finding title (e.g. 'No SOC 2 report')"); if (!title) return;
  const severity = (prompt("Severity: critical / high / medium / low / info", "medium") || "medium").toLowerCase();
  api("POST", "/api/tprm/vendor/" + id + "/finding", { title, severity, source: "manual", category: "Manual" }).then(() => { toast("✓ Finding added"); openVendor(id); }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function aiPanel(title: string, content: string, offline: boolean): void {
  $("ai-panel").innerHTML = `<div class="panel"><div class="ph">🤖 ${esc(title)}${offline ? ' <span class="pill">offline draft</span>' : ' <span class="pill" style="background:#14532d;color:#bbf7d0">local AI</span>'}</div><div class="ai-out">${mdLite(content)}</div></div>`;
  $("ai-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
}
function aiLoading(title: string): void { $("ai-panel").innerHTML = `<div class="panel"><div class="ph">🤖 ${esc(title)}</div><div class="ai-out muted">Thinking… (local model; deterministic draft if Ollama is offline)</div></div>`; }

function aiBrief(v: Vendor, findings: Finding[]): void {
  aiLoading("Vendor risk brief");
  api("POST", "/api/ai/tprm-vendor-brief", {
    name: v.name, services: v.services, domain: v.domain, dataSensitivity: v.dataSensitivity, businessCriticality: v.businessCriticality,
    tier: v.tier, postureScore: v.postureScore, postureGrade: v.postureGrade, conformance: v.conformance, residualTier: v.residualTier,
    usesAI: v.usesAI, aiUse: v.aiUse, findings: findings.map((f) => ({ title: f.title, severity: f.severity, detail: f.detail })),
  }).then((r) => aiPanel("Vendor risk brief", r.content, r.offline)).catch((e) => toast("⚠️ " + (e.message || e)));
}
function aiReview(runId: number): void {
  aiLoading("Questionnaire review");
  api("POST", "/api/ai/tprm-review-questionnaire", { runId }).then((r) => aiPanel("Questionnaire review", r.content, r.offline)).catch((e) => toast("⚠️ " + (e.message || e)));
}
function aiDraft(v: Vendor): void {
  if (!v.questionnaireRunId) { toast("⚠️ Link a questionnaire run first"); return; }
  const knowledge = prompt("Paste the vendor's knowledge base (policies, prior answers, control descriptions) to auto-draft answers from:") || "";
  aiLoading("Auto-drafted answers");
  api("POST", "/api/ai/tprm-draft-answers", { runId: v.questionnaireRunId, knowledge }).then((r) => aiPanel("Auto-drafted answers", r.content, r.offline)).catch((e) => toast("⚠️ " + (e.message || e)));
}

function reload(): Promise<void> {
  return fetch("/api/tprm").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => { DATA = d; });
}

document.addEventListener("DOMContentLoaded", () => {
  $("tp-cancel").onclick = closeModal;
  $("tp-create").onclick = createVendor;
  $("tp-modal").addEventListener("click", (e) => { if (e.target === $("tp-modal")) closeModal(); });
  reload().then(renderOverview).catch((e) => { $("tp-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
});
