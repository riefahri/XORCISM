/**
 * tprm.ts — Third-Party Risk Management cockpit (Panorays / Vendict style). Vendor inventory with
 * inherent-risk tier, outside-in posture grade, security-questionnaire conformance, combined residual
 * risk, findings, and local-AI copilots (vendor brief, questionnaire review, auto-draft answers).
 * Reads /api/tprm.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
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
        <span class="tier ${tierCls(v.tier)}">${fmt("tp.inherentTier", { t: esc(v.tier || "—") })}</span>
        <span>🔐 ${v.conformance != null ? fmt("tp.conformancePct", { n: v.conformance }) : t("tp.questPending")}</span>
        ${v.openFindings ? `<span>⚠ ${fmt("tp.openN", { n: v.openFindings })}</span>` : ""}
        ${v.overdue ? `<span class="pill pill-warn">${t("tp.reviewOverdue")}</span>` : (v.nextReview ? `<span>${fmt("tp.reviewOn", { d: esc(v.nextReview) })}</span>` : "")}
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
    card(t("tp.cVendors"), String(s.vendors), fmt("tp.cVendors.foot", { n: s.assessed })),
    card(t("tp.cAvgResidual"), String(s.avgResidual), t("tp.cAvgResidual.foot"), riskColor(s.avgResidual)),
    card(t("tp.cCritical"), String(s.critical), t("tp.cCritical.foot"), s.critical ? "#f87171" : undefined),
    card(t("tp.cUsingAI"), String(s.usingAI), t("tp.cUsingAI.foot"), s.usingAI ? "#c7d2fe" : undefined),
    card(t("tp.cOpenFindings"), String(s.openFindings), fmt("tp.cOpenFindings.foot", { n: s.overdue }), s.overdue ? "#fbbf24" : undefined),
  ].join("");
  const list = d.vendors.length ? d.vendors.map(vendorRow).join("") : `<div class="muted" style="padding:10px 0">${t("tp.noVendors")}</div>`;
  $("tp-body").innerHTML = `<div class="tp-cards">${cards}</div>
    <div class="tp-section">${fmt("tp.secPortfolio", { n: d.vendors.length })}<span class="spacer"></span><button class="btn2 go" id="tp-new">${t("tp.newVendor")}</button></div>
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
  if (!name) { toast(t("tp.errName")); return; }
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
    .then((j) => { closeModal(); toast(t("tp.vendorCreated")); reload().then(() => openVendor(j.id)); })
    .catch((e) => toast("⚠️ " + (e.message || e)))
    .finally(() => { btn.disabled = false; });
}

// ── vendor detail ──
function findingRow(f: Finding): string {
  const opts = ["open", "accepted", "remediated", "false-positive"].map((o) => `<option value="${o}"${f.status === o ? " selected" : ""}>${t("tp.fst." + o)}</option>`).join("");
  return `<div class="fnd st-${esc(f.status)}" data-fid="${f.id}">
    <span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span>
    <div class="ft"><b>${esc(f.title)}</b>${f.detail ? `<span>${esc(f.detail)}</span>` : ""}<span class="src">${esc(f.source)} · ${esc(f.category)}${f.createdDate ? ` · ${esc(f.createdDate)}` : ""}</span></div>
    <select class="fnd-status" data-fid="${f.id}">${opts}</select>
  </div>`;
}

function openVendor(id: number): void {
  $("tp-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("tp.loadingVendor")}</div>`;
  fetch("/api/tprm/vendor/" + id).then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: { vendor: Vendor; findings: Finding[]; run: any }) => {
    const v = d.vendor;
    const residual = v.residualRisk ?? v.inherentRisk ?? 0;
    const runs = DATA!.questionnaireRuns;
    const runOpts = [`<option value="">${t("tp.linkRunOpt")}</option>`]
      .concat(runs.map((r) => `<option value="${r.id}"${v.questionnaireRunId === r.id ? " selected" : ""}>${esc(r.name)}${r.conformance != null ? ` (${r.conformance}%)` : ""}</option>`)).join("");
    const cards = [
      card(t("tp.dInherent"), String(v.inherentRisk ?? "—"), fmt("tp.dInherent.foot", { t: esc(v.tier), data: esc(v.dataSensitivity), crit: esc(v.businessCriticality) }), riskColor(v.inherentRisk ?? 0)),
      `<div class="tp-card"><div class="lbl">${t("tp.dPosture")}</div><div class="val"><span class="grade ${gradeCls(v.postureGrade)}" style="display:inline-flex">${esc(v.postureGrade || "—")}</span></div><div class="foot">${v.postureScore != null ? `${v.postureScore}/100` : t("tp.notScanned")}</div></div>`,
      card(t("tp.dQuestionnaire"), v.conformance != null ? `${v.conformance}%` : "—", v.conformance != null ? t("tp.conformance") : t("tp.notAssessed"), v.conformance != null ? riskColor(100 - v.conformance) : undefined),
      card(t("tp.dResidual"), String(residual), esc(v.residualTier) + " · " + fmt("tp.reviewOn", { d: v.nextReview || "—" }), riskColor(residual)),
    ].join("");
    $("tp-body").innerHTML = `
      <div class="tp-section"><button class="btn2" id="tp-back">${t("tp.allVendors")}</button><span class="spacer"></span>
        <button class="btn2" id="tp-del" style="border-color:#7f1d1d;color:#fca5a5">${t("tp.delete")}</button></div>
      <h2 style="font-size:18px;margin:6px 0 2px">${esc(v.name)} ${v.usesAI ? '<span class="ai-badge">AI</span>' : ""} <span class="tier ${tierCls(v.residualTier)}">${fmt("tp.residualTier", { t: esc(v.residualTier) })}</span></h2>
      <div class="muted" style="font-size:12.5px;margin-bottom:6px">
        ${v.domain ? `🌐 ${esc(v.domain)} · ` : ""}${esc(v.category || "—")}${v.services ? ` · ${esc(v.services)}` : ""}${v.owner ? ` · 👤 ${esc(v.owner)}` : ""} · ${fmt("tp.statusLbl", { s: esc(v.status) })}
        ${v.usesAI && v.aiUse ? `<br><b style="color:#94a3b8">${t("tp.aiUse")}</b> ${esc(v.aiUse)}` : ""}</div>
      <div class="tp-cards">${cards}</div>
      <div class="acts">
        <button class="btn2 go" id="a-assess">${t("tp.assessBtn")}</button>
        <select class="btn2" id="a-link" style="padding:7px 10px">${runOpts}</select>
        <button class="btn2 ai" id="a-brief">${t("tp.aiBriefBtn")}</button>
        ${v.questionnaireRunId ? `<button class="btn2 ai" id="a-review">${t("tp.aiReviewBtn")}</button>` : ""}
        <button class="btn2 ai" id="a-draft">${t("tp.aiDraftBtn")}</button>
        <button class="btn2" id="a-finding">${t("tp.addFindingBtn")}</button>
      </div>
      <div id="ai-panel"></div>
      <div class="panel"><div class="ph">${fmt("tp.findingsPanel", { n: d.findings.length })}</div>
        <div id="fnd-list">${d.findings.length ? d.findings.map(findingRow).join("") : `<div class="muted" style="padding:12px 14px">${t("tp.noFindings")}</div>`}</div></div>`;
    $("tp-back").onclick = () => reload().then(renderOverview);
    $("tp-del").onclick = () => { if (!confirm(t("tp.confirmDelete"))) return; api("DELETE", "/api/tprm/vendor/" + id).then(() => reload().then(renderOverview)).then(() => toast(t("tp.vendorDeleted"))); };
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
  toast(t("tp.scanning"));
  api("POST", "/api/tprm/vendor/" + id + "/assess").then((r) => {
    toast(r.ok ? fmt("tp.postureResult", { grade: r.grade, posture: r.posture, n: r.findings }) : `⚠️ ${r.error}`);
    openVendor(id);
  }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function linkRun(id: number, runId: string): void {
  api("POST", "/api/tprm/vendor/" + id + "/link-run", { runId: runId || null }).then(() => { toast(t("tp.questLinked")); openVendor(id); }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function addFinding(id: number): void {
  const title = prompt(t("tp.promptFindingTitle")); if (!title) return;
  const severity = (prompt(t("tp.promptSeverity"), "medium") || "medium").toLowerCase();
  api("POST", "/api/tprm/vendor/" + id + "/finding", { title, severity, source: "manual", category: "Manual" }).then(() => { toast(t("tp.findingAdded")); openVendor(id); }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function aiPanel(title: string, content: string, offline: boolean): void {
  $("ai-panel").innerHTML = `<div class="panel"><div class="ph">🤖 ${esc(title)}${offline ? ` <span class="pill">${t("tp.offlineDraft")}</span>` : ` <span class="pill" style="background:#14532d;color:#bbf7d0">${t("tp.localAI")}</span>`}</div><div class="ai-out">${mdLite(content)}</div></div>`;
  $("ai-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
}
function aiLoading(title: string): void { $("ai-panel").innerHTML = `<div class="panel"><div class="ph">🤖 ${esc(title)}</div><div class="ai-out muted">${t("tp.thinking")}</div></div>`; }

function aiBrief(v: Vendor, findings: Finding[]): void {
  aiLoading(t("tp.aiBriefTitle"));
  api("POST", "/api/ai/tprm-vendor-brief", {
    name: v.name, services: v.services, domain: v.domain, dataSensitivity: v.dataSensitivity, businessCriticality: v.businessCriticality,
    tier: v.tier, postureScore: v.postureScore, postureGrade: v.postureGrade, conformance: v.conformance, residualTier: v.residualTier,
    usesAI: v.usesAI, aiUse: v.aiUse, findings: findings.map((f) => ({ title: f.title, severity: f.severity, detail: f.detail })),
  }).then((r) => aiPanel(t("tp.aiBriefTitle"), r.content, r.offline)).catch((e) => toast("⚠️ " + (e.message || e)));
}
function aiReview(runId: number): void {
  aiLoading(t("tp.aiReviewTitle"));
  api("POST", "/api/ai/tprm-review-questionnaire", { runId }).then((r) => aiPanel(t("tp.aiReviewTitle"), r.content, r.offline)).catch((e) => toast("⚠️ " + (e.message || e)));
}
function aiDraft(v: Vendor): void {
  if (!v.questionnaireRunId) { toast(t("tp.linkFirst")); return; }
  const knowledge = prompt(t("tp.promptKnowledge")) || "";
  aiLoading(t("tp.aiDraftTitle"));
  api("POST", "/api/ai/tprm-draft-answers", { runId: v.questionnaireRunId, knowledge }).then((r) => aiPanel(t("tp.aiDraftTitle"), r.content, r.offline)).catch((e) => toast("⚠️ " + (e.message || e)));
}

function reload(): Promise<void> {
  return fetch("/api/tprm").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => { DATA = d; });
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("tp-cancel").onclick = closeModal;
  $("tp-create").onclick = createVendor;
  $("tp-modal").addEventListener("click", (e) => { if (e.target === $("tp-modal")) closeModal(); });
  reload().then(renderOverview).catch((e) => { $("tp-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
});
