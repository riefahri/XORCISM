/**
 * zero-trust.ts — Zero Trust cockpit (CISA ZTMM v2.0). Per-pillar maturity (live signals or the
 * latest assessment), a fused trust score worklist (NIST 800-207), and a maturity assessment with
 * a 4-stage picker per function. Reads /api/zero-trust.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const e = $("toast"); e.textContent = m; e.className = "show"; setTimeout(() => { e.className = ""; }, 3000); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

const stIdx = (s: number) => Math.max(0, Math.min(3, Math.round(s)));
const stageLabel = (i: number): string => [t("zt.stage0"), t("zt.stage1"), t("zt.stage2"), t("zt.stage3")][stIdx(i)];

interface Pillar { pillarKey: string; name: string; cross: boolean; currentStage: number; currentLabel: string; targetStage: number; pct: number; signalStage: number; signalPct: number; signalBasis: string; source: string; }
interface TrustEnt { type: string; id: number; name: string; trust: number; tier: string; reasons: string[]; }
interface Data { pillars: Pillar[]; overall: { stage: number; label: string; pct: number }; trust: any; trustWorklist: TrustEnt[]; ueba: { summary: any; worklist: any[] }; policies: any[]; policiesSummary: any; assessments: any[]; hasAssessment: boolean; gaps: Pillar[]; }

let DATA: Data | null = null;

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="zt-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const trustColor = (t: number): string => t >= 80 ? "#4ade80" : t >= 60 ? "#60a5fa" : t >= 40 ? "#fbbf24" : "#f87171";

function pillarRow(p: Pillar): string {
  const st = stIdx(p.currentStage);
  return `<div class="pil">
    <span class="nm">${esc(p.name)}${p.cross ? `<span class="cross">${t("zt.crossCut")}</span>` : ""}</span>
    <div class="track">
      <div class="stagebar"><i class="b${st}" style="width:${Math.max(3, p.pct)}%"></i></div>
      <div class="stageticks"><span>${esc(stageLabel(0))}</span><span>${esc(stageLabel(1))}</span><span>${esc(stageLabel(2))}</span><span>${esc(stageLabel(3))}</span></div>
      <div class="basis">${esc(p.signalBasis)}</div>
    </div>
    <div class="stg">
      <span class="s${st}">${esc(stageLabel(st))}</span><br>
      <span class="src src-${p.source === "assessment" ? "assessment" : "live"}">${p.source === "assessment" ? t("zt.badgeAssessed") : t("zt.badgeLive")}</span>
    </div>
  </div>`;
}

function trustRow(e: TrustEnt): string {
  return `<div class="te">
    <span class="ty ty-${esc(e.type)}">${esc(e.type)}</span>
    <span class="tn">${esc(e.name)}</span>
    <span class="tr">${e.reasons.length ? esc(e.reasons.join(" · ")) : "—"}</span>
    <span class="tier tier-${esc(e.tier)}">${esc(e.tier)}</span>
    <span class="tscore" style="color:${trustColor(e.trust)}">${e.trust}</span>
  </div>`;
}

function renderOverview(): void {
  const d = DATA!; const o = d.overall; const tr = d.trust;
  const gap = d.gaps[0];
  const cards = [
    card(t("zt.cMaturity"), `${esc(stageLabel(o.stage))}`, fmt("zt.cMaturity.foot", { s: o.stage, p: o.pct }), o.pct >= 67 ? "#4ade80" : o.pct >= 34 ? "#fbbf24" : "#f87171"),
    card(t("zt.cTrust"), String(tr.overall), fmt("zt.cTrust.foot", { tier: esc(tr.tier), n: tr.entities }), trustColor(tr.overall)),
    card(t("zt.cLowTrust"), String(tr.low), fmt("zt.cLowTrust.foot", { i: tr.identities.count, a: tr.devices.count }), tr.low ? "#f87171" : "#4ade80"),
    card(t("zt.cGap"), gap ? esc(gap.name) : "—", gap ? `${stageLabel(gap.currentStage)} → ${stageLabel(gap.targetStage)}` : t("zt.cGap.atTarget"), gap ? "#fbbf24" : "#4ade80"),
  ].join("");
  const pillars = d.pillars.map(pillarRow).join("");
  const work = d.trustWorklist.length ? d.trustWorklist.map(trustRow).join("") : `<div class="muted" style="padding:12px 14px">${t("zt.noLowTrust")}</div>`;
  const u = d.ueba || { summary: {}, worklist: [] };
  const us = u.summary || {};
  const uebaColor = (r: number) => r >= 50 ? "#f87171" : r >= 25 ? "#fbbf24" : "#60a5fa";
  const uebaRows = u.worklist.length
    ? u.worklist.map((e: any) => `<div class="te">
        <span class="ty" style="background:#3b0764;color:#e9d5ff">UEBA</span>
        <span class="tn">${esc(e.name)}</span>
        <span class="tr">${esc(e.reasons.join(" · "))}${e.lastSeen ? ` · ${fmt("zt.lastSeen", { d: esc(e.lastSeen) })}` : ""}</span>
        <span class="tier" style="background:#1e2440;color:#94a3b8">${fmt("zt.signins", { n: e.signins })}</span>
        <span class="tscore" style="color:${uebaColor(e.risk)}">${e.risk}</span></div>`).join("")
    : `<div class="muted" style="padding:12px 14px">${t("zt.noUeba")}</div>`;
  const ps = d.policiesSummary || {};
  const polRows = (d.policies || []).length
    ? d.policies.map((p: any) => {
        const enabled = /^enabled$/i.test(p.state), report = /report/i.test(p.state);
        const bg = enabled ? "#14532d" : report ? "#78350f" : "#1e2440", fg = enabled ? "#bbf7d0" : report ? "#fde68a" : "#94a3b8";
        return `<div class="te">
          <span class="tier" style="background:${bg};color:${fg}">${esc(report ? t("zt.reportOnly") : p.state || "—")}</span>
          <span class="tn">${esc(p.name)}</span>
          <span class="tr">${esc(p.subjects)} → ${esc(p.resources)}${p.conditions && p.conditions !== "(any)" ? ` · ${esc(p.conditions)}` : ""}</span>
          <span class="tier" style="background:#1e2440;color:#cbd5e1">${esc(p.grantControls || "—")}</span></div>`;
      }).join("")
    : `<div class="muted" style="padding:12px 14px">${t("zt.noPolicy")}</div>`;
  const assess = d.assessments.length
    ? d.assessments.map((a) => `<div class="as" data-id="${a.id}"><span class="an">${esc(a.name)}</span><span class="src src-assessment">${esc(a.status)}</span><span class="spacer"></span>${a.overallStage != null ? `<span class="muted" style="font-size:12px">${fmt("zt.cMaturity.foot", { s: a.overallStage, p: a.score ?? 0 })}</span>` : ""}${a.target ? `<span class="muted" style="font-size:12px">🎯 ${esc(a.target)}</span>` : ""}</div>`).join("")
    : `<div class="muted" style="padding:8px 0">${t("zt.noAssessment")}</div>`;
  $("zt-body").innerHTML = `<div class="zt-cards">${cards}</div>
    <div class="zt-section">${d.hasAssessment ? t("zt.secPillarAssessment") : t("zt.secPillarLive")}</div>${pillars}
    <div class="zt-section">${t("zt.secTrustWork")}</div>
    <div class="panel">${work}</div>
    <div class="zt-section">${fmt("zt.secUeba", { s: us.signins || 0, h: us.highRisk || 0, m: us.mfaLessRate || 0 })}</div>
    <div class="panel">${uebaRows}</div>
    <div class="zt-section">${fmt("zt.secPolicy", { t: ps.total || 0, e: ps.enabled || 0, m: ps.requireMfa || 0, b: ps.block || 0, r: ps.reportOnly || 0 })}</div>
    <div class="panel">${polRows}</div>
    <div class="zt-section">${t("zt.secAssessments")}<span class="spacer"></span><button class="btn2 go" id="zt-new">${t("zt.newAssessment")}</button></div>${assess}`;
  $("zt-new").onclick = openModal;
  Array.prototype.forEach.call(document.querySelectorAll(".as"), (el: HTMLElement) => { el.onclick = () => openAssessment(Number(el.getAttribute("data-id"))); });
}

// ── new-assessment modal ──
function openModal(): void {
  ($("f-name") as HTMLInputElement).value = `${t("zt.assessmentName")} ${new Date().getFullYear()}`;
  ["f-scope", "f-owner", "f-date"].forEach((i) => { ($(i) as HTMLInputElement).value = ""; });
  ($("f-target") as HTMLSelectElement).value = "3";
  $("zt-modal").classList.add("show");
}
function closeModal(): void { $("zt-modal").classList.remove("show"); }
function createAssessment(): void {
  const body = {
    name: ($("f-name") as HTMLInputElement).value.trim() || undefined,
    scope: ($("f-scope") as HTMLInputElement).value.trim() || undefined,
    owner: ($("f-owner") as HTMLInputElement).value.trim() || undefined,
    targetStage: Number(($("f-target") as HTMLSelectElement).value),
    targetDate: ($("f-date") as HTMLInputElement).value || undefined,
  };
  const btn = $("zt-create") as HTMLButtonElement; btn.disabled = true;
  api("POST", "/api/zero-trust/assessment", body)
    .then((j) => { closeModal(); toast(t("zt.toastCreated")); openAssessment(j.id); })
    .catch((e) => toast("⚠️ " + (e.message || e)))
    .finally(() => { btn.disabled = false; });
}

// ── assessment detail ──
function functionHtml(f: any): string {
  const cur = f.currentStage != null ? f.currentStage : (f.autoStage ?? 0);
  const btns = [0, 1, 2, 3].map((s) => {
    const sel = cur === s ? ` sel sel${s}` : "";
    const auto = f.autoStage === s ? " auto" : "";
    return `<button class="sb${sel}${auto}" data-item="${f.itemId}" data-stage="${s}" title="${esc(stageLabel(s))}${f.autoStage === s ? " · " + t("zt.liveEstTitle") : ""}"><b>${esc(stageLabel(s))}</b>${esc(f.stages[s] || "")}</button>`;
  }).join("");
  return `<div class="fn"><div class="ft">${esc(f.name)}</div><div class="fd">${esc(f.desc)}</div><div class="stagebtns">${btns}</div></div>`;
}
function pillarSectionHtml(p: any): string {
  const stages = p.functions.map((f: any) => f.currentStage != null ? f.currentStage : (f.autoStage ?? 0));
  const avg = stages.length ? stages.reduce((a: number, b: number) => a + b, 0) / stages.length : 0;
  const st = stIdx(avg);
  return `<div class="panel"><div class="ph">${esc(p.name)}${p.cross ? `<span class="cross">${t("zt.crossCut")}</span>` : ""}<span class="spacer" style="flex:1"></span><span class="s${st}">${esc(stageLabel(st))}</span></div>${p.functions.map(functionHtml).join("")}</div>`;
}

function openAssessment(id: number): void {
  $("zt-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("zt.loadingAssessment")}</div>`;
  fetch("/api/zero-trust/assessment/" + id).then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: any) => {
    const a = d.assessment;
    const st = a.overallStage != null ? stIdx(a.overallStage) : 0;
    $("zt-body").innerHTML = `
      <div class="zt-section"><button class="btn2" id="zt-back">${t("zt.overview")}</button><span class="spacer"></span>
        <button class="btn2" id="zt-del" style="border-color:#7f1d1d;color:#fca5a5">${t("zt.delete")}</button></div>
      <h2 style="font-size:18px;margin:6px 0 2px">${esc(a.name)}</h2>
      <div class="muted" style="font-size:12.5px;margin-bottom:12px">${a.scope ? `🎯 ${esc(a.scope)} · ` : ""}${a.owner ? `👤 ${esc(a.owner)} · ` : ""}${t("zt.statusLabel")} ${esc(a.status)}${a.target ? ` · ${t("zt.targetLabel")} ${esc(a.target)}` : ""}</div>
      <div class="zt-cards">${[
        card(t("zt.cOverall"), a.overallStage != null ? stageLabel(st) : "—", a.overallStage != null ? fmt("zt.cMaturity.foot", { s: a.overallStage, p: a.score ?? 0 }) : t("zt.notScored"), a.score != null ? (a.score >= 67 ? "#4ade80" : a.score >= 34 ? "#fbbf24" : "#f87171") : undefined),
        card(t("zt.cFunctions"), String(d.pillars.reduce((n: number, p: any) => n + p.functions.length, 0)), t("zt.cFunctions.foot")),
        card(t("zt.cSeed"), "✓", t("zt.cSeed.foot"), "#38bdf8"),
      ].join("")}</div>
      <div class="muted" style="font-size:11.5px;margin:2px 0 12px">${t("zt.pickHint")}</div>
      ${d.pillars.map(pillarSectionHtml).join("")}`;
    $("zt-back").onclick = () => reload().then(renderOverview);
    $("zt-del").onclick = () => { if (!confirm(t("zt.confirmDelete"))) return; api("DELETE", "/api/zero-trust/assessment/" + id).then(() => reload().then(renderOverview)).then(() => toast(t("zt.toastDeleted"))); };
    Array.prototype.forEach.call(document.querySelectorAll(".sb"), (b: HTMLElement) => {
      b.onclick = () => setStage(id, Number(b.getAttribute("data-item")), Number(b.getAttribute("data-stage")));
    });
  }).catch((e) => { $("zt-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function setStage(assessmentId: number, itemId: number, stage: number): void {
  api("POST", "/api/zero-trust/item/" + itemId, { currentStage: stage }).then(() => openAssessment(assessmentId)).catch((e) => toast("⚠️ " + (e.message || e)));
}

function api(method: string, url: string, body?: any): Promise<any> {
  return fetch(url, { method, headers: body ? { "Content-Type": "application/json" } : undefined, body: body ? JSON.stringify(body) : undefined })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }));
}
function reload(): Promise<void> {
  return fetch("/api/zero-trust").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => { DATA = d; });
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("zt-cancel").onclick = closeModal;
  $("zt-create").onclick = createAssessment;
  $("zt-modal").addEventListener("click", (e) => { if (e.target === $("zt-modal")) closeModal(); });
  reload().then(renderOverview).catch((e) => { $("zt-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
});
