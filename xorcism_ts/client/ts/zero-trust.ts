/**
 * zero-trust.ts — Zero Trust cockpit (CISA ZTMM v2.0). Per-pillar maturity (live signals or the
 * latest assessment), a fused trust score worklist (NIST 800-207), and a maturity assessment with
 * a 4-stage picker per function. Reads /api/zero-trust.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const e = $("toast"); e.textContent = m; e.className = "show"; setTimeout(() => { e.className = ""; }, 3000); }

const STAGES = ["Traditional", "Initial", "Advanced", "Optimal"];
const stIdx = (s: number) => Math.max(0, Math.min(3, Math.round(s)));

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
    <span class="nm">${esc(p.name)}${p.cross ? '<span class="cross">cross-cut</span>' : ""}</span>
    <div class="track">
      <div class="stagebar"><i class="b${st}" style="width:${Math.max(3, p.pct)}%"></i></div>
      <div class="stageticks"><span>Traditional</span><span>Initial</span><span>Advanced</span><span>Optimal</span></div>
      <div class="basis">${esc(p.signalBasis)}</div>
    </div>
    <div class="stg">
      <span class="s${st}">${esc(STAGES[st])}</span><br>
      <span class="src src-${p.source === "assessment" ? "assessment" : "live"}">${p.source === "assessment" ? "assessed" : "live signal"}</span>
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
  const d = DATA!; const o = d.overall; const t = d.trust;
  const gap = d.gaps[0];
  const cards = [
    card("ZT maturity", `${o.label}`, `stage ${o.stage}/3 · ${o.pct}%`, o.pct >= 67 ? "#4ade80" : o.pct >= 34 ? "#fbbf24" : "#f87171"),
    card("Trust posture", String(t.overall), `${esc(t.tier)} · ${t.entities} entities`, trustColor(t.overall)),
    card("Low-trust entities", String(t.low), `of ${t.identities.count} identities + ${t.devices.count} assets`, t.low ? "#f87171" : "#4ade80"),
    card("Biggest gap", gap ? esc(gap.name) : "—", gap ? `${STAGES[stIdx(gap.currentStage)]} → ${STAGES[stIdx(gap.targetStage)]}` : "at target", gap ? "#fbbf24" : "#4ade80"),
  ].join("");
  const pillars = d.pillars.map(pillarRow).join("");
  const work = d.trustWorklist.length ? d.trustWorklist.map(trustRow).join("") : '<div class="muted" style="padding:12px 14px">No low-trust entities — everything is Trusted.</div>';
  const u = d.ueba || { summary: {}, worklist: [] };
  const us = u.summary || {};
  const uebaColor = (r: number) => r >= 50 ? "#f87171" : r >= 25 ? "#fbbf24" : "#60a5fa";
  const uebaRows = u.worklist.length
    ? u.worklist.map((e: any) => `<div class="te">
        <span class="ty" style="background:#3b0764;color:#e9d5ff">UEBA</span>
        <span class="tn">${esc(e.name)}</span>
        <span class="tr">${esc(e.reasons.join(" · "))}${e.lastSeen ? ` · last ${esc(e.lastSeen)}` : ""}</span>
        <span class="tier" style="background:#1e2440;color:#94a3b8">${e.signins} sign-ins</span>
        <span class="tscore" style="color:${uebaColor(e.risk)}">${e.risk}</span></div>`).join("")
    : '<div class="muted" style="padding:12px 14px">No sign-in telemetry yet — add an IdP connector (<b>entra-signin</b> / <b>okta-signin</b>) to mature the Identity pillar to continuous verification.</div>';
  const ps = d.policiesSummary || {};
  const polRows = (d.policies || []).length
    ? d.policies.map((p: any) => {
        const enabled = /^enabled$/i.test(p.state), report = /report/i.test(p.state);
        const bg = enabled ? "#14532d" : report ? "#78350f" : "#1e2440", fg = enabled ? "#bbf7d0" : report ? "#fde68a" : "#94a3b8";
        return `<div class="te">
          <span class="tier" style="background:${bg};color:${fg}">${esc(report ? "report-only" : p.state || "—")}</span>
          <span class="tn">${esc(p.name)}</span>
          <span class="tr">${esc(p.subjects)} → ${esc(p.resources)}${p.conditions && p.conditions !== "(any)" ? ` · ${esc(p.conditions)}` : ""}</span>
          <span class="tier" style="background:#1e2440;color:#cbd5e1">${esc(p.grantControls || "—")}</span></div>`;
      }).join("")
    : '<div class="muted" style="padding:12px 14px">No Zero Trust policies ingested — add the <b>entra-conditional-access</b> connector to populate the policy register.</div>';
  const assess = d.assessments.length
    ? d.assessments.map((a) => `<div class="as" data-id="${a.id}"><span class="an">${esc(a.name)}</span><span class="src src-assessment">${esc(a.status)}</span><span class="spacer"></span>${a.overallStage != null ? `<span class="muted" style="font-size:12px">stage ${a.overallStage}/3 · ${a.score ?? 0}%</span>` : ""}${a.target ? `<span class="muted" style="font-size:12px">🎯 ${esc(a.target)}</span>` : ""}</div>`).join("")
    : '<div class="muted" style="padding:8px 0">No formal assessment yet — the pillars above use live signals. Create one to set targets and track progress.</div>';
  $("zt-body").innerHTML = `<div class="zt-cards">${cards}</div>
    <div class="zt-section">Pillar maturity ${d.hasAssessment ? "(from your assessment)" : "(from live signals)"}</div>${pillars}
    <div class="zt-section">Trust score worklist — least-trusted first (NIST 800-207)</div>
    <div class="panel">${work}</div>
    <div class="zt-section">Session risk (UEBA) — ${us.signins || 0} sign-ins · ${us.highRisk || 0} high-risk · ${us.mfaLessRate || 0}% MFA-less</div>
    <div class="panel">${uebaRows}</div>
    <div class="zt-section">ZT policy register — ${ps.total || 0} policies · ${ps.enabled || 0} enabled · ${ps.requireMfa || 0} require MFA · ${ps.block || 0} block · ${ps.reportOnly || 0} report-only</div>
    <div class="panel">${polRows}</div>
    <div class="zt-section">Maturity assessments<span class="spacer"></span><button class="btn2 go" id="zt-new">+ New assessment</button></div>${assess}`;
  $("zt-new").onclick = openModal;
  Array.prototype.forEach.call(document.querySelectorAll(".as"), (el: HTMLElement) => { el.onclick = () => openAssessment(Number(el.getAttribute("data-id"))); });
}

// ── new-assessment modal ──
function openModal(): void {
  ($("f-name") as HTMLInputElement).value = `Zero Trust maturity — ${new Date().getFullYear()}`;
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
    .then((j) => { closeModal(); toast("✓ Assessment created from live signals"); openAssessment(j.id); })
    .catch((e) => toast("⚠️ " + (e.message || e)))
    .finally(() => { btn.disabled = false; });
}

// ── assessment detail ──
function functionHtml(f: any): string {
  const cur = f.currentStage != null ? f.currentStage : (f.autoStage ?? 0);
  const btns = [0, 1, 2, 3].map((s) => {
    const sel = cur === s ? ` sel sel${s}` : "";
    const auto = f.autoStage === s ? " auto" : "";
    return `<button class="sb${sel}${auto}" data-item="${f.itemId}" data-stage="${s}" title="${esc(STAGES[s])}${f.autoStage === s ? " · live-signal estimate" : ""}"><b>${esc(STAGES[s])}</b>${esc(f.stages[s] || "")}</button>`;
  }).join("");
  return `<div class="fn"><div class="ft">${esc(f.name)}</div><div class="fd">${esc(f.desc)}</div><div class="stagebtns">${btns}</div></div>`;
}
function pillarSectionHtml(p: any): string {
  const stages = p.functions.map((f: any) => f.currentStage != null ? f.currentStage : (f.autoStage ?? 0));
  const avg = stages.length ? stages.reduce((a: number, b: number) => a + b, 0) / stages.length : 0;
  const st = stIdx(avg);
  return `<div class="panel"><div class="ph">${esc(p.name)}${p.cross ? '<span class="cross">cross-cut</span>' : ""}<span class="spacer" style="flex:1"></span><span class="s${st}">${esc(STAGES[st])}</span></div>${p.functions.map(functionHtml).join("")}</div>`;
}

function openAssessment(id: number): void {
  $("zt-body").innerHTML = '<div class="muted" style="padding:24px;text-align:center">Loading assessment…</div>';
  fetch("/api/zero-trust/assessment/" + id).then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: any) => {
    const a = d.assessment;
    const st = a.overallStage != null ? stIdx(a.overallStage) : 0;
    $("zt-body").innerHTML = `
      <div class="zt-section"><button class="btn2" id="zt-back">← Overview</button><span class="spacer"></span>
        <button class="btn2" id="zt-del" style="border-color:#7f1d1d;color:#fca5a5">Delete</button></div>
      <h2 style="font-size:18px;margin:6px 0 2px">${esc(a.name)}</h2>
      <div class="muted" style="font-size:12.5px;margin-bottom:12px">${a.scope ? `🎯 ${esc(a.scope)} · ` : ""}${a.owner ? `👤 ${esc(a.owner)} · ` : ""}status: ${esc(a.status)}${a.target ? ` · target ${esc(a.target)}` : ""}</div>
      <div class="zt-cards">${[
        card("Overall maturity", a.overallStage != null ? STAGES[st] : "—", a.overallStage != null ? `stage ${a.overallStage}/3 · ${a.score ?? 0}%` : "not scored", a.score != null ? (a.score >= 67 ? "#4ade80" : a.score >= 34 ? "#fbbf24" : "#f87171") : undefined),
        card("Functions", String(d.pillars.reduce((n: number, p: any) => n + p.functions.length, 0)), "across 8 pillars"),
        card("Live-signal seed", "✓", "blue marker = XORCISM estimate", "#38bdf8"),
      ].join("")}</div>
      <div class="muted" style="font-size:11.5px;margin:2px 0 12px">Pick the stage that matches reality for each function. The <span style="color:#38bdf8">blue-marked</span> button is XORCISM's live-signal estimate.</div>
      ${d.pillars.map(pillarSectionHtml).join("")}`;
    $("zt-back").onclick = () => reload().then(renderOverview);
    $("zt-del").onclick = () => { if (!confirm("Delete this Zero Trust assessment?")) return; api("DELETE", "/api/zero-trust/assessment/" + id).then(() => reload().then(renderOverview)).then(() => toast("✓ Deleted")); };
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
  $("zt-cancel").onclick = closeModal;
  $("zt-create").onclick = createAssessment;
  $("zt-modal").addEventListener("click", (e) => { if (e.target === $("zt-modal")) closeModal(); });
  reload().then(renderOverview).catch((e) => { $("zt-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
});
