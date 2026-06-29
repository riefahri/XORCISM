/**
 * assurance.ts — Continuous control monitoring view (/assurance).
 * Renders the control posture computed live from telemetry by /api/assurance, plus per-framework
 * readiness (SOC 2 / ISO 27001 / NIST CSF), the posture trend over snapshots, and drift (what changed).
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface FwRef { fw: string; ref: string; }
interface Control { id: string; name: string; iso: string; nist: string; status: string; score: number; metric: string; evidence: string[]; frameworks?: FwRef[]; }
interface FrameworkReadiness { fw: string; label: string; readinessPct: number; proven: number; measurable: number; }
interface Drift { id: string; name: string; from: string; to: string; dir: "up" | "down"; }
interface Assurance {
  controls: Control[];
  stats: { total: number; proven: number; partial: number; gap: number; attest: number; provenPct: number };
  frameworks: FrameworkReadiness[]; trend: { at: string; pct: number }[]; drift: Drift[];
  evaluatedAt: string;
}

const statusLabel = (s: string): string => t("asr.st." + s) || s;
function statusColor(s: string): string { return s === "proven" ? "#22c55e" : s === "partial" ? "#f59e0b" : s === "gap" ? "#ef4444" : "#64748b"; }
function pctColor(p: number): string { return p >= 70 ? "#22c55e" : p >= 40 ? "#f59e0b" : "#ef4444"; }

function ctlCard(c: Control): string {
  const refs = c.frameworks && c.frameworks.length
    ? c.frameworks.map((f) => `${esc(f.fw === "soc2" ? "SOC 2" : f.fw === "iso27001" ? "ISO" : "NIST")} ${esc(f.ref)}`).join(" · ")
    : `ISO ${esc(c.iso)} · NIST ${esc(c.nist)}`;
  return `<div class="ctl">
    <div class="top">
      <span class="nm">${esc(c.name)}</span>
      <span class="refs">${refs}</span>
      <span class="badge b-${esc(c.status)}">${esc(statusLabel(c.status))}</span>
    </div>
    ${c.status !== "attest" ? `<div class="sbar"><i style="width:${c.score}%;background:${statusColor(c.status)}"></i></div>` : ""}
    <div class="metric">${esc(c.metric)}</div>
    ${c.evidence.length ? `<div class="evi">↳ ${c.evidence.map(esc).join(" · ")}</div>` : ""}
  </div>`;
}

// Per-framework readiness cards (the "you are N% SOC 2 ready" headline).
function fwRow(fws: FrameworkReadiness[]): string {
  if (!fws || !fws.length) return "";
  const card = (f: FrameworkReadiness): string => `<div class="fw">
    <div class="fw-top"><span class="fw-lbl">${esc(f.label)}</span><span class="fw-pct" style="color:${pctColor(f.readinessPct)}">${f.readinessPct}%</span></div>
    <div class="sbar"><i style="width:${f.readinessPct}%;background:${pctColor(f.readinessPct)}"></i></div>
    <div class="muted" style="font-size:11px;margin-top:3px">${fmt("asr.fwProven", { n: f.proven, m: f.measurable })}</div>
  </div>`;
  return `<div class="sect-h">${t("asr.fwTitle")}</div><div class="fw-grid">${fws.map(card).join("")}</div>`;
}

// Inline SVG sparkline of provenPct over the persisted snapshots.
function trendSpark(trend: { at: string; pct: number }[]): string {
  if (!trend || trend.length < 2) return "";
  const W = 280, H = 46, n = trend.length, max = 100;
  const pts = trend.map((p, i) => `${(i / (n - 1)) * W},${(H - (p.pct / max) * H).toFixed(1)}`).join(" ");
  const last = trend[n - 1].pct, delta = last - trend[0].pct;
  const dStr = delta === 0 ? "±0" : (delta > 0 ? "+" : "") + delta;
  return `<div class="sect-h">${t("asr.trendTitle")} <span class="muted" style="font-weight:400">· ${fmt("asr.trendDelta", { d: dStr, n })}</span></div>
    <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:46px;margin-bottom:14px">
      <polyline points="${pts}" fill="none" stroke="${pctColor(last)}" stroke-width="2" vector-effect="non-scaling-stroke"/>
    </svg>`;
}

// Drift = control objectives whose status changed vs the previous snapshot.
function driftBlock(drift: Drift[]): string {
  if (!drift || !drift.length) return `<div class="drift-ok">✓ ${t("asr.noDrift")}</div>`;
  const row = (d: Drift): string => `<div class="drift-row ${d.dir}">
    <span>${d.dir === "up" ? "▲" : "▼"}</span>
    <span class="nm">${esc(d.name)}</span>
    <span class="muted">${esc(statusLabel(d.from))} → ${esc(statusLabel(d.to))}</span>
    <span class="tag ${d.dir}">${d.dir === "up" ? t("asr.driftUp") : t("asr.driftDown")}</span>
  </div>`;
  return `<div class="sect-h">${t("asr.driftTitle")}</div>${drift.map(row).join("")}`;
}

async function load(): Promise<void> {
  let d: Assurance;
  try { const r = await fetch("/api/assurance"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("as-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${fmt("asr.loadFailed", { e: esc(e) })}</div>`; return; }
  const st = d.stats;
  const order: Record<string, number> = { proven: 0, partial: 1, gap: 2, attest: 3 };
  const controls = d.controls.slice().sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9));
  $("as-body").innerHTML = `
    <div class="as-hero">
      <span class="as-pct" style="color:${pctColor(st.provenPct)}">${st.provenPct}%</span>
      <div>
        <div class="as-bar"><i style="width:${st.provenPct}%;background:${pctColor(st.provenPct)}"></i></div>
        <div class="muted" style="font-size:12px;margin-top:4px">${t("asr.heroSub")}</div>
      </div>
    </div>
    <div class="tally" style="margin-bottom:16px">
      <span class="pill p-proven">${fmt("asr.tallyProven", { n: st.proven })}</span>
      <span class="pill p-partial">${fmt("asr.tallyPartial", { n: st.partial })}</span>
      <span class="pill p-gap">${fmt("asr.tallyGap", { n: st.gap })}</span>
      <span class="pill p-attest">${fmt("asr.tallyAttest", { n: st.attest })}</span>
    </div>
    ${fwRow(d.frameworks)}
    ${trendSpark(d.trend)}
    ${driftBlock(d.drift)}
    <div class="sect-h">${t("asr.controlsTitle")}</div>
    ${controls.map(ctlCard).join("")}
    <div class="muted" style="font-size:11px;margin-top:12px">${fmt("asr.evaluatedAt", { t: esc(d.evaluatedAt) })}</div>`;
}

// Audit & Accreditation package — generate the traceable, AI-narrated report (download as Markdown).
async function genAuditPackage(): Promise<void> {
  const host = document.getElementById("as-audit"); if (!host) return;
  const btn = document.getElementById("as-genpkg") as HTMLButtonElement | null;
  if (btn) { btn.disabled = true; btn.textContent = "⏳ Generating…"; }
  host.innerHTML = `<div class="muted" style="padding:10px">${t("asr.pkgGenerating") || "Assembling control, regulatory, risk and BIA evidence…"}</div>`;
  try {
    const r = await fetch("/api/audit-package"); if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const d = await r.json() as { executiveSummary: string; ai: boolean; model: string; accreditation: { provenPct: number; gap: number }; regulatory: { cloud: { pass: number; fail: number }; auditTrailTotal: number }; risk: { register: { total: number; overAppetite: number } }; bia: { total: number; critical: number; computedTotal: number; computedCritical: number }; trend: { at: string; provenPct: number }[]; markdown: string };
    const url = URL.createObjectURL(new Blob([d.markdown], { type: "text/markdown" }));
    const biaTotal = d.bia.total || d.bia.computedTotal, biaCrit = d.bia.total ? d.bia.critical : d.bia.computedCritical;
    const biaLbl = d.bia.total ? "BIA" : "BIA (computed)";
    // posture trend sparkline
    let spark = "";
    if (d.trend && d.trend.length >= 2) {
      const W = 200, H = 30, n = d.trend.length;
      const pts = d.trend.map((p, i) => `${(i / (n - 1)) * W},${(H - (p.provenPct / 100) * H).toFixed(1)}`).join(" ");
      const delta = d.trend[n - 1].provenPct - d.trend[0].provenPct;
      spark = `<div class="muted" style="font-size:11px;margin-top:8px">Posture trend (${n} snapshots, ${delta >= 0 ? "+" : ""}${delta} pts)
        <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:200px;height:30px;vertical-align:middle;margin-left:6px"><polyline points="${pts}" fill="none" stroke="${pctColor(d.trend[n - 1].provenPct)}" stroke-width="2" vector-effect="non-scaling-stroke"/></svg></div>`;
    }
    host.innerHTML = `<div style="border:1px solid #2d3250;border-radius:10px;padding:14px;background:#13162a;margin-bottom:16px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap"><b style="color:#e7ebf3">📄 Audit &amp; accreditation package</b>
        <span class="muted" style="font-size:11px">${d.ai ? "AI summary (" + esc(d.model) + ")" : "offline summary"}</span>
        <span style="flex:1"></span>
        <a href="${url}" download="audit-accreditation-package.md" style="color:#86efac;font-size:12px">⬇ Markdown</a>
        <select id="as-oscal-profile" title="OSCAL control-id profile" style="background:#0f1117;border:1px solid #2d3250;color:#cbd5e1;border-radius:6px;padding:2px 6px;font-size:11px">
          <option value="">default</option><option value="soc2">SOC 2</option><option value="iso27001">ISO 27001</option><option value="nistcsf">NIST CSF</option></select>
        <a id="as-oscal-ssp" href="/api/audit-package?format=oscal" style="color:#93c5fd;font-size:12px" title="OSCAL System Security Plan">⬇ OSCAL SSP</a>
        <a id="as-oscal-poam" href="/api/audit-package?format=poam" style="color:#93c5fd;font-size:12px" title="OSCAL Plan of Action &amp; Milestones">⬇ OSCAL POA&amp;M</a></div>
      <div style="font-size:13px;color:#cbd5e1;white-space:pre-wrap;line-height:1.5">${esc(d.executiveSummary)}</div>
      <div class="tally" style="margin-top:10px">
        <span class="pill p-proven">Accreditation ${d.accreditation.provenPct}%</span>
        <span class="pill p-gap">${d.accreditation.gap} control gap(s)</span>
        <span class="pill p-partial">Cloud ${d.regulatory.cloud.pass}✓/${d.regulatory.cloud.fail}✗</span>
        <span class="pill p-attest">${d.regulatory.auditTrailTotal} audit-log entries</span>
        <span class="pill p-gap">${d.risk.register.overAppetite}/${d.risk.register.total} risks over appetite</span>
        <span class="pill p-proven">${biaLbl} ${biaCrit}/${biaTotal} critical</span>
      </div>${spark}</div>`;
    // profile picker drives the OSCAL export control-id namespace (SOC 2 / ISO 27001 / NIST CSF)
    const sel = document.getElementById("as-oscal-profile") as HTMLSelectElement | null;
    if (sel) sel.onchange = () => {
      const q = sel.value ? `&profile=${sel.value}` : "";
      (document.getElementById("as-oscal-ssp") as HTMLAnchorElement).href = `/api/audit-package?format=oscal${q}`;
      (document.getElementById("as-oscal-poam") as HTMLAnchorElement).href = `/api/audit-package?format=poam${q}`;
    };
  } catch (e) { host.innerHTML = `<div class="muted" style="padding:10px">⚠️ ${esc(e)}</div>`; }
  finally { if (btn) { btn.disabled = false; btn.textContent = "📄 Generate audit & accreditation package"; } }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n(); void load();
  const b = document.getElementById("as-genpkg"); if (b) b.addEventListener("click", () => void genAuditPackage());
});
