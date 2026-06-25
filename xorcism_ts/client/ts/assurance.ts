/**
 * assurance.ts — Continuously-proven compliance view (/assurance).
 * Renders the control posture computed live from telemetry by /api/assurance.
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface Control { id: string; name: string; iso: string; nist: string; status: string; score: number; metric: string; evidence: string[]; }
interface Assurance { controls: Control[]; stats: { total: number; proven: number; partial: number; gap: number; attest: number; provenPct: number }; evaluatedAt: string; }

const statusLabel = (s: string): string => t("asr.st." + s) || s;
function statusColor(s: string): string { return s === "proven" ? "#22c55e" : s === "partial" ? "#f59e0b" : s === "gap" ? "#ef4444" : "#64748b"; }
function pctColor(p: number): string { return p >= 70 ? "#22c55e" : p >= 40 ? "#f59e0b" : "#ef4444"; }

function ctlCard(c: Control): string {
  return `<div class="ctl">
    <div class="top">
      <span class="nm">${esc(c.name)}</span>
      <span class="refs">ISO ${esc(c.iso)} · NIST ${esc(c.nist)}</span>
      <span class="badge b-${esc(c.status)}">${esc(statusLabel(c.status))}</span>
    </div>
    ${c.status !== "attest" ? `<div class="sbar"><i style="width:${c.score}%;background:${statusColor(c.status)}"></i></div>` : ""}
    <div class="metric">${esc(c.metric)}</div>
    ${c.evidence.length ? `<div class="evi">↳ ${c.evidence.map(esc).join(" · ")}</div>` : ""}
  </div>`;
}

async function load(): Promise<void> {
  let d: Assurance;
  try { const r = await fetch("/api/assurance"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("as-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${fmt("asr.loadFailed", { e: esc(e) })}</div>`; return; }
  const st = d.stats;
  // proven first, then partial, gap, attest
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
    ${controls.map(ctlCard).join("")}
    <div class="muted" style="font-size:11px;margin-top:12px">${fmt("asr.evaluatedAt", { t: esc(d.evaluatedAt) })}</div>`;
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
