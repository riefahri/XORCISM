/**
 * oval-scan.ts — OVAL scan results (/oval-scan). Per-asset verdicts + compliance/vuln
 * worklist from the XOR agent's OpenSCAP evaluations, via /api/oval-results.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface Row { asset: string; assetId: number | null; lastScan: string | null; vuln: number; compliancePass: number; complianceFail: number; inventory: number; total: number; }
interface Finding { asset: string; assetId: number | null; cls: string; title: string; severity: string; result: string; }
interface View {
  rows: Row[]; findings: Finding[];
  summary: { assets: number; verdicts: number; complianceFail: number; compliancePass: number; passRate: number | null; cves: number; lastScan: string | null };
}

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="ov-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rowHtml(r: Row): string {
  const cell = (n: number, cls: string): string => (n ? `<span class="pill ${cls}">${n}</span>` : `<span class="muted">0</span>`);
  return `<tr>
    <td><span class="aname">${esc(r.asset)}</span></td>
    <td>${esc(r.lastScan ? r.lastScan.replace("T", " ") : "—")}</td>
    <td>${cell(r.vuln, "p-vuln")}</td>
    <td>${cell(r.complianceFail, "p-fail")} ${cell(r.compliancePass, "p-pass")}</td>
    <td>${cell(r.inventory, "p-inv")}</td>
    <td class="muted">${r.total}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  const vuln = f.cls === "vulnerability";
  return `<li><span class="dot ${vuln ? "d-vuln" : "d-fail"}"></span>
    <span class="cls-${f.cls}">${vuln ? t("ov.vuln") : t("ov.fail")}</span> ·
    <a href="/asset-management">${esc(f.asset)}</a> — ${esc(f.title || (vuln ? t("ov.cveDetected") : t("ov.complianceCheck")))}${f.severity ? ` <span class="muted">(${esc(f.severity)})</span>` : ""}</li>`;
}

async function load(): Promise<void> {
  let d: View;
  try { const r = await fetch("/api/oval-results"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("ov-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!d.rows.length) {
    $("ov-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("ov.empty")}</div>`;
    return;
  }

  const cards = [
    card(t("ov.cAssets"), String(s.assets), fmt("ov.cAssets.foot", { n: s.verdicts })),
    card(t("ov.cPass"), s.passRate != null ? `${s.passRate}%` : "—", fmt("ov.cPass.foot", { p: s.compliancePass, f: s.complianceFail }), s.passRate != null ? (s.passRate >= 80 ? "#34d399" : s.passRate >= 50 ? "#fbbf24" : "#f87171") : undefined),
    card(t("ov.cFailures"), String(s.complianceFail), t("ov.cFailures.foot"), s.complianceFail ? "#fb923c" : "#34d399"),
    card(t("ov.cCves"), String(s.cves), t("ov.cCves.foot"), s.cves ? "#f87171" : "#34d399"),
    card(t("ov.cLastScan"), s.lastScan ? esc(s.lastScan.slice(0, 10)) : "—", s.lastScan ? esc(s.lastScan.slice(11, 19)) : t("ov.never")),
  ].join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">${fmt("ov.more", { n: d.findings.length - 60 })}</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">${t("ov.noFindings")}</div>`;

  const table = `<table class="ov"><thead><tr>
      <th>${t("ov.thAsset")}</th><th>${t("ov.thLastScan")}</th><th>${t("ov.thVulns")}</th><th>${t("ov.thCompliance")}</th><th>${t("ov.thInventory")}</th><th>${t("ov.thVerdicts")}</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("ov-body").innerHTML = `<div class="ov-cards">${cards}</div>
    <div class="ov-section">${fmt("ov.secWorklist", { n: d.findings.length })}</div>${findings}
    <div class="ov-section">${fmt("ov.secByAsset", { n: d.rows.length })}</div>${table}
    <div class="legend">${t("ov.legend")}</div>`;
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
