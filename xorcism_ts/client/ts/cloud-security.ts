/** cloud-security.ts — Cloud Security Management cockpit (/cloud-security). Cloud asset inventory,
 * exposure/misconfig worklist, provider breakdown + CSA CCM reference, from /api/cloud-security. */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.replace(`{${k}}`, String(v)), t(key));

interface Row { id: number; name: string; provider: string; criticality: string; publicFacing: boolean; encrypted: boolean; pii: boolean; thirdParty: boolean; owner: boolean; vulns: number; criticalVulns: number; kev: number; tags: string[]; flags: string[]; score: number; hostname: string; ip: string; }
interface Data { rows: Row[]; worklist: { id: number; name: string; provider: string; severity: string; reason: string }[]; summary: any; }

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="cs-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const pcls = (p: string): string => `p-${["AWS", "Azure", "GCP", "OCI", "SaaS", "Cloud"].includes(p) ? p : "Cloud"}`;
const scls = (s: string): string => `sv-${["Critical", "High", "Medium", "Low"].includes(s) ? s : "Low"}`;

function rowHtml(r: Row): string {
  return `<tr>
    <td><a class="nm" href="/?db=XORCISM&table=ASSET&editCol=AssetID&editVal=${r.id}" style="color:var(--accent,#7c83fd);text-decoration:none" title="${t("cs.editAsset")}">${esc(r.name)}</a>${r.hostname || r.ip ? `<div class="muted" style="font-size:11px">${esc(r.hostname || r.ip)}</div>` : ""}</td>
    <td><span class="prov ${pcls(r.provider)}">${esc(r.provider)}</span></td>
    <td>${esc(r.criticality || "—")}</td>
    <td>${r.publicFacing ? `<span class="tag t-pub">${t("cs.public")}</span>` : `<span class='muted'>${t("cs.internal")}</span>`}</td>
    <td>${r.encrypted ? `<span class="tag t-enc">${t("cs.enc")}</span>` : `<span class="tag t-unenc">${t("cs.noEnc")}</span>`}${r.pii ? ` <span class="tag t-pii">PII</span>` : ""}</td>
    <td>${r.vulns ? `${r.vulns}${r.criticalVulns ? ` <span class="muted" style="font-size:11px">(${r.criticalVulns}C)</span>` : ""}${r.kev ? ` <span class="tag t-kev">${r.kev} KEV</span>` : ""}` : "<span class='muted'>0</span>"}</td>
    <td>${r.owner ? "✓" : `<span class='tag t-unenc'>${t("cs.ownerNone")}</span>`}</td>
  </tr>`;
}

function load(): void {
  fetch("/api/cloud-security").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => {
    const s = d.summary;
    if (!d.rows.length) {
      $("cs-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${fmt("cs.emptyA", { n: s.ccmControls, m: s.ccmDomains })}<br>
        ${t("cs.emptyB")}</div>`;
      return;
    }
    const cards = [
      card(t("cs.cAssets"), String(s.cloudAssets), fmt("cs.cAssetsFoot", { n: s.thirdParty })),
      card(t("cs.cPublic"), String(s.publicFacing), t("cs.cPublicFoot"), s.publicFacing ? "#fbbf24" : "#34d399"),
      card(t("cs.cUnenc"), String(s.unencrypted), t("cs.cUnencFoot"), s.unencrypted ? "#f87171" : "#34d399"),
      card(t("cs.cKev"), String(s.kev), t("cs.cKevFoot"), s.kev ? "#f87171" : "#34d399"),
      card(t("cs.cCrit"), String(s.criticalAssets), fmt("cs.cCritFoot", { n: s.withCriticalVulns })),
      card("CSA CCM", String(s.ccmControls), fmt("cs.cCcmFoot", { n: s.ccmDomains }), "#60a5fa"),
    ].join("");
    const byProv = Object.entries(s.byProvider || {}).sort((a: any, b: any) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="prov ${pcls(k)}">${esc(k)}</span> <b>${n}</b></span>`).join("");
    const work = d.worklist.length
      ? `<ul class="worklist">${d.worklist.slice(0, 40).map((w) => `<li><span class="sev ${scls(w.severity)}">${esc(w.severity)}</span> <b style="color:#e2e8f0">${esc(w.name)}</b> <span class="prov ${pcls(w.provider)}">${esc(w.provider)}</span> — ${esc(w.reason)}</li>`).join("")}</ul>`
      : `<div class="muted" style="padding:8px 0">${t("cs.workNone")}</div>`;
    const table = `<table class="cs"><thead><tr><th>${t("cs.thAsset")}</th><th>${t("cs.thProvider")}</th><th>${t("cs.thCriticality")}</th><th>${t("cs.thExposure")}</th><th>${t("cs.thEncryption")}</th><th>${t("cs.thVulns")}</th><th>${t("cs.thOwner")}</th></tr></thead><tbody>${d.rows.slice(0, 200).map(rowHtml).join("")}</tbody></table>`;
    $("cs-body").innerHTML = `<div class="cs-cards">${cards}</div>
      <div class="cs-section">${t("cs.secProvider")}</div><div class="breakdown">${byProv || "<span class='muted'>—</span>"}</div>
      <div class="cs-section">${t("cs.secWorklist")} (${d.worklist.length})</div>${work}
      <div class="cs-section">${t("cs.secAssets")} (${d.rows.length})</div>${table}`;
  }).catch((e) => { $("cs-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}
document.addEventListener("DOMContentLoaded", () => { initI18n(); load(); });
