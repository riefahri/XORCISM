/**
 * exposure.ts — Prioritized exposure worklist (/exposure).
 * Renders the fusion-scored top vulnerabilities from /api/fusion/top. Each row links
 * to the vulnerability and to Exploit-DB. Localized via exp.* keys.
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string {
  return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
}

interface Fusion { VulnerabilityID: number; ref: string; cvss: number | null; kev: number; epss: number | null; exploits: number; itw: boolean; assets: number; maxValue: number | null; score: number; priority: number; factors: string[]; }

const CVE_RX = /CVE-\d{4}-\d{3,7}/i;
function prioColor(p: number): string { return p >= 80 ? "#ef4444" : p >= 60 ? "#f59e0b" : p >= 40 ? "#eab308" : "#22c55e"; }

function row(f: Fusion, i: number): string {
  const cve = (f.ref.match(CVE_RX)?.[0] || "").toUpperCase();
  const chips: string[] = [];
  if (f.kev) chips.push(`<span class="chip c-kev">KEV</span>`);
  if (f.exploits) chips.push(`<span class="chip c-exp">⚔ ${f.exploits} exploit${f.exploits > 1 ? "s" : ""}</span>`);
  if (f.itw) chips.push(`<span class="chip c-itw">in the wild</span>`);
  if (f.epss != null && f.epss > 0) chips.push(`<span class="chip c-epss">EPSS ${(f.epss * 100).toFixed(1)}%</span>`);
  if (f.cvss != null && f.cvss > 0) chips.push(`<span class="chip c-cvss">CVSS ${f.cvss}</span>`);
  // Clickable: expands the impacted assets (only if there are any).
  chips.push(f.assets
    ? `<button class="chip c-ast asset-toggle" data-vid="${f.VulnerabilityID}" title="${esc(t("exp.viewAssets"))}">${f.assets} ${t("exp.assets")} ▾</button>`
    : `<span class="chip c-ast">0 ${t("exp.assets")}</span>`);
  const refLink = `/?db=XVULNERABILITY&table=VULNERABILITY&editCol=VulnerabilityID&editVal=${f.VulnerabilityID}`;
  const edb = cve ? ` · <a class="edb" href="/exploitdb?cve=${encodeURIComponent(cve)}" target="_blank" rel="noopener">Exploit-DB</a>` : "";
  return `<tr data-vid="${f.VulnerabilityID}">
    <td class="rank">${i + 1}</td>
    <td class="prio"><div class="bar"><i style="width:${f.priority}%;background:${prioColor(f.priority)}"></i></div>
      <b style="color:${prioColor(f.priority)}">${f.priority}</b> <span class="muted">/ ${t("exp.score")} ${f.score}</span></td>
    <td class="ref"><a href="${refLink}" target="_blank" rel="noopener">${esc(f.ref)}</a>${edb}</td>
    <td>${chips.join("")}</td>
  </tr>`;
}

interface ImpactedAsset { id: number; name: string; criticality: string | null; businessValue: number | null; address: string | null; publicFacing: boolean; }

function assetItemHtml(a: ImpactedAsset): string {
  const link = `/?db=XORCISM&table=ASSET&editCol=AssetID&editVal=${a.id}`;
  const meta = [a.criticality ? esc(a.criticality) : "", a.publicFacing ? t("exp.internetFacing") : "", a.address ? esc(a.address) : ""].filter(Boolean).join(" · ");
  return `<a class="asset-pill" href="${link}"><b>${esc(a.name)}</b>${meta ? ` <span class="muted">${meta}</span>` : ""}</a>`;
}

// Toggle the impacted-assets detail row under a vulnerability row.
async function toggleAssets(btn: HTMLButtonElement): Promise<void> {
  const vid = Number(btn.dataset.vid);
  const tr = btn.closest("tr") as HTMLTableRowElement | null;
  if (!tr) return;
  const next = tr.nextElementSibling as HTMLElement | null;
  if (next && next.classList.contains("asset-detail")) { next.remove(); btn.textContent = btn.textContent!.replace("▴", "▾"); return; }
  btn.textContent = btn.textContent!.replace("▾", "▴");
  const detail = document.createElement("tr");
  detail.className = "asset-detail";
  detail.innerHTML = `<td colspan="4"><div class="asset-box"><span class="muted">${esc(t("exp.loadingAssets"))}</span></div></td>`;
  tr.parentElement!.insertBefore(detail, tr.nextSibling);
  try {
    const r = await fetch(`/api/fusion/vuln/${vid}/assets`);
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    const list = (d.assets || []) as ImpactedAsset[];
    detail.querySelector(".asset-box")!.innerHTML = list.length
      ? `<div class="asset-box-h">${esc(t("exp.impactedAssets"))} (${list.length})</div>${list.map(assetItemHtml).join("")}`
      : `<span class="muted">${esc(t("exp.noAssets"))}</span>`;
  } catch (e) { detail.querySelector(".asset-box")!.innerHTML = `<span class="muted">⚠️ ${esc(e)}</span>`; }
}

async function load(): Promise<void> {
  let d: { results: Fusion[]; scanned: number };
  try { const r = await fetch("/api/fusion/top?limit=100"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("ex-results").innerHTML = `<div class="ex-empty">⚠️ ${esc(e)}</div>`; return; }
  $("ex-info").textContent = `${d.scanned.toLocaleString()} ${t("exp.scanned")} · ${t("exp.showing")} ${d.results.length}`;
  if (!d.results.length) { $("ex-results").innerHTML = `<div class="ex-empty">${esc(t("exp.none"))}</div>`; return; }
  $("ex-results").innerHTML = `<table class="ex"><thead><tr>
      <th>#</th><th>${esc(t("exp.colPriority"))}</th><th>${esc(t("exp.colVuln"))}</th><th>${esc(t("exp.colSignals"))}</th>
    </tr></thead><tbody>${d.results.map(row).join("")}</tbody></table>`;
  $("ex-results").querySelectorAll<HTMLButtonElement>(".asset-toggle").forEach((b) => b.addEventListener("click", () => void toggleAssets(b)));
}

function mdLite(s: string): string {
  return String(s || "").split(/\n/).map((raw) => {
    const l = esc(raw).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>");
    if (/^#{1,6}\s/.test(raw)) return `<div style="font-weight:600;color:#e2e8f0;margin:8px 0 3px">${l.replace(/^#{1,6}\s*/, "")}</div>`;
    if (/^\s*[-*]\s/.test(raw)) return `<div style="margin-left:8px">• ${l.replace(/^\s*[-*]\s*/, "")}</div>`;
    if (!raw.trim()) return '<div style="height:6px"></div>';
    return `<div>${l}</div>`;
  }).join("");
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("ex-ai").addEventListener("click", async () => {
    const btn = $("ex-ai") as HTMLButtonElement; btn.disabled = true;
    const panel = $("ex-brief"); panel.style.display = "block"; panel.innerHTML = `<span class="muted">🧠 ${esc(t("exp.briefing"))}</span>`;
    try {
      const r = await fetch("/api/ai/exposure-brief", { method: "POST" });
      const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      panel.innerHTML = `<div class="muted" style="margin-bottom:5px">${d.offline ? esc(t("exp.aiOffline")) : "model: " + esc(d.model)}</div>` + mdLite(d.brief);
    } catch (e) { panel.innerHTML = `<span class="muted">⚠️ ${esc(e)}</span>`; }
    finally { btn.disabled = false; }
  });
  void load();
});
