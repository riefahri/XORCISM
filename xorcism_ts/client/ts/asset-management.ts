/**
 * asset-management.ts — Asset Management inventory + governance worklist (/asset-management).
 * Renders the asset estate with posture (owner / exposure / backup / controls / vulns) +
 * derived governance findings, from /api/asset-management. Fully i18n via t("asm.*").
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface AssetRow {
  id: number; name: string; criticality: string; owner: string | null; environment: string;
  exposure: "Internet" | "Internal"; backed: boolean; backupPlan: boolean; pii: boolean;
  businessValue: number | null; financialValue: number | null; riskScore: number | null;
  os: string; address: string; vulns: { open: number; kev: number; critical: number };
  controls: number; hasBia: boolean; lastChecked: string | null; flags: string[]; score: number;
}
interface AssetFinding { kind: string; label: string; severity: "Critical" | "High" | "Medium" | "Low"; assetId: number; asset: string; }
interface Inventory {
  rows: AssetRow[]; findings: AssetFinding[];
  summary: {
    total: number; crownJewels: number; internetFacing: number; pii: number;
    unbackedCritical: number; noOwner: number; withCriticalVulns: number; stale: number;
    byCriticality: Record<string, number>; byEnvironment: Record<string, number>;
  };
}

const critClass = (c: string): string => `c-${(c || "unrated").toLowerCase()}`;
const scoreClass = (n: number): string => (n >= 40 ? "s-hi" : n >= 15 ? "s-md" : "s-lo");
const yn = (b: boolean): string => (b ? `<span class="ok">✓</span>` : `<span class="no">✗</span>`);
// Exposure is a server enum ("Internet"/"Internal"); localize for display only.
const expLabel = (e: string): string => (e === "Internet" ? t("asm.exp.internet") : t("asm.exp.internal"));

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="am-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function vulnCell(v: AssetRow["vulns"]): string {
  if (!v.open) return `<span class="muted">—</span>`;
  const out: string[] = [];
  if (v.kev) out.push(`<span class="vbadge v-kev">${v.kev} KEV</span>`);
  if (v.critical) out.push(`<span class="vbadge v-crit">${fmt("asm.vb.crit", { n: v.critical })}</span>`);
  out.push(`<span class="vbadge v-open">${fmt("asm.vb.open", { n: v.open })}</span>`);
  return out.join("");
}

function rowHtml(r: AssetRow): string {
  const flags = r.flags.length ? r.flags.map((f) => `<span class="flag">${esc(f)}</span>`).join("") : `<span class="muted">—</span>`;
  return `<tr>
    <td><div class="aname">${esc(r.name)}</div>
      <div class="muted" style="font-size:11px">${esc(r.os || r.environment)}${r.address ? ` · ${esc(r.address)}` : ""}</div></td>
    <td><span class="crit ${critClass(r.criticality)}">${esc(r.criticality)}</span></td>
    <td>${esc(r.owner || "—")}</td>
    <td><span class="pill ${r.exposure === "Internet" ? "exp-internet" : "exp-internal"}">${esc(expLabel(r.exposure))}</span></td>
    <td>${yn(r.backed)}${r.backupPlan ? ` <span class="muted" style="font-size:11px">${t("asm.cell.plan")}</span>` : ""}</td>
    <td>${vulnCell(r.vulns)}</td>
    <td>${r.controls || `<span class="no">0</span>`} · ${r.hasBia ? `<span class="ok">BIA</span>` : `<span class="no">${t("asm.cell.noBia")}</span>`}</td>
    <td>${flags}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
  </tr>`;
}

function findingHtml(f: AssetFinding): string {
  // Click-through opens the ASSET explorer view filtered to the finding's asset (by name).
  const href = f.asset
    ? `/?db=XORCISM&table=ASSET&filterCol=AssetName&filterVal=${encodeURIComponent(f.asset)}`
    : "/?db=XORCISM&table=ASSET";
  return `<li><span class="sev-dot dot-${f.severity}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> —
    <a href="${esc(href)}">${esc(f.label)}</a></li>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/asset-management"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("am-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!d.rows.length) {
    $("am-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("asm.empty")}</div>`;
    return;
  }

  const cards = [
    card(t("asm.card.assets"), String(s.total), fmt("asm.card.assets.f", { n: s.crownJewels })),
    card(t("asm.card.internetFacing"), String(s.internetFacing), t("asm.card.internetFacing.f"), s.internetFacing ? "#fb923c" : "#34d399"),
    card(t("asm.card.kevCritical"), String(s.withCriticalVulns), t("asm.card.kevCritical.f"), s.withCriticalVulns ? "#f87171" : "#34d399"),
    card(t("asm.card.unbacked"), String(s.unbackedCritical), t("asm.card.unbacked.f"), s.unbackedCritical ? "#f87171" : "#34d399"),
    card(t("asm.card.noOwner"), String(s.noOwner), t("asm.card.noOwner.f"), s.noOwner ? "#fb923c" : "#34d399"),
    card(t("asm.card.pii"), String(s.pii), t("asm.card.pii.f"), s.pii ? "#fbbf24" : undefined),
    card(t("asm.card.stale"), String(s.stale), t("asm.card.stale.f"), s.stale ? "#fbbf24" : undefined),
  ].join("");

  const byCrit = Object.entries(s.byCriticality).sort((a, b) => b[1] - a[1])
    .map(([c, n]) => `<span class="bd"><span class="crit ${critClass(c)}">${esc(c)}</span> <b>${n}</b></span>`).join("");
  const byEnv = Object.entries(s.byEnvironment).sort((a, b) => b[1] - a[1])
    .map(([e, n]) => `<span class="bd">${esc(e)} <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">${fmt("asm.more", { n: d.findings.length - 60 })}</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">${t("asm.noFindings")}</div>`;

  const table = `<table class="am"><thead><tr>
      <th>${t("asm.th.asset")}</th><th>${t("asm.th.criticality")}</th><th>${t("asm.th.owner")}</th><th>${t("asm.th.exposure")}</th><th>${t("asm.th.backup")}</th><th>${t("asm.th.vulns")}</th><th>${t("asm.th.controlsBia")}</th><th>${t("asm.th.findings")}</th><th title="${t("asm.th.risk.title")}">${t("asm.th.risk")}</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("am-body").innerHTML = `<div class="am-cards">${cards}</div>
    <div class="am-section">${fmt("asm.sec.worklist", { n: d.findings.length })}</div>${findings}
    <div class="am-section">${t("asm.sec.byCriticality")}</div><div class="breakdown">${byCrit}</div>
    <div class="am-section">${t("asm.sec.byEnvironment")}</div><div class="breakdown">${byEnv}</div>
    <div class="am-section">${fmt("asm.sec.inventory", { n: d.rows.length })}</div>${table}
    <div class="legend">${t("asm.legend")}</div>`;
}

// ── Guided "new asset" modal ───────────────────────────────────────────────────
async function loadOwners(): Promise<void> {
  try {
    const r = await fetch("/api/lookup?db=XORCISM&table=PERSON&idCol=PersonID&labelCol=FullName");
    if (!r.ok) return;
    const list = (await r.json()) as { id: number; label: string }[];
    const sel = $("am-f-owner") as HTMLSelectElement;
    for (const p of list) { const o = document.createElement("option"); o.value = String(p.id); o.textContent = p.label || `#${p.id}`; sel.appendChild(o); }
  } catch { /* lookup unavailable */ }
}

function openModal(): void {
  for (const id of ["am-f-name", "am-f-os", "am-f-host", "am-f-ip", "am-f-bv", "am-f-fv", "am-f-notes"]) (document.getElementById(id) as HTMLInputElement).value = "";
  for (const id of ["am-f-crit", "am-f-env", "am-f-owner"]) (document.getElementById(id) as HTMLSelectElement).value = "";
  for (const id of ["am-f-public", "am-f-pii"]) (document.getElementById(id) as HTMLInputElement).checked = false;
  $("am-f-err").textContent = "";
  $("am-modal").classList.add("open");
  ($("am-f-name") as HTMLInputElement).focus();
}
function closeModal(): void { $("am-modal").classList.remove("open"); }

function toast(html: string): void {
  const el = $("toast");
  el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #34d399;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 8000);
}

async function createAsset(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  const ck = (id: string): boolean => (document.getElementById(id) as HTMLInputElement).checked;
  const name = v("am-f-name").trim();
  const err = $("am-f-err");
  if (!name) { err.textContent = `⚠️ ${t("asm.err.name")}`; ($("am-f-name") as HTMLInputElement).focus(); return; }
  const btn = $("am-create") as HTMLButtonElement;
  btn.disabled = true; err.textContent = `${t("asm.creating")}`;
  try {
    const body = {
      name, criticality: v("am-f-crit") || undefined, environment: v("am-f-env") || undefined,
      os: v("am-f-os").trim() || undefined, ownerPersonId: v("am-f-owner") || undefined,
      hostname: v("am-f-host").trim() || undefined, ip: v("am-f-ip").trim() || undefined,
      businessValue: v("am-f-bv").trim() || undefined, financialValue: v("am-f-fv") || undefined,
      publicFacing: ck("am-f-public"), hostPii: ck("am-f-pii"), notes: v("am-f-notes").trim() || undefined,
    };
    const r = await fetch("/api/asset-management/asset", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeModal();
    await load();
    const link = `/?db=XORCISM&table=ASSET&editCol=AssetID&editVal=${d.id}`;
    toast(fmt("asm.toast.created", { link }));
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

async function matchCves(): Promise<void> {
  const btn = $("am-match") as HTMLButtonElement;
  btn.disabled = true; const label = btn.textContent; btn.textContent = `${t("asm.matching")}`;
  try {
    const r = await fetch("/api/cve-match/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ days: 30 }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    await load();
    toast(d.newLinks
      ? fmt("asm.match.new", { n: d.newLinks, a: d.assetsAffected, x: d.assetsNotified, c: d.cvesScanned })
      : fmt("asm.match.none", { c: d.cvesScanned }));
  } catch (e) { toast(`⚠️ ${e}`); }
  finally { btn.disabled = false; btn.textContent = label; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("am-match").addEventListener("click", () => void matchCves());
  $("am-new").addEventListener("click", openModal);
  $("am-cancel").addEventListener("click", closeModal);
  $("am-create").addEventListener("click", () => void createAsset());
  $("am-modal").addEventListener("click", (e) => { if (e.target === $("am-modal")) closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
  ($("am-f-name") as HTMLInputElement).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void createAsset(); });
  void loadOwners();
  void load();
});
