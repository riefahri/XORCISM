/**
 * risk-register.ts — Risk Register inventory + treatment worklist (/risk-register).
 * Inherent→residual posture, treatment, CRQ/FAIR ALE, from /api/risk-register.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Row { id: number; ref: string; title: string; category: string; owner: string | null; asset: string | null; status: string; open: boolean; inherent: string; current: string; residual: string; residualRank: number; treatment: string; hasPlan: boolean; ale: number | null; sle: number | null; currency: string; reviewInDays: number | null; reviewOverdue: boolean; score: number; }
interface Finding { id: number; ref: string; title: string; severity: "Critical" | "High" | "Medium" | "Low" | "Info"; reason: string; kind: string; label: string; }
interface Inventory {
  rows: Row[]; findings: Finding[];
  summary: { risks: number; open: number; closed: number; treatedRate: number | null; highCritical: number; untreated: number; accepted: number; overdueReview: number; noOwner: number; quantified: number; totalALE: number; currency: string; byLevel: Record<string, number>; byStatus: Record<string, number>; byTreatment: Record<string, number>; byCategory: Record<string, number>; riskScore: number; };
}

let CUR = "EUR";
const rankOf = (label: string): number => ({ critical: 0, "very high": 0, high: 1, medium: 2, moderate: 2, low: 3, "very low": 4 }[label.toLowerCase()] ?? 5);
const lvl = (label: string): string => `<span class="lvl lvl-${rankOf(label)}">${esc(label)}</span>`;
const scoreClass = (n: number): string => (n >= 50 ? "s-hi" : n >= 25 ? "s-md" : "s-lo");
const postureColor = (n: number): string => (n >= 60 ? "#f87171" : n >= 35 ? "#fbbf24" : "#34d399");
function money(n: number | null): string {
  if (n == null) return "—";
  try { return new Intl.NumberFormat(undefined, { style: "currency", currency: CUR, maximumFractionDigits: 0 }).format(n); }
  catch { return `${CUR} ${Math.round(n).toLocaleString()}`; }
}

function card(lbl: string, val: string, foot: string, color?: string, cls = "rr-card"): string {
  return `<div class="${cls}"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rowHtml(r: Row): string {
  const treat = r.treatment !== "—" ? `<span class="tr">${esc(r.treatment)}</span>${r.hasPlan ? "" : ` <span class="muted" style="font-size:11px">no plan</span>`}` : `<span class="tag">untreated</span>`;
  const review = r.reviewInDays == null ? `<span class="muted">—</span>` : r.reviewOverdue ? `<span class="tag">${-r.reviewInDays}d overdue</span>` : `<span class="muted">${r.reviewInDays}d</span>`;
  return `<tr>
    <td><div class="rname">${esc(r.ref)} <span style="font-weight:400">${esc(r.title)}</span></div>
      <div class="muted" style="font-size:11px">${esc(r.category)}${r.owner ? ` · ${esc(r.owner)}` : ""}${r.asset ? ` · ${esc(r.asset)}` : ""}</div></td>
    <td>${lvl(r.inherent)}<span class="arrow">→</span>${lvl(r.residual)}</td>
    <td>${treat}</td>
    <td><span class="st ${r.open ? "st-open" : "st-closed"}">${esc(r.status)}</span></td>
    <td class="num">${r.ale != null ? `<b>${esc(money(r.ale))}</b>` : "<span class=\"muted\">—</span>"}</td>
    <td>${review}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  const color = f.kind === "untreated" ? "#f87171" : f.kind === "accepted" ? "#fb923c" : f.kind === "owner" ? "#64748b" : "#fbbf24";
  return `<li><span class="dot" style="background:${color}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> ·
    <a href="/?db=XCOMPLIANCE&table=RISKREGISTERENTRY&filterCol=RiskRegisterEntryID&filterVal=${esc(f.id)}">${esc(f.ref)}</a>
    ${f.title ? `<span class="muted">${esc(f.title)}</span> — ` : "— "}${esc(f.label)}</li>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/risk-register"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("rr-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  CUR = d.summary.currency || "EUR";
  const s = d.summary;

  if (!d.rows.length) {
    $("rr-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">
      No risks in the register yet. <a href="/?db=XCOMPLIANCE&table=RISKREGISTERENTRY">Add your first risk</a>
      (inherent &amp; residual level, treatment, owner, review — optionally CRQ/FAIR ALE), and the
      governance worklist appears here.</div>`;
    return;
  }

  const cards = [
    card("Residual posture", String(s.riskScore), "open risks · severity-weighted", postureColor(s.riskScore), "rr-card rr-score"),
    card("Open risks", String(s.open), `${s.closed} closed · ${s.risks} total`),
    card("High / critical", String(s.highCritical), "open · residual", s.highCritical ? "#f87171" : "#34d399"),
    card("Untreated", String(s.untreated), "high/critical · no plan", s.untreated ? "#f87171" : "#34d399"),
    card("Overdue reviews", String(s.overdueReview), "past review date", s.overdueReview ? "#fbbf24" : "#34d399"),
    card("Treated", s.treatedRate != null ? `${s.treatedRate}%` : "—", "open risks with a plan", s.treatedRate != null ? (s.treatedRate >= 70 ? "#34d399" : s.treatedRate >= 40 ? "#fbbf24" : "#f87171") : undefined),
    card("Annualized exposure", money(s.totalALE), `${s.quantified}/${s.risks} quantified (FAIR)`),
  ].join("");

  const byLevel = ["Critical", "High", "Medium", "Low", "Very Low"].filter((k) => s.byLevel[k]).map((k) => `<span class="bd">${lvl(k)} <b>${s.byLevel[k]}</b></span>`).join("");
  const byTreat = Object.entries(s.byTreatment).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");
  const byCat = Object.entries(s.byCategory).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">+${d.findings.length - 60} more…</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">✓ No untreated risks, overdue reviews or governance gaps — clean risk posture.</div>`;

  const table = `<table class="rr"><thead><tr>
      <th>Risk</th><th title="inherent → residual">Inherent → Residual</th><th>Treatment</th><th>Status</th><th class="num" title="Annualized Loss Expectancy (FAIR)">ALE</th><th title="next review">Review</th><th title="priority score">Score</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("rr-body").innerHTML = `<div class="rr-cards">${cards}</div>
    <div class="rr-section">Treatment worklist (${d.findings.length})</div>${findings}
    <div class="rr-section">Open risks by residual level</div><div class="breakdown">${byLevel || '<span class="muted">none</span>'}</div>
    ${byTreat ? `<div class="rr-section">By treatment strategy</div><div class="breakdown">${byTreat}</div>` : ""}
    ${byCat ? `<div class="rr-section">By category</div><div class="breakdown">${byCat}</div>` : ""}
    <div class="rr-section">Risks (${d.rows.length})</div>${table}
    <div class="legend">↳ <b>Score</b> is a risk's priority (higher = worse): residual severity + ALE + overdue review +
      untreated high/critical + no owner. <b>Treated</b> = open risks with a treatment plan or an explicit accept.
      <b>ALE</b> = Annualized Loss Expectancy from the risk's CRQ/FAIR fields; decompose a single loss with
      <a href="/fair-mam">FAIR-MAM</a>. Manage under <a href="/?db=XCOMPLIANCE&table=RISKREGISTERENTRY">Risk entries</a>.</div>`;
}

// ── Guided "new risk" modal ───────────────────────────────────────────────────
let lookupsLoaded = false;

function inherentPreview(): void {
  const prob = Number((document.getElementById("rr-f-prob") as HTMLSelectElement).value);
  const impact = Number((document.getElementById("rr-f-impact") as HTMLSelectElement).value);
  const el = $("rr-f-preview");
  if (!prob || !impact) { el.textContent = "Set likelihood × impact"; el.style.color = "#64748b"; return; }
  const s = prob * impact;
  const [label, color] = s >= 20 ? ["Critical", "#f87171"] : s >= 12 ? ["High", "#fb923c"]
    : s >= 6 ? ["Medium", "#fbbf24"] : s >= 3 ? ["Low", "#86efac"] : ["Very Low", "#94a3b8"];
  el.innerHTML = `<b style="color:${color}">${label}</b> <span class="muted">(${prob}×${impact} = ${s})</span>`;
}

async function fillSelect(selId: string, db: string, table: string, idCol: string, labelCol: string): Promise<void> {
  try {
    const r = await fetch(`/api/lookup?db=${db}&table=${table}&idCol=${idCol}&labelCol=${labelCol}`);
    if (!r.ok) return;
    const list = (await r.json()) as { id: unknown; label: unknown }[];
    const sel = document.getElementById(selId) as HTMLSelectElement;
    for (const o of (Array.isArray(list) ? list : []).slice(0, 500)) {
      if (o.label == null || String(o.label).trim() === "") continue;
      const opt = document.createElement("option");
      opt.value = String(o.id); opt.textContent = String(o.label);
      sel.appendChild(opt);
    }
  } catch { /* optional */ }
}

function openRiskModal(): void {
  for (const id of ["rr-f-title", "rr-f-desc", "rr-f-review", "rr-f-target"]) (document.getElementById(id) as HTMLInputElement).value = "";
  for (const id of ["rr-f-category", "rr-f-owner", "rr-f-prob", "rr-f-impact", "rr-f-treatment", "rr-f-asset"]) (document.getElementById(id) as HTMLSelectElement).value = "";
  (document.getElementById("rr-f-status") as HTMLSelectElement).value = "Open";
  $("rr-f-err").textContent = "";
  inherentPreview();
  if (!lookupsLoaded) {
    lookupsLoaded = true;
    void fillSelect("rr-f-owner", "XORCISM", "PERSON", "PersonID", "FullName");
    void fillSelect("rr-f-asset", "XORCISM", "ASSET", "AssetID", "AssetName");
  }
  $("rr-modal").classList.add("open");
  ($("rr-f-title") as HTMLInputElement).focus();
}
function closeRiskModal(): void { $("rr-modal").classList.remove("open"); }

function toast(html: string): void {
  const el = $("toast");
  el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #34d399;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 8000);
}

async function createRisk(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  const title = v("rr-f-title").trim();
  const err = $("rr-f-err");
  if (!title) { err.textContent = "⚠️ Enter a title."; ($("rr-f-title") as HTMLInputElement).focus(); return; }
  const btn = $("rr-create") as HTMLButtonElement;
  btn.disabled = true; err.textContent = "Creating…";
  try {
    const body = {
      title, description: v("rr-f-desc").trim() || undefined, category: v("rr-f-category") || undefined,
      ownerPersonId: v("rr-f-owner") || undefined, assetId: v("rr-f-asset") || undefined,
      probability: v("rr-f-prob") || undefined, impact: v("rr-f-impact") || undefined,
      treatment: v("rr-f-treatment") || undefined, status: v("rr-f-status"),
      reviewDate: v("rr-f-review") || undefined, targetDate: v("rr-f-target") || undefined,
    };
    const r = await fetch("/api/risk-register/entry", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeRiskModal();
    await load();
    const link = `/?db=XCOMPLIANCE&table=RISKREGISTERENTRY&editCol=RiskRegisterEntryID&editVal=${d.id}`;
    toast(`✅ Risk added to the register — <a href="${link}" style="color:#7dd3fc">open it ↗</a>`);
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  $("rr-new").addEventListener("click", openRiskModal);
  $("rr-cancel").addEventListener("click", closeRiskModal);
  $("rr-create").addEventListener("click", () => void createRisk());
  for (const id of ["rr-f-prob", "rr-f-impact"]) (document.getElementById(id) as HTMLSelectElement).addEventListener("change", inherentPreview);
  $("rr-modal").addEventListener("click", (e) => { if (e.target === $("rr-modal")) closeRiskModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeRiskModal(); });
  void load();
});
