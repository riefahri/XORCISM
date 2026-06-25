/**
 * fair-mam.ts — FAIR-MAM materiality assessment (/fair-mam). An interactive loss-decomposition
 * calculator over the FAIR-MAM taxonomy + a list of saved assessments, from /api/fair-mam.
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const tfmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
const partyLabel = (p: string): string => t(p === "third-party" ? "fm.thirdParty" : "fm.firstParty");
const lossLabel = (l: string): string => t(l === "secondary" ? "fm.secondary" : "fm.primary");
const detLabel = (d: string): string => { const k: Record<string, string> = { "Material": "fm.det.material", "Approaching": "fm.det.approaching", "Not material": "fm.det.not", "Unassessed": "fm.det.unassessed" }; return k[d] ? t(k[d]) : d; };

interface Cat { id: number; code: string; name: string; parent: string | null; lossType: "primary" | "secondary"; party: "first-party" | "third-party"; description: string; sortOrder: number; }
interface Assessment { id: number; name: string; scenarioRef: string | null; currency: string; total: number; primary: number; secondary: number; firstParty: number; thirdParty: number; threshold: number | null; ratio: number | null; determination: string; lineCount: number; createdDate: string | null; }
interface Risk { id: number; ref: string; title: string; }
interface Inventory {
  categories: Cat[]; assessments: Assessment[]; risks: Risk[];
  summary: { assessments: number; material: number; approaching: number; largestExposure: number; totalExposure: number; currency: string; avgPrimaryShare: number | null };
}

let CATS: Cat[] = [];
let RISKS: Risk[] = [];
let CUR = "EUR";

function fmt(n: number): string {
  try { return new Intl.NumberFormat(undefined, { style: "currency", currency: CUR, maximumFractionDigits: 0 }).format(n || 0); }
  catch { return `${CUR} ${Math.round(n || 0).toLocaleString()}`; }
}
const pert = (lo: number, m: number, hi: number): number => {
  const a = [lo, m, hi].map((x) => (Number.isFinite(x) ? x : NaN));
  if (a.every((x) => Number.isFinite(x))) return (a[0] + 4 * a[1] + a[2]) / 6;
  if (Number.isFinite(a[1])) return a[1];
  const v = [a[0], a[2]].filter((x) => Number.isFinite(x));
  return v.length ? v.reduce((s, x) => s + x, 0) / v.length : 0;
};
const verdictClass = (d: string): string => `v-${d.toLowerCase().replace(/[^a-z]/g, "").replace("notmaterial", "not")}`;

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="fm-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

/** Build the calculator table: leaf categories (those with no children) grouped by top-level. */
function calcTable(): string {
  const childrenOf = new Set(CATS.filter((c) => c.parent).map((c) => c.parent));
  const isLeaf = (c: Cat): boolean => !CATS.some((x) => x.parent === c.code);
  const tops = CATS.filter((c) => !c.parent);
  const rowsFor = (loss: "primary" | "secondary"): string => tops.filter((t) => t.lossType === loss).map((t) => {
    const leaves = isLeaf(t) ? [t] : CATS.filter((c) => c.parent === t.code);
    const head = `<tr class="fm-grp"><td colspan="5">${esc(t.name)}<span class="pp pp-${t.lossType}">${lossLabel(t.lossType)}</span> <span class="muted" style="font-weight:400;text-transform:none">· ${esc(partyLabel(t.party))}</span></td></tr>`;
    const body = leaves.map((c) => `<tr data-row="${c.id}">
      <td><div class="cat-name">${esc(c.code === t.code ? c.name : c.name)}</div>${c.description ? `<div class="cat-d">${esc(c.description)}</div>` : ""}</td>
      <td class="num"><input class="fm-in" type="number" min="0" step="1000" data-cat="${c.id}" data-k="min" placeholder="0"></td>
      <td class="num"><input class="fm-in" type="number" min="0" step="1000" data-cat="${c.id}" data-k="ml" placeholder="0"></td>
      <td class="num"><input class="fm-in" type="number" min="0" step="1000" data-cat="${c.id}" data-k="max" placeholder="0"></td>
      <td class="num fm-exp" data-exp="${c.id}">—</td>
    </tr>`).join("");
    return head + body;
  }).join("");
  void childrenOf;
  return `<table class="fm"><thead><tr>
      <th>${t("fm.thCategory")}</th><th class="num">${t("fm.thMin")}</th><th class="num">${t("fm.thMl")}</th><th class="num">${t("fm.thMax")}</th><th class="num">${t("fm.thExpected")}</th>
    </tr></thead><tbody>
      <tr class="fm-grp"><td colspan="5" style="background:#0b1f17;color:#6ee7b7">${t("fm.bannerPrimary")}</td></tr>
      ${rowsFor("primary")}
      <tr class="fm-grp"><td colspan="5" style="background:#241a0b;color:#fcd34d">${t("fm.bannerSecondary")}</td></tr>
      ${rowsFor("secondary")}
    </tbody></table>`;
}

function recompute(): void {
  const get = (id: number, k: string): number => {
    const el = document.querySelector(`input[data-cat="${id}"][data-k="${k}"]`) as HTMLInputElement | null;
    const v = el ? parseFloat(el.value) : NaN; return Number.isFinite(v) ? v : NaN;
  };
  const catById = new Map(CATS.map((c) => [c.id, c]));
  let total = 0, primary = 0, secondary = 0, firstP = 0, thirdP = 0;
  const inputCats = new Set([...document.querySelectorAll("input.fm-in")].map((e) => Number((e as HTMLElement).dataset.cat)));
  for (const id of inputCats) {
    const e = pert(get(id, "min"), get(id, "ml"), get(id, "max"));
    const cell = document.querySelector(`[data-exp="${id}"]`);
    if (cell) cell.textContent = e ? fmt(e) : "—";
    if (!e) continue;
    total += e;
    const c = catById.get(id);
    if (c?.lossType === "secondary") secondary += e; else primary += e;
    if (c?.party === "third-party") thirdP += e; else firstP += e;
  }
  const thr = parseFloat((document.getElementById("fm-threshold") as HTMLInputElement)?.value || "");
  const threshold = Number.isFinite(thr) && thr > 0 ? thr : null;
  const det = !threshold ? "Unassessed" : total >= threshold ? "Material" : total >= 0.5 * threshold ? "Approaching" : "Not material";
  $("fm-total").textContent = fmt(total);
  $("fm-split").innerHTML = `${t("fm.primary")} <b>${fmt(primary)}</b> · ${t("fm.secondary")} <b>${fmt(secondary)}</b> &nbsp;|&nbsp; ${t("fm.firstParty")} <b>${fmt(firstP)}</b> · ${t("fm.thirdParty")} <b>${fmt(thirdP)}</b>${threshold ? ` &nbsp;|&nbsp; ${tfmt("fm.pctThreshold", { n: Math.round((total / threshold) * 100) })}` : ""}`;
  const v = $("fm-verdict"); v.textContent = detLabel(det); v.className = `fm-verdict ${verdictClass(det)}`;
}

async function save(): Promise<void> {
  const btn = $("fm-save") as HTMLButtonElement; const stat = $("fm-stat");
  const lines: { categoryId: number; min?: number; mostLikely?: number; max?: number }[] = [];
  for (const id of new Set([...document.querySelectorAll("input.fm-in")].map((e) => Number((e as HTMLElement).dataset.cat)))) {
    const num = (k: string): number | undefined => { const el = document.querySelector(`input[data-cat="${id}"][data-k="${k}"]`) as HTMLInputElement | null; const v = el ? parseFloat(el.value) : NaN; return Number.isFinite(v) ? v : undefined; };
    const min = num("min"), ml = num("ml"), mx = num("max");
    if (min != null || ml != null || mx != null) lines.push({ categoryId: id, min, mostLikely: ml, max: mx });
  }
  if (!lines.length) { stat.innerHTML = t("fm.errNoLines"); return; }
  const name = (document.getElementById("fm-name") as HTMLInputElement).value.trim() || undefined;
  const thr = parseFloat((document.getElementById("fm-threshold") as HTMLInputElement).value || "");
  const threshold = Number.isFinite(thr) && thr > 0 ? thr : undefined;
  const riskSel = document.getElementById("fm-risk") as HTMLSelectElement | null;
  const riskRegisterEntryId = riskSel && riskSel.value ? Number(riskSel.value) : undefined;
  btn.disabled = true; stat.textContent = t("fm.saving");
  try {
    const r = await fetch("/api/fair-mam/assess", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, currency: CUR, threshold, lines, riskRegisterEntryId }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    const wb = d.riskWriteback
      ? tfmt("fm.writeback", { sle: esc(fmt(d.riskWriteback.sle)), ale: d.riskWriteback.ale != null ? ` · ALE ${esc(fmt(d.riskWriteback.ale))}` : "", id: esc(d.riskWriteback.id), ref: esc(d.riskWriteback.ref) })
      : "";
    stat.innerHTML = `${tfmt("fm.saved", { id: esc(d.assessmentId), total: esc(fmt(d.total)), det: esc(detLabel(d.determination)) })}${wb} <a href="/fair-mam">${t("fm.refresh")}</a>`;
  } catch (e) { stat.innerHTML = `⚠️ ${esc(e)}`; }
  finally { btn.disabled = false; }
}

function savedTable(rows: Assessment[]): string {
  if (!rows.length) return `<div class="muted" style="padding:12px 0">${t("fm.noAssessments")}</div>`;
  return `<table class="fa"><thead><tr>
      <th>${t("fm.thAssessment")}</th><th class="num">${t("fm.thSingleLoss")}</th><th class="num">${t("fm.primary")}</th><th class="num">${t("fm.secondary")}</th><th class="num">${t("fm.thThreshold")}</th><th class="num">${t("fm.thPctThr")}</th><th>${t("fm.thDetermination")}</th>
    </tr></thead><tbody>${rows.map((a) => `<tr>
      <td>${esc(a.name)}${a.scenarioRef ? `<div class="muted" style="font-size:11px">${esc(a.scenarioRef)}</div>` : ""}<div class="muted" style="font-size:11px">${tfmt("fm.lines", { n: a.lineCount })}${a.createdDate ? ` · ${esc(a.createdDate)}` : ""}</div></td>
      <td class="num"><b>${esc(fmt(a.total))}</b></td>
      <td class="num">${esc(fmt(a.primary))}</td>
      <td class="num">${esc(fmt(a.secondary))}</td>
      <td class="num">${a.threshold != null ? esc(fmt(a.threshold)) : "<span class=\"muted\">—</span>"}</td>
      <td class="num">${a.ratio != null ? a.ratio + "%" : "<span class=\"muted\">—</span>"}</td>
      <td><span class="det det-${esc(a.determination.replace(/\s/g, ""))}">${esc(detLabel(a.determination))}</span></td>
    </tr>`).join("")}</tbody></table>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/fair-mam"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("fm-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  CATS = d.categories; RISKS = d.risks || []; CUR = d.summary.currency || "EUR";
  if (!CATS.length) { $("fm-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("fm.notSeeded")}</div>`; return; }
  const s = d.summary;

  const cards = [
    card(t("fm.cAssessments"), String(s.assessments), tfmt("fm.cAssessments.foot", { m: s.material, a: s.approaching })),
    card(t("fm.cMaterial"), String(s.material), t("fm.cMaterial.foot"), s.material ? "#f87171" : "#34d399"),
    card(t("fm.cLargest"), fmt(s.largestExposure), t("fm.cLargest.foot")),
    card(t("fm.cTotal"), fmt(s.totalExposure), tfmt("fm.cTotal.foot", { n: s.assessments })),
    card(t("fm.cAvgPrimary"), s.avgPrimaryShare != null ? `${s.avgPrimaryShare}%` : "—", t("fm.cAvgPrimary.foot")),
  ].join("");

  $("fm-body").innerHTML = `<div class="fm-cards">${cards}</div>
    <div class="fm-section">${t("fm.secCalc")}</div>
    <div class="fm-calc">
      <div class="fm-meta">
        <div class="fm-fld"><label>${t("fm.mName")}</label><input id="fm-name" type="text" placeholder="${t("fm.mNamePh")}" style="min-width:280px"></div>
        <div class="fm-fld"><label>${t("fm.mThreshold")}</label><input id="fm-threshold" type="number" min="0" step="100000" placeholder="${t("fm.mThresholdPh")}"></div>
        <div class="fm-fld"><label>${t("fm.mCurrency")}</label><select id="fm-currency"><option>EUR</option><option>USD</option><option>GBP</option><option>CHF</option></select></div>
        ${RISKS.length ? `<div class="fm-fld"><label>${t("fm.mLinkRisk")}</label><select id="fm-risk" style="min-width:240px"><option value="">${t("fm.optNone")}</option>${RISKS.map((r) => `<option value="${r.id}">${esc(r.ref)} — ${esc(r.title)}</option>`).join("")}</select></div>` : ""}
      </div>
      ${calcTable()}
      <div class="fm-tot">
        <div><div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase">${t("fm.expectedSingleLoss")}</div><div class="big fm-exp" id="fm-total">${fmt(0)}</div></div>
        <div><span id="fm-verdict" class="fm-verdict v-unassessed">${t("fm.det.unassessed")}</span><div class="fm-split" id="fm-split" style="margin-top:6px"></div></div>
        <button id="fm-save" class="fm-save">${t("fm.saveBtn")}</button>
        <div class="fm-stat" id="fm-stat"></div>
      </div>
    </div>
    <div class="fm-section">${tfmt("fm.secSaved", { n: d.assessments.length })}</div>${savedTable(d.assessments)}
    <div class="legend">${t("fm.legend")}</div>`;

  const curSel = document.getElementById("fm-currency") as HTMLSelectElement;
  if (curSel) { curSel.value = CUR; curSel.onchange = () => { CUR = curSel.value; recompute(); }; }
  $("fm-body").addEventListener("input", (ev) => { const t = ev.target as HTMLElement; if (t.classList.contains("fm-in") || t.id === "fm-threshold") recompute(); });
  ($("fm-save") as HTMLButtonElement).addEventListener("click", () => void save());
  recompute();
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
