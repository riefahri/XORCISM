/**
 * csf-maturity.ts — NIST CSF 2.0 maturity self-assessment (/csf-maturity).
 * Renders the 6-function rollup + 5-level scale + per-subcategory current/target scoring
 * (inline selects POST to /api/csf-maturity/score), from /api/csf-maturity.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Level { score: number; name: string; description: string; }
interface Row { id: number; functionCode: string; functionName: string; categoryCode: string; categoryName: string; sub: string; outcome: string; current: number | null; target: number | null; gap: number; notes: string; }
interface Fn { code: string; name: string; subs: number; scored: number; current: number | null; target: number | null; gap: number | null; categories: { code: string; name: string; subs: number; scored: number; current: number | null }[]; }
interface Inv {
  levels: Level[]; functions: Fn[]; rows: Row[];
  worklist: { id: number; sub: string; functionCode: string; outcome: string; current: number | null; target: number | null; gap: number; severity: string }[];
  summary: { subcategories: number; scored: number; coverage: number; overallCurrent: number | null; overallTarget: number | null; maturityScore: number; belowTarget: number; gaps: number; withTarget: number };
}

const LCOL = ["#475569", "#ef4444", "#fb923c", "#fbbf24", "#a3e635", "#10b981"]; // index 0=unset, 1..5 maturity
const scoreColor = (n: number): string => (n >= 80 ? "#10b981" : n >= 50 ? "#fbbf24" : n >= 25 ? "#fb923c" : "#ef4444");
const lc = (n: number | null): string => LCOL[n == null ? 0 : Math.max(0, Math.min(5, n))];

function card(lbl: string, val: string, foot: string, color?: string, cls = "cf-card"): string {
  return `<div class="${cls}"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}

function levelOpts(levels: Level[], sel: number | null): string {
  return `<option value=""${sel == null ? " selected" : ""}>—</option>` +
    levels.map((l) => `<option value="${l.score}"${sel === l.score ? " selected" : ""}>L${l.score} ${esc(l.name)}</option>`).join("");
}

function fnRow(f: Fn): string {
  const curPct = f.current != null ? (f.current / 5) * 100 : 0;
  const tgtPct = f.target != null ? (f.target / 5) * 100 : null;
  return `<div class="fn">
    <div class="nm">${esc(f.name)} <span class="c">${esc(f.code)}</span></div>
    <div class="track"><i style="width:${curPct}%;background:${lc(f.current != null ? Math.round(f.current) : null)}"></i>${tgtPct != null ? `<span class="tgt" style="left:${tgtPct}%" title="target ${f.target}"></span>` : ""}</div>
    <div class="meta">${f.current != null ? `<b style="color:#e2e8f0">${f.current}</b>${f.target != null ? ` / ${f.target}` : ""} · ${f.scored}/${f.subs}` : `<span class="muted">not assessed</span>`}</div>
  </div>`;
}

function subRow(r: Row, levels: Level[]): string {
  return `<tr>
    <td class="scode">${esc(r.sub)}</td>
    <td>${esc(r.outcome)}</td>
    <td><select class="lvsel" data-sub="${r.id}" data-kind="current">${levelOpts(levels, r.current)}</select></td>
    <td><select class="lvsel" data-sub="${r.id}" data-kind="target">${levelOpts(levels, r.target)}</select></td>
    <td>${r.gap > 0 ? `<span class="gap">gap ${r.gap}</span>` : (r.current != null && r.target != null ? '<span class="muted">on target</span>' : "")}</td>
  </tr>`;
}

async function saveScore(subId: number, kind: string, value: string): Promise<boolean> {
  const body: Record<string, unknown> = { subId };
  body[kind === "current" ? "currentLevel" : "targetLevel"] = value === "" ? null : Number(value);
  try {
    const r = await fetch("/api/csf-maturity/score", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    return r.ok;
  } catch { return false; }
}

async function seedDemo(btn: HTMLButtonElement): Promise<void> {
  btn.disabled = true; const orig = btn.textContent; btn.textContent = "Seeding…";
  try {
    const r = await fetch("/api/csf-maturity/seed", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    if (r.ok) { await load(); return; }
  } catch { /* */ }
  btn.disabled = false; btn.textContent = orig;
}

async function load(): Promise<void> {
  let d: Inv;
  try { const r = await fetch("/api/csf-maturity"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("cf-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  if (!d.levels.length) { $("cf-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">CSF catalogue not seeded yet.</div>`; return; }
  const s = d.summary;

  const cards = [
    card("Maturity score", `${s.maturityScore}%`, s.overallCurrent != null ? `avg L${s.overallCurrent} of 5` : "not assessed", scoreColor(s.maturityScore), "cf-card cf-score"),
    card("Overall maturity", s.overallCurrent != null ? `L${s.overallCurrent}` : "—", s.overallTarget != null ? `target L${s.overallTarget}` : "no target set"),
    card("Coverage", `${s.coverage}%`, `${s.scored}/${s.subcategories} subcategories scored`, s.coverage >= 80 ? "#34d399" : s.coverage >= 40 ? "#fbbf24" : "#fb923c"),
    card("Gaps to target", String(s.gaps), s.gaps ? "subcategories below target" : "all on target", s.gaps ? "#fbbf24" : "#34d399"),
    card("Subcategories", String(s.subcategories), "6 functions · 22 categories"),
  ].join("");

  const fns = d.functions.map(fnRow).join("");

  const worklist = d.worklist.length
    ? `<ul class="worklist">${d.worklist.map((w) => `<li><span class="sev-${esc(w.severity)}">${esc(w.severity)}</span> · <span class="scode">${esc(w.sub)}</span> — ${esc(w.outcome)} <span class="gap">L${w.current ?? "?"}→L${w.target ?? "?"} (gap ${w.gap})</span></li>`).join("")}</ul>`
    : `<div class="muted" style="padding:8px 0">No gaps — every scored subcategory meets its target.</div>`;

  // table grouped by function
  let table = `<table class="cf"><thead><tr><th>ID</th><th>Outcome</th><th>Current</th><th>Target</th><th></th></tr></thead><tbody>`;
  for (const f of d.functions) {
    table += `<tr class="fhead"><td colspan="5">${esc(f.name)} (${esc(f.code)}) — ${f.subs} subcategories${f.current != null ? ` · current L${f.current}${f.target != null ? ` / target L${f.target}` : ""}` : ""}</td></tr>`;
    for (const r of d.rows.filter((x) => x.functionCode === f.code)) table += subRow(r, d.levels);
  }
  table += `</tbody></table>`;

  const scale = d.levels.map((l) => `<div class="lv" style="border-left-color:${lc(l.score)}"><div class="ln" style="color:${lc(l.score)}">L${l.score}</div><div><div class="lt">${esc(l.name)}</div><div class="ld">${esc(l.description)}</div></div></div>`).join("");

  $("cf-body").innerHTML = `<div class="cf-cards">${cards}</div>
    <div class="cf-section">Maturity by function (current ▸ marker = target)</div>${fns}
    <div class="cf-section" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">Top gaps to target (${d.worklist.length})
      ${s.scored === 0 ? `<button id="cf-seed" class="cf-go" title="Seed a realistic demo maturity profile">Seed demo profile</button>` : ""}</div>${worklist}
    <div class="cf-section">Assessment — score each subcategory (current vs target)</div>${table}
    <div class="cf-section">Maturity scale (CMMI-style)</div>${scale}
    <div class="legend">CSF 2.0 Core (functions, categories, subcategories) is a U.S. Government work in the public domain. Scores are stored per organisation; the maturity score is the average current level ÷ 5.</div>`;

  document.querySelectorAll<HTMLSelectElement>("select.lvsel").forEach((sel) => {
    sel.addEventListener("change", () => { void saveScore(Number(sel.dataset.sub), String(sel.dataset.kind), sel.value); });
  });
  const seed = document.getElementById("cf-seed") as HTMLButtonElement | null;
  if (seed) seed.addEventListener("click", () => void seedDemo(seed));
}

document.addEventListener("DOMContentLoaded", () => { void load(); });
