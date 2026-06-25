/**
 * crisis-management.ts — Crisis management & tabletop-exercise readiness (/crisis-management).
 * Exercises + scenario library + improvement worklist, from /api/crisis-management.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface ExerciseRow { id: number; name: string; scenario: string; type: string; status: string; date: string | null; completed: boolean; injects: number; injectsDone: number; participants: number; actions: number; highActions: number; overdue: number; hasAAR: boolean; score: number; }
interface ScenarioRow { id: number; name: string; type: string; severity: string; injects: number; exercised: boolean; }
interface Finding { id: number; exercise: string; name: string; severity: "Critical" | "High" | "Medium" | "Low" | "Info"; overdue: boolean; unassigned: boolean; kind: "action" | "scenario" | "exercise"; label: string; }
interface Inventory {
  rows: ExerciseRow[]; findings: Finding[]; scenarios: ScenarioRow[];
  summary: { exercises: number; planned: number; inProgress: number; completed: number; completionRate: number | null; scenarios: number; scenariosNeverExercised: number; scenarioCoverage: number; openActions: number; highActions: number; overdueActions: number; participants: number; withoutAAR: number; readinessScore: number; byType: Record<string, number>; byStatus: Record<string, number>; };
}

const sevClass = (s: string): string => `s-${(s || "low").toLowerCase()}`;
const stClass = (s: string): string => (/complet|clos|done|conduct/i.test(s) ? "st-completed" : /progress|cours|ongoing/i.test(s) ? "st-progress" : "st-planned");
const scoreClass = (n: number): string => (n >= 30 ? "s-hi" : n >= 10 ? "s-md" : "s-lo");
const readyColor = (n: number): string => (n >= 70 ? "#34d399" : n >= 40 ? "#fbbf24" : "#f87171");

function card(lbl: string, val: string, foot: string, color?: string, cls = "cr-card"): string {
  return `<div class="${cls}"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rowHtml(r: ExerciseRow): string {
  const pct = r.injects ? Math.round((r.injectsDone / r.injects) * 100) : 0;
  const injCell = r.injects
    ? `${r.injectsDone}/${r.injects}<div class="prog"><span style="width:${pct}%"></span></div>`
    : `<span class="muted">—</span>`;
  const posture = r.actions
    ? `<span class="pill p-open">${fmt("cris.open", { n: r.actions })}</span>${r.highActions ? `<span class="pill p-high">${fmt("cris.high", { n: r.highActions })}</span>` : ""}${r.overdue ? `<span class="tag">${fmt("cris.overdueN", { n: r.overdue })}</span>` : ""}`
    : `<span class="pill p-clean">${t("cris.clean")}</span>`;
  const aar = r.completed ? (r.hasAAR ? `<span class="pill p-aar">AAR</span>` : `<span class="pill p-noaar">${t("cris.noAar")}</span>`) : `<span class="muted">—</span>`;
  return `<tr>
    <td><div class="aname">${esc(r.name)}</div><div class="muted" style="font-size:11px">${esc(r.scenario)}${r.date ? ` · ${esc(r.date)}` : ""}</div></td>
    <td><span class="st ${stClass(r.status)}">${esc(r.status)}</span></td>
    <td>${injCell}</td>
    <td>${r.participants || `<span class="muted">0</span>`}</td>
    <td>${posture}</td>
    <td>${aar}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
    <td><a class="scn-run" href="/crisis-exercise?audit=${r.id}" title="${t("cris.runTitle")}">${t("cris.run")}</a></td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  const color = f.kind === "scenario" ? "#e11d48" : f.kind === "exercise" ? "#38bdf8" : "#fb923c";
  const href = f.kind === "scenario" ? "/?db=XCOMPLIANCE&table=CRISISSCENARIO" : f.kind === "exercise" ? "/?db=XCOMPLIANCE&table=AUDIT" : "/?db=XCOMPLIANCE&table=AUDITFINDING";
  return `<li><span class="dot" style="background:${color}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> ·
    <a href="${href}">${esc(f.exercise)}</a> — ${esc(f.label)}</li>`;
}

function scenarioHtml(s: ScenarioRow): string {
  const run = s.exercised
    ? `<span class="scn-done">${t("cris.exercised")}</span>`
    : `<button class="scn-run" data-scn="${s.id}" data-name="${esc(s.name)}" title="${t("cris.runExerciseTitle")}">${t("cris.runExercise")}</button>`;
  return `<div class="scn-card">
    <div class="t">${esc(s.name)}</div>
    <div class="m"><span class="sev ${sevClass(s.severity)}">${esc(s.severity)}</span> · ${esc(s.type)} · ${fmt("cris.nInjects", { n: s.injects })}</div>
    ${run}
  </div>`;
}

async function launch(btn: HTMLButtonElement): Promise<void> {
  const id = Number(btn.dataset.scn);
  if (!id) return;
  btn.disabled = true; const orig = btn.textContent; btn.textContent = t("cris.scheduling");
  try {
    const r = await fetch("/api/crisis-management/launch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scenarioId: id }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    btn.outerHTML = `<span class="scn-done">${fmt("cris.exerciseCreated", { id: esc(d.auditId), injects: esc(d.injects) })}</span>`;
  } catch (e) { btn.disabled = false; btn.textContent = orig; const sp = document.createElement("span"); sp.className = "scn-done"; sp.style.color = "#f87171"; sp.textContent = ` ⚠ ${e}`; btn.after(sp); }
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/crisis-management"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("cr-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!d.rows.length && !d.scenarios.length) {
    $("cr-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("cris.empty")}</div>`;
    return;
  }

  const cards = [
    card(t("cris.cReadiness"), `${s.readinessScore}`, t("cris.cReadiness.foot"), readyColor(s.readinessScore), "cr-card cr-ready"),
    card(t("cris.cExercises"), String(s.exercises), fmt("cris.cExercises.foot", { p: s.planned, c: s.completed })),
    card(t("cris.cCoverage"), `${s.scenarioCoverage}%`, fmt("cris.cCoverage.foot", { e: s.scenarios - s.scenariosNeverExercised, t: s.scenarios }), s.scenarioCoverage >= 60 ? "#34d399" : s.scenarioCoverage >= 30 ? "#fbbf24" : "#f87171"),
    card(t("cris.cActions"), String(s.openActions), fmt("cris.cActions.foot", { n: s.highActions }), s.openActions ? "#fb923c" : "#34d399"),
    card(t("cris.cOverdue"), String(s.overdueActions), t("cris.cOverdue.foot"), s.overdueActions ? "#f87171" : "#34d399"),
    card(t("cris.cNoAar"), String(s.withoutAAR), t("cris.cNoAar.foot"), s.withoutAAR ? "#fbbf24" : "#34d399"),
  ].join("");

  const byType = Object.entries(s.byType).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">${fmt("cris.more", { n: d.findings.length - 60 })}</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">${t("cris.noFindings")}</div>`;

  const scenarios = d.scenarios.length
    ? `<div class="scn">${d.scenarios.map(scenarioHtml).join("")}</div>`
    : `<div class="muted" style="padding:12px 0">${t("cris.noScenarios")}</div>`;

  const table = d.rows.length ? `<table class="cr"><thead><tr>
      <th>${t("cris.thExercise")}</th><th>${t("cris.thStatus")}</th><th title="${t("cris.thInjects.title")}">${t("cris.thInjects")}</th><th>${t("cris.thPeople")}</th><th>${t("cris.thActions")}</th><th title="${t("cris.thAar.title")}">AAR</th><th title="${t("cris.thScore.title")}">${t("cris.thScore")}</th><th></th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`
    : `<div class="muted" style="padding:12px 0">${t("cris.noExercises")}</div>`;

  $("cr-body").innerHTML = `<div class="cr-cards">${cards}</div>
    <div class="cr-section">${fmt("cris.secWorklist", { n: d.findings.length })}</div>${findings}
    <div class="cr-section">${fmt("cris.secLibrary", { n: d.scenarios.length })}</div>${scenarios}
    ${byType ? `<div class="cr-section">${t("cris.secByType")}</div><div class="breakdown">${byType}</div>` : ""}
    <div class="cr-section">${fmt("cris.secExercises", { n: d.rows.length })}</div>${table}
    <div class="legend">${t("cris.legend")}</div>`;

  $("cr-body").addEventListener("click", (ev) => {
    const t = ev.target as HTMLElement;
    if (t && t.classList.contains("scn-run")) void launch(t as HTMLButtonElement);
  });
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
