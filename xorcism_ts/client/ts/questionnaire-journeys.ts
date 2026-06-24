/** questionnaire-journeys.ts — Guided QUESTIONNAIRE runner (/questionnaire-journeys). Questionnaire
 * catalogue (OCIL, CSA AI-CAIQ) → start run modal → sectioned runner with per-question answer +
 * comment + evidence (autosaved) + completion/conformance progress → submit. Reads
 * /api/questionnaire-journeys. Localized via i18n (page chrome via t()). */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t2 = $("toast"); t2.textContent = m; t2.className = "show"; setTimeout(() => { t2.className = ""; }, 2800); }

interface Qn { id: number; name: string; description: string; language: string; questions: number; sections: number; }
interface Run { id: number; questionnaireId: number; questionnaireName: string; name: string; subject: string; respondent: string; owner: string; status: string; startedDate: string; targetDate: string; submittedDate: string; total: number; answered: number; na: number; yes: number; no: number; partial: number; pct: number; conformance: number; }
interface Quest { responseId: number; questionId: number; name: string; text: string; description: string; answer: string; comment: string; evidence: string; }
interface Section { key: string; name: string; questions: Quest[]; total: number; answered: number; pct: number; }
interface Detail { run: Run; sections: Section[]; progress: { pct: number; total: number; answered: number; na: number; yes: number; no: number; partial: number; conformance: number } }
interface Data { questionnaires: Qn[]; runs: Run[]; summary: any }

let DATA: Data | null = null;
let DETAIL: Detail | null = null;
let pendingQn: Qn | null = null;

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="qj-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const pbar = (pct: number): string => `<div class="pbar"><i style="width:${Math.max(0, Math.min(100, pct))}%"></i></div>`;

function qnCard(q: Qn): string {
  return `<div class="qn" data-qn="${q.id}">
    <div class="top"><span class="nm">${esc(q.name)}</span><span class="badge">${q.questions} Q</span></div>
    <div class="desc">${esc(q.description || t("qj.noDescription"))}</div>
    <div class="meta"><span>&#128202; ${q.sections} ${t("qj.sections")}</span>${q.language ? `<span>&#127760; ${esc(q.language)}</span>` : ""}</div>
    <button class="start" data-qn="${q.id}">${t("qj.startrun")}</button>
  </div>`;
}

function runRow(r: Run): string {
  const stKey = ["in_progress", "submitted", "reviewed"].includes(r.status) ? r.status : "in_progress";
  return `<div class="rn" data-id="${r.id}">
    <div class="row1">
      <span class="jn">${esc(r.name)}</span>
      <span class="qnm">${esc(r.questionnaireName)}</span>
      <span class="st-pill st-${stKey}">${t("qj.status." + stKey)}</span>
      <span class="spacer" style="flex:1"></span>
      ${pbar(r.pct)}<span class="pct">${r.pct}%</span>
    </div>
    <div class="meta">
      <span>${r.answered}/${r.total} ${t("qj.answered")}${r.na ? ` &middot; ${r.na} ${t("qj.ans.na")}` : ""}</span>
      <span>&#9989; ${r.conformance}% ${t("qj.conformance")}</span>
      ${r.subject ? `<span>&#127919; ${esc(r.subject.length > 44 ? r.subject.slice(0, 44) + "…" : r.subject)}</span>` : ""}
      ${r.owner ? `<span>&#128100; ${esc(r.owner)}</span>` : ""}
      ${r.targetDate ? `<span>&#128197; ${t("qj.target")} ${esc(r.targetDate)}</span>` : ""}
    </div>
  </div>`;
}

function renderOverview(): void {
  DETAIL = null;
  const d = DATA!; const s = d.summary;
  const cards = [
    card(t("qj.kpi.runs"), String(s.runs), `${s.inFlight} ${t("qj.kpi.inflight")}`),
    card(t("qj.kpi.avgprogress"), `${s.avgProgress}%`, t("qj.kpi.acrossactive"), s.avgProgress >= 80 ? "#4ade80" : s.avgProgress >= 40 ? "#fbbf24" : undefined),
    card(t("qj.kpi.conformance"), `${s.avgConformance}%`, t("qj.kpi.avgconf"), s.avgConformance >= 80 ? "#4ade80" : s.avgConformance >= 40 ? "#fbbf24" : "#f87171"),
    card(t("qj.kpi.submitted"), String(s.submitted), t("qj.kpi.completedruns"), s.submitted ? "#4ade80" : undefined),
  ].join("");
  const myRuns = d.runs.length ? d.runs.map(runRow).join("") : `<div class="muted" style="padding:10px 0">${t("qj.noruns")}</div>`;
  const cat = d.questionnaires.length ? d.questionnaires.map(qnCard).join("") : `<div class="muted" style="padding:10px 0">${t("qj.noquestionnaires")}</div>`;
  $("qj-body").innerHTML = `<div class="qj-cards">${cards}</div>
    <div class="qj-section">${t("qj.myruns")} (${d.runs.length})</div>${myRuns}
    <div class="qj-section">${t("qj.startnew")}</div><div class="qn-grid">${cat}</div>`;
  Array.prototype.forEach.call(document.querySelectorAll(".qn"), (el: HTMLElement) => {
    el.onclick = () => openWizard(d.questionnaires.find((q) => q.id === Number(el.getAttribute("data-qn")))!);
  });
  Array.prototype.forEach.call(document.querySelectorAll(".rn"), (el: HTMLElement) => {
    el.onclick = () => openRun(Number(el.getAttribute("data-id")));
  });
}

function openWizard(q: Qn): void {
  pendingQn = q;
  $("qj-dlg-title").textContent = `${t("qj.startcolon")} ${q.name}`;
  $("qj-dlg-qn").innerHTML = `<span class="qnm" style="font-size:9px;border-radius:5px;padding:1px 7px;background:#3730a3;color:#c7d2fe">${q.questions} ${t("qj.questions")}</span> &middot; ${q.sections} ${t("qj.sections")}`;
  ($("qj-name") as HTMLInputElement).value = `${q.name} — ${new Date().getFullYear()}`;
  ($("qj-subject") as HTMLInputElement).value = "";
  ($("qj-respondent") as HTMLInputElement).value = "";
  ($("qj-owner") as HTMLInputElement).value = "";
  ($("qj-target") as HTMLInputElement).value = "";
  $("qj-modal").classList.add("show");
}
function closeWizard(): void { $("qj-modal").classList.remove("show"); pendingQn = null; }

function createRun(): void {
  if (!pendingQn) return;
  const body = {
    questionnaireId: pendingQn.id,
    name: ($("qj-name") as HTMLInputElement).value.trim() || undefined,
    subject: ($("qj-subject") as HTMLInputElement).value.trim() || undefined,
    respondent: ($("qj-respondent") as HTMLInputElement).value.trim() || undefined,
    owner: ($("qj-owner") as HTMLInputElement).value.trim() || undefined,
    targetDate: ($("qj-target") as HTMLInputElement).value || undefined,
  };
  const btn = $("qj-create") as HTMLButtonElement; btn.disabled = true;
  fetch("/api/questionnaire-journeys", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((j) => { closeWizard(); toast(t("qj.toaststarted")); openRun(j.id); })
    .catch((e) => toast("⚠️ " + (e.message || e)))
    .finally(() => { btn.disabled = false; });
}

const ANS_OPTS: string[] = ["", "yes", "no", "partial", "na"];
const ansClass = (a: string): string => (a ? `a-${a}` : "");

function questHtml(q: Quest): string {
  const state = q.answer ? (q.answer === "na" ? "na" : "answered") : "unanswered";
  const opts = ANS_OPTS.map((v) => `<option value="${v}"${q.answer === v ? " selected" : ""}>${t("qj.ans." + (v || "unanswered"))}</option>`).join("");
  return `<div class="q ${state}" data-rid="${q.responseId}">
    <div class="q-top">${q.name ? `<span class="q-name">${esc(q.name)}</span>` : ""}<span class="q-text">${esc(q.text || q.description)}</span></div>
    <div class="q-ctl">
      <select class="q-ans ${ansClass(q.answer)}" data-rid="${q.responseId}">${opts}</select>
      <input class="q-comment" data-rid="${q.responseId}" value="${esc(q.comment)}" placeholder="${t("qj.commentph")}">
      <input class="q-evidence" data-rid="${q.responseId}" value="${esc(q.evidence)}" placeholder="${t("qj.evidenceph")}">
    </div>
  </div>`;
}

function sectionHtml(sec: Section, idx: number): string {
  return `<div class="sec${idx === 0 ? "" : " collapsed"}" data-sec="${esc(sec.key)}">
    <div class="sec-head"><span class="sec-num">${sec.answered}/${sec.total}</span><span class="sec-name">${esc(sec.name)}</span>
      <span class="spacer" style="flex:1"></span>${pbar(sec.pct)}<span class="pct sec-pct">${sec.pct}%</span><span class="caret">&#9660;</span></div>
    <div class="sec-body">${sec.questions.map(questHtml).join("")}</div>
  </div>`;
}

function recomputeAndPatch(): void {
  if (!DETAIL) return;
  let total = 0, answered = 0, na = 0, yes = 0, no = 0, partial = 0;
  DETAIL.sections.forEach((sec) => {
    sec.total = sec.questions.length;
    sec.answered = sec.questions.filter((q) => q.answer).length;
    sec.pct = sec.total ? Math.round((sec.answered / sec.total) * 100) : 0;
    total += sec.total;
    sec.questions.forEach((q) => {
      if (!q.answer) return;
      answered++;
      if (q.answer === "na") na++; else if (q.answer === "yes") yes++; else if (q.answer === "no") no++; else if (q.answer === "partial") partial++;
    });
    // patch section header
    const el = document.querySelector(`.sec[data-sec="${CSS.escape(sec.key)}"]`);
    if (el) {
      (el.querySelector(".sec-num") as HTMLElement).textContent = `${sec.answered}/${sec.total}`;
      (el.querySelector(".sec-pct") as HTMLElement).textContent = `${sec.pct}%`;
      (el.querySelector(".pbar > i") as HTMLElement).style.width = `${sec.pct}%`;
    }
  });
  const applicable = answered - na;
  const pct = total ? Math.round((answered / total) * 100) : 0;
  const conformance = applicable ? Math.round(((yes + 0.5 * partial) / applicable) * 100) : 0;
  DETAIL.progress = { pct, total, answered, na, yes, no, partial, conformance };
  const set = (id: string, v: string) => { const e = document.getElementById(id); if (e) e.textContent = v; };
  set("qj-kpi-progress", `${pct}%`);
  set("qj-kpi-progress-foot", `${answered}/${total} ${t("qj.answered")}`);
  set("qj-kpi-conformance", `${conformance}%`);
  const top = document.querySelector("#qj-top-bar > i") as HTMLElement | null;
  if (top) top.style.width = `${pct}%`;
}

function openRun(id: number): void {
  $("qj-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("qj.loadingrun")}</div>`;
  fetch("/api/questionnaire-journeys/item/" + id).then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Detail) => {
    DETAIL = d;
    const run = d.run; const pr = d.progress;
    const cards = [
      `<div class="qj-card"><div class="lbl">${t("qj.progress")}</div><div class="val" id="qj-kpi-progress" style="color:${pr.pct >= 80 ? "#4ade80" : pr.pct >= 40 ? "#fbbf24" : "#e7ebf3"}">${pr.pct}%</div><div class="foot" id="qj-kpi-progress-foot">${pr.answered}/${pr.total} ${t("qj.answered")}</div></div>`,
      `<div class="qj-card"><div class="lbl">${t("qj.conformance")}</div><div class="val" id="qj-kpi-conformance" style="color:${pr.conformance >= 80 ? "#4ade80" : pr.conformance >= 40 ? "#fbbf24" : "#f87171"}">${pr.conformance}%</div><div class="foot">${pr.yes} ${t("qj.ans.yes")} &middot; ${pr.no} ${t("qj.ans.no")}</div></div>`,
      card(t("qj.sectionscard"), String(d.sections.length), t("qj.domains")),
      card(t("qj.subjectcard"), run.subject || "—", t("qj.beingassessed")),
    ].join("");
    $("qj-body").innerHTML = `
      <div class="qj-section"><button class="btn-sm2" id="qj-back">${t("qj.allruns")}</button><span class="spacer" style="flex:1"></span>
        <button class="btn-submit" id="qj-submit">${t("qj.submit")}</button>
        <button class="btn-sm2" id="qj-del" style="border-color:#7f1d1d;color:#fca5a5">${t("qj.delete")}</button></div>
      <h2 style="font-size:18px;margin:6px 0 2px">${esc(run.name)} <span class="qnm" style="font-size:10px;border-radius:5px;padding:1px 7px;background:#3730a3;color:#c7d2fe">${esc(run.questionnaireName)}</span></h2>
      <div class="muted" style="font-size:12.5px;margin-bottom:12px;max-width:960px">
        ${run.respondent ? `<b style="color:#94a3b8">${t("qj.respondentlabel")}</b> ${esc(run.respondent)} &nbsp;&middot;&nbsp; ` : ""}
        ${run.owner ? `<b style="color:#94a3b8">${t("qj.ownerlabel")}</b> ${esc(run.owner)} &nbsp;&middot;&nbsp; ` : ""}
        <span class="st-pill st-${["in_progress", "submitted", "reviewed"].includes(run.status) ? run.status : "in_progress"}">${t("qj.status." + (["in_progress", "submitted", "reviewed"].includes(run.status) ? run.status : "in_progress"))}</span>
        ${run.submittedDate ? ` &nbsp;&middot;&nbsp; ${t("qj.submittedon")} ${esc(run.submittedDate)}` : ""}</div>
      <div class="pbar" id="qj-top-bar" style="height:6px;margin-bottom:14px"><i style="width:${pr.pct}%"></i></div>
      <div class="qj-cards">${cards}</div>
      <div style="margin-top:6px">${d.sections.map((s, i) => sectionHtml(s, i)).join("")}</div>`;
    $("qj-back").onclick = () => reload().then(renderOverview);
    $("qj-submit").onclick = () => submitRun(id);
    $("qj-del").onclick = () => {
      if (!confirm(t("qj.confirmdelete"))) return;
      fetch("/api/questionnaire-journeys/item/" + id, { method: "DELETE" }).then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
        .then(() => reload().then(renderOverview)).then(() => toast(t("qj.toastdeleted"))).catch((e) => toast("⚠️ " + (e.message || e)));
    };
    // collapse / expand
    Array.prototype.forEach.call(document.querySelectorAll(".sec-head"), (h: HTMLElement) => {
      h.onclick = (e) => { if ((e.target as HTMLElement).closest(".q-ctl")) return; h.parentElement!.classList.toggle("collapsed"); };
    });
    // answer selects
    Array.prototype.forEach.call(document.querySelectorAll(".q-ans"), (sel: HTMLSelectElement) => {
      sel.onchange = () => onAnswer(Number(sel.getAttribute("data-rid")), sel.value, sel);
    });
    // comment + evidence (save on blur)
    Array.prototype.forEach.call(document.querySelectorAll(".q-comment"), (inp: HTMLInputElement) => {
      inp.onblur = () => onField(Number(inp.getAttribute("data-rid")), { comment: inp.value }, "comment", inp.value);
    });
    Array.prototype.forEach.call(document.querySelectorAll(".q-evidence"), (inp: HTMLInputElement) => {
      inp.onblur = () => onField(Number(inp.getAttribute("data-rid")), { evidence: inp.value }, "evidence", inp.value);
    });
  }).catch((e) => { $("qj-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function findQuest(rid: number): Quest | undefined {
  if (!DETAIL) return undefined;
  for (const sec of DETAIL.sections) { const q = sec.questions.find((x) => x.responseId === rid); if (q) return q; }
  return undefined;
}

function onAnswer(rid: number, value: string, sel: HTMLSelectElement): void {
  const q = findQuest(rid); if (!q) return;
  q.answer = value;
  sel.className = `q-ans ${ansClass(value)}`;
  const row = sel.closest(".q"); if (row) row.className = `q ${value ? (value === "na" ? "na" : "answered") : "unanswered"}`;
  recomputeAndPatch();
  fetch("/api/questionnaire-journeys/response/" + rid, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ answer: value }) })
    .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function onField(rid: number, patch: Record<string, string>, key: "comment" | "evidence", value: string): void {
  const q = findQuest(rid); if (!q) return;
  if (q[key] === value) return; // no change
  q[key] = value;
  fetch("/api/questionnaire-journeys/response/" + rid, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(patch) })
    .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function submitRun(id: number): void {
  fetch("/api/questionnaire-journeys/submit/" + id, { method: "POST" })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((j) => { toast(`${t("qj.toastsubmitted")} — ${j.progress.conformance}% ${t("qj.conformance")}`); openRun(id); })
    .catch((e) => toast("⚠️ " + (e.message || e)));
}

function reload(): Promise<void> {
  return fetch("/api/questionnaire-journeys").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => { DATA = d; });
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("qj-cancel").onclick = closeWizard;
  $("qj-create").onclick = createRun;
  $("qj-modal").addEventListener("click", (e) => { if (e.target === $("qj-modal")) closeWizard(); });
  reload().then(renderOverview).catch((e) => { $("qj-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
});
