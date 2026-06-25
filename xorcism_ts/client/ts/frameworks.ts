/**
 * frameworks.ts — Frameworks management (/frameworks).
 * Lists the FRAMEWORK catalogue with an inline vocabulary-mapping dropdown per row (sets
 * FRAMEWORK.VocabularyID → the controls catalogue), plus a "New framework" modal. From /api/frameworks.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
function toast(m: string): void { const el = $("toast"); if (!el) return; el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2600); }

interface Vocab { id: number; name: string; version: string | null; reference: string | null; controls: number }
interface Row { id: number; name: string; version: string | null; description: string | null; vocabularyId: number | null; vocabularyName: string | null; controls: number; mapped: boolean }
interface Data { rows: Row[]; vocabularies: Vocab[]; summary: { total: number; mapped: number; unmapped: number; controlsCovered: number; vocabularies: number } }

let DATA: Data | null = null;

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="fw-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}

function vocabOptions(selected: number | null): string {
  const vs = DATA?.vocabularies || [];
  const opts = vs.map((v) => `<option value="${v.id}"${v.id === selected ? " selected" : ""}>${esc(v.name)}${v.controls ? ` (${v.controls})` : ""}</option>`).join("");
  return `<option value=""${selected == null ? " selected" : ""}>${t("frm.notMapped")}</option>${opts}`;
}

function rowHtml(r: Row): string {
  return `<tr data-id="${r.id}">
    <td><span class="fname">${esc(r.name)}</span>${r.version ? ` <span class="muted">${esc(r.version)}</span>` : ""}${r.description ? `<div class="muted" style="font-size:11px;max-width:420px">${esc(r.description)}</div>` : ""}</td>
    <td><select class="vsel" data-map="${r.id}">${vocabOptions(r.vocabularyId)}</select></td>
    <td>${r.mapped ? `<span class="ctrl" id="fw-ctrl-${r.id}">${fmt("frm.nControls", { n: r.controls })}</span>` : `<span class="muted" id="fw-ctrl-${r.id}">—</span>`}</td>
    <td>${r.mapped ? `<span class="badge b-mapped">${t("frm.mapped")}</span>` : `<span class="badge b-unmapped">${t("frm.unmapped")}</span>`}</td>
  </tr>`;
}

function render(): void {
  if (!DATA) return;
  const s = DATA.summary;
  const cards = [
    card(t("frm.cFrameworks"), String(s.total), t("frm.cFrameworks.foot"), "#22c55e"),
    card(t("frm.cMapped"), String(s.mapped), t("frm.cMapped.foot"), s.mapped ? "#34d399" : undefined),
    card(t("frm.cUnmapped"), String(s.unmapped), t("frm.cUnmapped.foot"), s.unmapped ? "#fbbf24" : "#34d399"),
    card(t("frm.cControls"), String(s.controlsCovered), fmt("frm.cControls.foot", { n: s.vocabularies }), "#60a5fa"),
  ].join("");
  const table = DATA.rows.length
    ? `<table class="fw"><thead><tr><th>${t("frm.thFramework")}</th><th>${t("frm.thVocab")}</th><th>${t("frm.thControls")}</th><th>${t("frm.thStatus")}</th></tr></thead>
       <tbody>${DATA.rows.map(rowHtml).join("")}</tbody></table>`
    : `<div class="muted" style="padding:24px;text-align:center">${t("frm.noFrameworks")}</div>`;
  $("fw-body").innerHTML = `<div class="fw-cards">${cards}</div>
    <div class="fw-section">${fmt("frm.secCatalogue", { n: DATA.rows.length })}</div>${table}
    <div class="muted" style="font-size:11px;margin-top:12px">${t("frm.legend")}</div>`;
  // wire inline mapping dropdowns
  $("fw-body").querySelectorAll<HTMLSelectElement>("select[data-map]").forEach((sel) => {
    sel.addEventListener("change", () => void mapFramework(Number(sel.dataset.map), sel.value ? Number(sel.value) : null, sel));
  });
  $("fw-bar-stat").textContent = fmt("frm.barStat", { m: s.mapped, n: s.total });
}

async function mapFramework(id: number, vocabularyId: number | null, sel: HTMLSelectElement): Promise<void> {
  sel.disabled = true;
  try {
    const r = await fetch(`/api/frameworks/${id}/map`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ vocabularyId }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    // update the row's control count + status badge + local state, no full reload
    const row = DATA?.rows.find((x) => x.id === id);
    if (row) { row.vocabularyId = vocabularyId; row.mapped = vocabularyId != null; row.controls = vocabularyId != null ? Number(d.controls || 0) : 0; row.vocabularyName = vocabularyId != null ? (DATA?.vocabularies.find((v) => v.id === vocabularyId)?.name ?? null) : null; }
    const ctrl = document.getElementById(`fw-ctrl-${id}`);
    if (ctrl) { ctrl.className = vocabularyId != null ? "ctrl" : "muted"; ctrl.textContent = vocabularyId != null ? fmt("frm.nControls", { n: d.controls || 0 }) : "—"; }
    const tr = sel.closest("tr"); const badge = tr?.querySelector(".badge");
    if (badge) { badge.className = `badge ${vocabularyId != null ? "b-mapped" : "b-unmapped"}`; badge.textContent = vocabularyId != null ? t("frm.mapped") : t("frm.unmapped"); }
    if (DATA) { DATA.summary.mapped = DATA.rows.filter((x) => x.mapped).length; DATA.summary.unmapped = DATA.summary.total - DATA.summary.mapped; DATA.summary.controlsCovered = DATA.rows.reduce((a, x) => a + x.controls, 0); }
    $("fw-bar-stat").textContent = DATA ? fmt("frm.barStat", { m: DATA.summary.mapped, n: DATA.summary.total }) : "";
    toast(vocabularyId != null ? fmt("frm.mappedTo", { n: d.controls || 0 }) : t("frm.mappingCleared"));
  } catch (e) { toast(`⚠️ ${(e as Error).message}`); }
  finally { sel.disabled = false; }
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/frameworks"); if (!r.ok) throw new Error(`HTTP ${r.status}`); DATA = await r.json(); }
  catch (e) { $("fw-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  render();
}

// ── New-framework modal ──────────────────────────────────────────────────────────
function openModal(): void {
  (document.getElementById("fw-f-vocab") as HTMLSelectElement).innerHTML = vocabOptions(null);
  (document.getElementById("fw-f-name") as HTMLInputElement).value = "";
  (document.getElementById("fw-f-version") as HTMLInputElement).value = "";
  (document.getElementById("fw-f-desc") as HTMLTextAreaElement).value = "";
  $("fw-f-err").textContent = "";
  $("fw-modal").classList.add("open");
  (document.getElementById("fw-f-name") as HTMLInputElement).focus();
}
function closeModal(): void { $("fw-modal").classList.remove("open"); }

async function createFramework(): Promise<void> {
  const name = (document.getElementById("fw-f-name") as HTMLInputElement).value.trim();
  if (!name) { $("fw-f-err").textContent = t("frm.errName"); return; }
  const body = {
    name,
    version: (document.getElementById("fw-f-version") as HTMLInputElement).value.trim(),
    description: (document.getElementById("fw-f-desc") as HTMLTextAreaElement).value.trim(),
    vocabularyId: (document.getElementById("fw-f-vocab") as HTMLSelectElement).value || null,
  };
  const btn = document.getElementById("fw-create") as HTMLButtonElement;
  btn.disabled = true;
  try {
    const r = await fetch("/api/frameworks", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeModal(); toast(fmt("frm.created", { name: esc(name) }));
    void load();
  } catch (e) { $("fw-f-err").textContent = (e as Error).message; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void load();
  document.getElementById("fw-new")?.addEventListener("click", openModal);
  document.getElementById("fw-cancel")?.addEventListener("click", closeModal);
  document.getElementById("fw-create")?.addEventListener("click", () => void createFramework());
  document.getElementById("fw-modal")?.addEventListener("click", (e) => { if (e.target === document.getElementById("fw-modal")) closeModal(); });
});
