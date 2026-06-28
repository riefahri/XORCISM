/**
 * xlsx-import.ts — reusable Excel/CSV import modal with column → field mapping.
 *
 * A self-contained dialog (builds its own DOM + toast, lazy-loads SheetJS from /vendor/xlsx.full.min.js):
 * upload a .xlsx/.xls/.csv, map its columns to the target fields (with fuzzy header auto-match),
 * optionally upsert, download a template, then POST { rows, upsert } to `endpoint`. Used by Asset
 * Management's siblings (Risk Register, Risk Assessment, …). Generic UI strings come from i18n `xi.*`;
 * field labels are passed in already-localized by the caller.
 */
import { t } from "./i18n";

export interface XlsxField { key: string; label: string; required?: boolean; guess: string[]; }
export interface XlsxImportOpts {
  title: string;
  lead: string;
  fields: XlsxField[];
  endpoint: string;             // POST { rows: [{field:value}], upsert } → { created, updated, skipped, errors[] }
  upsertLabel?: string;         // when set, an "update existing" checkbox is shown (sent as `upsert`)
  templateName?: string;        // download-template file name (without extension)
  onDone?: () => void;          // called after a successful import (e.g. reload the page data)
}

interface XlsxLib {
  read(data: Uint8Array, opts: { type: string }): { SheetNames: string[]; Sheets: Record<string, unknown> };
  utils: {
    sheet_to_json(ws: unknown, opts: { header: 1; blankrows: boolean; defval: string }): unknown[][];
    aoa_to_sheet(data: unknown[][]): unknown;
    book_new(): unknown;
    book_append_sheet(wb: unknown, ws: unknown, name: string): void;
  };
  writeFile(wb: unknown, filename: string): void;
}

const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
const getXlsx = (): XlsxLib | undefined => (window as unknown as { XLSX?: XlsxLib }).XLSX;
function loadXlsx(): Promise<void> {
  if (getXlsx()) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "/vendor/xlsx.full.min.js";
    s.onload = () => resolve(); s.onerror = () => reject(new Error("xlsx load failed"));
    document.head.appendChild(s);
  });
}
function xiToast(msg: string, ok = true): void {
  const el = document.createElement("div");
  el.textContent = msg;
  el.style.cssText = `position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid ${ok ? "#34d399" : "#f87171"};color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:4000`;
  document.body.appendChild(el);
  window.setTimeout(() => el.remove(), 7000);
}

export function openXlsxImport(opts: XlsxImportOpts): void {
  let headers: string[] = [];
  let rows: unknown[][] = [];
  const selects: Record<string, HTMLSelectElement> = {};

  const inputCss = "width:100%;box-sizing:border-box;background:#0f1117;border:1px solid #2d3250;border-radius:8px;padding:8px 10px;color:#e2e8f0;font-size:12.5px;font-family:inherit";
  const bg = document.createElement("div");
  bg.style.cssText = "position:fixed;inset:0;background:rgba(4,6,15,.66);display:flex;align-items:flex-start;justify-content:center;z-index:3500;overflow:auto;padding:40px 16px";
  bg.onclick = (e) => { if (e.target === bg) bg.remove(); };
  const card = document.createElement("div");
  card.style.cssText = "background:#13162a;border:1px solid #2d3250;border-radius:14px;width:min(680px,96vw);padding:20px 22px";
  card.innerHTML =
    `<h3 style="margin:0 0 4px;font-size:17px;color:#e2e8f0">${esc(opts.title)}</h3>
     <p style="font-size:12.5px;color:#94a3b8;margin:0 0 14px">${opts.lead}</p>
     <div class="fld" style="margin-bottom:10px">
       <label style="display:block;font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px">${esc(t("xi.file"))}</label>
       <input id="xi-file" type="file" accept=".xlsx,.xls,.csv,.ods" autocomplete="off">
       <div style="margin-top:6px"><a href="#" id="xi-template" class="muted" style="font-size:11.5px;color:#64748b;text-decoration:underline">${esc(t("xi.template"))}</a></div>
     </div>
     <div id="xi-status" class="muted" style="font-size:12px;min-height:16px;margin-bottom:8px;color:#94a3b8"></div>
     <div id="xi-mapwrap" style="display:none">
       <div style="font-size:12px;font-weight:700;color:#cbd5e1;text-transform:uppercase;letter-spacing:.5px;margin:6px 0 8px">${esc(t("xi.mapHead"))}</div>
       <div id="xi-map" style="display:grid;grid-template-columns:1fr 1fr;gap:8px 16px"></div>
       ${opts.upsertLabel ? `<label style="margin-top:14px;display:flex;align-items:center;gap:7px;font-size:12px;color:#cbd5e1"><input type="checkbox" id="xi-upsert" style="width:auto"> <span>${esc(opts.upsertLabel)}</span></label>` : ""}
     </div>
     <div id="xi-result" style="margin-top:10px"></div>
     <div style="display:flex;align-items:center;gap:10px;margin-top:16px">
       <span id="xi-err" style="flex:1;color:#f87171;font-size:12px;min-height:16px"></span>
       <button id="xi-cancel" class="btn btn-ghost btn-sm" type="button">${esc(t("modal.cancel") || "Cancel")}</button>
       <button id="xi-run" type="button" disabled style="background:#7c83fd;color:#0b0d18;border:none;border-radius:8px;font-size:13px;font-weight:700;padding:9px 16px;cursor:pointer">${esc(t("xi.run"))}</button>
     </div>`;
  bg.appendChild(card);
  document.body.appendChild(bg);
  const q = <T extends HTMLElement>(id: string): T => card.querySelector(`#${id}`) as T;

  const buildMapping = (): void => {
    const wrap = q("xi-map"); wrap.innerHTML = "";
    const used = new Set<number>();
    for (const f of opts.fields) {
      const row = document.createElement("div"); row.style.cssText = "display:flex;flex-direction:column;gap:3px";
      const lbl = document.createElement("label");
      lbl.textContent = f.label + (f.required ? " *" : "");
      lbl.style.cssText = "font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.4px";
      const sel = document.createElement("select"); sel.style.cssText = inputCss;
      const none = document.createElement("option"); none.value = "-1"; none.textContent = t("xi.ignore"); sel.appendChild(none);
      headers.forEach((h, i) => { const o = document.createElement("option"); o.value = String(i); o.textContent = h || `${t("xi.col")} ${i + 1}`; sel.appendChild(o); });
      let guess = -1;
      for (let i = 0; i < headers.length; i++) {
        const hl = (headers[i] || "").toLowerCase().trim();
        if (!used.has(i) && hl && f.guess.some((g) => hl === g || hl.includes(g))) { guess = i; break; }
      }
      if (guess >= 0) { sel.value = String(guess); used.add(guess); }
      selects[f.key] = sel;
      row.appendChild(lbl); row.appendChild(sel); wrap.appendChild(row);
    }
  };

  (q<HTMLInputElement>("xi-file")).addEventListener("change", async () => {
    const file = (q<HTMLInputElement>("xi-file")).files?.[0]; if (!file) return;
    const status = q("xi-status"); status.textContent = t("xi.reading");
    (q<HTMLButtonElement>("xi-run")).disabled = true; q("xi-result").innerHTML = "";
    try {
      await loadXlsx(); const XLSX = getXlsx();
      if (!XLSX) { status.textContent = t("xi.noxlsx"); return; }
      const buf = await file.arrayBuffer();
      const wb = XLSX.read(new Uint8Array(buf), { type: "array" });
      const ws = wb.Sheets[wb.SheetNames[0]];
      const aoa = XLSX.utils.sheet_to_json(ws, { header: 1, blankrows: false, defval: "" });
      if (!aoa.length) { status.textContent = t("xi.empty"); return; }
      headers = (aoa[0] as unknown[]).map((h) => String(h ?? "").trim());
      rows = aoa.slice(1).filter((r) => Array.isArray(r) && r.some((c) => String(c ?? "").trim() !== ""));
      buildMapping(); q("xi-mapwrap").style.display = "block";
      status.textContent = t("xi.detected").replace("{cols}", String(headers.length)).replace("{rows}", String(rows.length));
      (q<HTMLButtonElement>("xi-run")).disabled = rows.length === 0;
    } catch (e) { status.textContent = `⚠️ ${e}`; }
  });

  (q("xi-template")).addEventListener("click", async (e) => {
    e.preventDefault();
    try {
      await loadXlsx(); const XLSX = getXlsx(); if (!XLSX) { xiToast(t("xi.noxlsx"), false); return; }
      const head = opts.fields.map((f) => f.label);
      const ws = XLSX.utils.aoa_to_sheet([head, head.map(() => "")]);
      const wb = XLSX.utils.book_new(); XLSX.utils.book_append_sheet(wb, ws, "Import");
      XLSX.writeFile(wb, (opts.templateName || "import") + "-template.xlsx");
    } catch (err) { xiToast(`⚠️ ${err}`, false); }
  });

  (q("xi-cancel")).addEventListener("click", () => bg.remove());

  (q("xi-run")).addEventListener("click", async () => {
    const err = q("xi-err"); err.textContent = "";
    const required = opts.fields.filter((f) => f.required);
    for (const f of required) {
      if (Number(selects[f.key]?.value ?? -1) < 0) { err.textContent = t("xi.needField").replace("{field}", f.label); return; }
    }
    const mapped = rows.map((r) => {
      const o: Record<string, unknown> = {};
      for (const f of opts.fields) { const ci = Number(selects[f.key]?.value ?? -1); if (ci >= 0) { const cell = (r as unknown[])[ci]; if (String(cell ?? "").trim() !== "") o[f.key] = cell; } }
      return o;
    }).filter((o) => required.every((f) => String(o[f.key] ?? "").trim() !== ""));
    if (!mapped.length) { err.textContent = t("xi.noRows"); return; }
    const btn = q<HTMLButtonElement>("xi-run"); btn.disabled = true; err.textContent = t("xi.importing");
    try {
      const upsert = opts.upsertLabel ? (q<HTMLInputElement>("xi-upsert")).checked : false;
      const r = await fetch(opts.endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ rows: mapped, upsert }) });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      err.textContent = "";
      const errLines = (d.errors as { row: number; error: string }[] | undefined)?.slice(0, 8)
        .map((e2) => `<div>${t("xi.row")} ${e2.row}: ${esc(e2.error)}</div>`).join("") || "";
      q("xi-result").innerHTML =
        `<div style="background:#0f1117;border:1px solid #2d3250;border-radius:8px;padding:10px 12px;font-size:12.5px;color:#cbd5e1">
          <div style="color:#34d399">${t("xi.done").replace("{created}", String(d.created ?? 0)).replace("{updated}", String(d.updated ?? 0)).replace("{skipped}", String(d.skipped ?? 0))}</div>
          ${d.errors?.length ? `<div style="color:#f87171;margin-top:6px">${t("xi.errors").replace("{n}", String(d.errors.length))}</div>${errLines}` : ""}
        </div>`;
      xiToast(t("xi.toast").replace("{created}", String(d.created ?? 0)).replace("{updated}", String(d.updated ?? 0)));
      opts.onDone?.();
    } catch (e) { err.textContent = `⚠️ ${e}`; }
    finally { btn.disabled = false; }
  });
}
