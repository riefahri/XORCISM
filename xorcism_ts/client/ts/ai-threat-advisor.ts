/** ai-threat-advisor.ts — OWASP AI Exchange agent threat advisor (/ai-threat-advisor). */
// NB: import as T — `t` is used as param/local in this file (toast()'s `const t`, .map((t)=>…)).
import { initI18n, t as T } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), T(key));
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2400); }

const SHAPE_KEYS = ["llm", "agent", "ml", "tools", "memory", "autonomous", "external", "sensitive"];
const SHAPES = (): [string, string][] => SHAPE_KEYS.map((k) => [k, T(`ata.shape.${k}`)] as [string, string]);
const icls = (i: string): string => `i-${["High", "Medium", "Low"].includes(i) ? i : "Low"}`;
const selected = new Set<string>(["agent", "tools", "external"]);

function threatCard(th: any): string {
  return `<div class="th ${th.impact.toLowerCase()}">
    <div class="top"><span class="ref">${esc(th.ref)}</span><span class="nm">${esc(th.name)}</span><span class="cat">${esc(th.category)}</span><span class="imp ${icls(th.impact)}">${esc(th.impact)}</span><span class="muted" style="font-size:11px;margin-left:auto">${esc(th.lifecycle)}</span></div>
    <div class="desc">${esc(th.description)}</div>
    <div class="ctrl"><b>${T("ata.controls")}</b> ${esc(th.controls)}</div>
  </div>`;
}

function renderShapes(): void {
  $("shapes").innerHTML = SHAPES().map(([k, l]) => `<label class="shape${selected.has(k) ? " on" : ""}" data-k="${k}"><input type="checkbox" ${selected.has(k) ? "checked" : ""}> ${esc(l)}</label>`).join("");
  Array.prototype.forEach.call(document.querySelectorAll(".shape"), (el: HTMLElement) => {
    el.onclick = (e) => { if ((e.target as HTMLElement).tagName !== "INPUT") (el.querySelector("input") as HTMLInputElement).checked = !(el.querySelector("input") as HTMLInputElement).checked;
      const k = el.getAttribute("data-k")!; if ((el.querySelector("input") as HTMLInputElement).checked) { selected.add(k); el.classList.add("on"); } else { selected.delete(k); el.classList.remove("on"); } };
  });
}

function advise(): void {
  if (!selected.size) { toast(T("ata.selectOne")); return; }
  fetch("/api/ai-threats/advise", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ shapes: [...selected] }) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((d) => {
      const cards = `<div class="cards"><div class="card"><div class="lbl">${T("ata.cApplicable")}</div><div class="val">${d.summary.applicable}</div><div class="foot">${T("ata.cApplicable.f")}</div></div>
        <div class="card"><div class="lbl">${T("ata.cHigh")}</div><div class="val" style="color:#f87171">${d.summary.high}</div><div class="foot">${T("ata.cHigh.f")}</div></div>
        <div class="card"><div class="lbl">${T("ata.cCategories")}</div><div class="val">${d.summary.categories}</div><div class="foot">${T("ata.cCategories.f")}</div></div></div>`;
      $("result").innerHTML = `<div class="sec">${fmt("ata.secApplicable", { n: d.threats.length })}</div>${cards}${d.threats.map(threatCard).join("")}`;
      $("result").scrollIntoView({ behavior: "smooth", block: "nearest" });
    }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function loadCatalogue(): void {
  fetch("/api/ai-threats").then((r) => r.json()).then((d) => {
    $("catalogue").innerHTML = `<div class="muted" style="font-size:12px;margin-bottom:8px">${fmt("ata.catMeta", { n: d.total, src: esc(d.source) })}</div>` +
      d.categories.map((c: any) => `<div class="sec" style="font-size:12px;color:#a5b4fc">${esc(c.category)}</div>${c.threats.map((th: any) => threatCard({ ...th, category: c.category })).join("")}`).join("");
  }).catch((e) => { $("catalogue").innerHTML = `<div class="muted">⚠️ ${esc(e)}</div>`; });
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); renderShapes(); $("advise").onclick = advise; advise(); loadCatalogue(); });
