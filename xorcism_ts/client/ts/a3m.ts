/**
 * a3m.ts — A3M matrix view (Agentic AI Attack Matrix), read from XTHREAT.A3M* via
 * /api/a3m/matrix. Tactics (columns) → AAT-#### techniques.
 */
import { initI18n } from "./i18n";

interface Tech { aatId: string; name: string; description: string | null }
interface Tactic { name: string; techniques: Tech[] }
interface Matrix { tactics: Tactic[] }

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function el(tag: string, cls?: string): HTMLElement { const e = document.createElement(tag); if (cls) e.className = cls; return e; }

function render(m: Matrix): void {
  const root = $("a3m-matrix");
  root.innerHTML = "";
  let techCount = 0;
  for (const tac of m.tactics) {
    const col = el("div", "att-col");
    const head = el("div", "att-col-head");
    head.innerHTML = `<div class="att-tac-name">${tac.name}</div>` +
      `<div class="att-tac-meta">${tac.techniques.length} tech.</div>`;
    col.appendChild(head);
    const body = el("div", "att-col-body");
    for (const t of tac.techniques) {
      techCount++;
      const cell = el("div", "att-cell");
      cell.dataset.s = `${t.aatId} ${t.name}`.toLowerCase();
      const id = el("span", "att-id"); id.textContent = t.aatId;
      const nm = el("div", "tn"); nm.textContent = t.name;
      if (t.description) cell.title = t.description;
      cell.appendChild(id); cell.appendChild(nm);
      body.appendChild(cell);
    }
    col.appendChild(body);
    root.appendChild(col);
  }
  $("a3m-stats").textContent = `${m.tactics.length} tactiques · ${techCount} techniques`;
  applyFilter();
}

function applyFilter(): void {
  const q = ($("a3m-search") as HTMLInputElement).value.trim().toLowerCase();
  document.querySelectorAll<HTMLElement>(".att-cell").forEach((c) => {
    c.style.display = !q || (c.dataset.s ?? "").includes(q) ? "" : "none";
  });
}

async function load(): Promise<void> {
  const root = $("a3m-matrix");
  root.innerHTML = `<div style="padding:24px;color:var(--text-muted)">Chargement…</div>`;
  try {
    const r = await fetch("/api/a3m/matrix");
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      root.innerHTML = `<div style="padding:24px;color:var(--danger)">${(d as { error?: string }).error || `Erreur ${r.status}`}</div>`;
      return;
    }
    const m = (await r.json()) as Matrix;
    render(m);
    if (!m.tactics.some((t) => t.techniques.length)) {
      root.insertAdjacentHTML("afterbegin",
        `<div style="padding:0 16px 12px;color:var(--text-dim);font-size:12px">Aucune technique importée. Lancez <code>python xorcism_python/importers/import_a3m.py</code>.</div>`);
    }
  } catch (e) {
    root.innerHTML = `<div style="padding:24px;color:var(--danger)">${(e as Error).message}</div>`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  ($("a3m-search") as HTMLInputElement).oninput = applyFilter;
  void load();
});
