/**
 * d3fend.ts — MITRE D3FEND matrix view (tactics → techniques → sub-techniques),
 * with the countered ATT&CK mappings, read from XTHREAT.D3FEND* via /api/d3fend/matrix.
 */
import { initI18n, t } from "./i18n";

interface Sub { d3fendId: string; name: string; url: string | null; attackIds: string[] }
interface Tech { d3fendId: string; name: string; url: string | null; attackIds: string[]; subtechniques: Sub[] }
interface Tactic { name: string; shortName: string; definition: string | null; techniques: Tech[] }
interface Matrix { tactics: Tactic[] }

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function el(tag: string, cls?: string): HTMLElement { const e = document.createElement(tag); if (cls) e.className = cls; return e; }

function techLink(d3fendId: string, name: string, url: string | null): HTMLElement {
  const a = document.createElement("a");
  a.textContent = name;
  a.title = `${d3fendId} — ${name}`;
  // We use the URL provided by the import (form /technique/d3f:ClassName/). NO
  // fallback on the D3-ID: /technique/D3-XXX/ returns 404 (the page is keyed on d3f:ClassName).
  if (url) { a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer"; }
  return a;
}

function mapBadge(attackIds: string[]): HTMLElement | null {
  if (!attackIds.length) return null;
  const b = el("span", "att-map");
  b.textContent = `⚔ ${attackIds.length}`;
  b.title = t("tip.counters") + " " + attackIds.join(", ");
  return b;
}

function render(m: Matrix): void {
  const root = $("d3-matrix");
  root.innerHTML = "";
  let techCount = 0, subCount = 0, mapCount = 0;
  for (const tac of m.tactics) {
    const col = el("div", "att-col");
    const head = el("div", "att-col-head");
    head.innerHTML =
      `<div class="att-tac-name">${tac.name}</div>` +
      `<div class="att-tac-meta">${tac.shortName} · ${tac.techniques.length} tech.</div>`;
    if (tac.definition) head.title = tac.definition;
    col.appendChild(head);
    const bodyEl = el("div", "att-col-body");
    for (const tch of tac.techniques) {
      techCount++;
      subCount += tch.subtechniques.length;
      mapCount += tch.attackIds.length;
      const cell = el("div", "att-cell");
      cell.dataset.s = `${tch.d3fendId} ${tch.name} ${tch.attackIds.join(" ")}`.toLowerCase() +
        " " + tch.subtechniques.map((s) => `${s.d3fendId} ${s.name} ${s.attackIds.join(" ")}`).join(" ").toLowerCase();
      const main = el("div", "att-cell-main");
      const id = el("span", "att-id"); id.textContent = tch.d3fendId;
      main.appendChild(id);
      main.appendChild(techLink(tch.d3fendId, tch.name, tch.url));
      const badge = mapBadge(tch.attackIds);
      if (badge) main.appendChild(badge);
      let subsBox: HTMLElement | null = null;
      if (tch.subtechniques.length) {
        const toggle = el("span", "att-sub-toggle");
        toggle.textContent = `▸ ${tch.subtechniques.length}`;
        subsBox = el("div", "att-subs");
        for (const s of tch.subtechniques) {
          const sd = el("div", "att-sub");
          const sid = el("span", "att-id"); sid.textContent = s.d3fendId;
          sd.appendChild(sid); sd.appendChild(document.createTextNode(" "));
          sd.appendChild(techLink(s.d3fendId, s.name, s.url));
          const sb = mapBadge(s.attackIds);
          if (sb) sd.appendChild(sb);
          subsBox.appendChild(sd);
        }
        toggle.onclick = () => {
          const open = subsBox!.classList.toggle("open");
          toggle.textContent = `${open ? "▾" : "▸"} ${tch.subtechniques.length}`;
        };
        main.appendChild(toggle);
      }
      cell.appendChild(main);
      if (subsBox) cell.appendChild(subsBox);
      bodyEl.appendChild(cell);
    }
    col.appendChild(bodyEl);
    root.appendChild(col);
  }
  $("d3-stats").textContent =
    `${m.tactics.length} tactiques · ${techCount} techniques · ${subCount} sous-techniques · ${mapCount} liens ATT&CK`;
  applyFilter();
}

function applyFilter(): void {
  const q = ($("d3-search") as HTMLInputElement).value.trim().toLowerCase();
  document.querySelectorAll<HTMLElement>(".att-cell").forEach((c) => {
    c.style.display = !q || (c.dataset.s ?? "").includes(q) ? "" : "none";
  });
}

async function load(): Promise<void> {
  const root = $("d3-matrix");
  root.innerHTML = `<div style="padding:24px;color:var(--text-muted)">Chargement…</div>`;
  try {
    const r = await fetch("/api/d3fend/matrix");
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      root.innerHTML = `<div style="padding:24px;color:var(--danger)">${(d as { error?: string }).error || `Erreur ${r.status}`}</div>`;
      return;
    }
    const m = (await r.json()) as Matrix;
    render(m);
    if (!m.tactics.some((t) => t.techniques.length)) {
      root.insertAdjacentHTML("afterbegin",
        `<div style="padding:0 16px 12px;color:var(--text-dim);font-size:12px">Aucune technique importée. Lancez <code>python xorcism_python/importers/import_d3fend.py</code>.</div>`);
    }
  } catch (e) {
    root.innerHTML = `<div style="padding:24px;color:var(--danger)">${(e as Error).message}</div>`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  ($("d3-search") as HTMLInputElement).oninput = applyFilter;
  void load();
});
