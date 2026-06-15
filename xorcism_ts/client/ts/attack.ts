/**
 * attack.ts — MITRE ATT&CK matrix view (tactics → techniques → sub-techniques),
 * read from XTHREAT.ATTACK* via /api/attack/matrix.
 */
// Aliased as `tr`: `t` is already used as a loop variable (technique) in this file.
import { initI18n, t as tr } from "./i18n";

interface Sub { attackId: string; name: string; url: string | null }
interface Tech { attackId: string; name: string; url: string | null; subtechniques: Sub[] }
interface Tactic { attackId: string; name: string; shortName: string; url: string | null; techniques: Tech[] }
interface Matrix { domain: string; tactics: Tactic[] }

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function el(tag: string, cls?: string): HTMLElement { const e = document.createElement(tag); if (cls) e.className = cls; return e; }

// ── Validation coverage (BAS): heatmap per ATT&CK technique ──────────────────────
interface Cov { tests: number; detected: number; prevented: number; status: string }
let coverage: Record<string, Cov> = {};
const COV_COLOR: Record<string, string> = { prevented: "#22c55e", detected: "#2dd4bf", tested: "#f59e0b" };
// Coverage label resolved AT CALL TIME (not at module load: t() isn't ready yet
// during top-level constant evaluation).
const covLabel = (s: string): string => tr("cov." + s) || s;
const COV_RANK: Record<string, number> = { "": 0, tested: 1, detected: 2, prevented: 3 };
// Aggregated status = max(technique, its sub-techniques); counters summed.
function rollup(t: Tech): Cov {
  const best: Cov = { tests: 0, detected: 0, prevented: 0, status: "" };
  const acc = (c?: Cov): void => {
    if (!c) return;
    best.tests += c.tests; best.detected += c.detected; best.prevented += c.prevented;
    if ((COV_RANK[c.status] ?? 0) > (COV_RANK[best.status] ?? 0)) best.status = c.status;
  };
  acc(coverage[t.attackId]);
  for (const s of t.subtechniques) acc(coverage[s.attackId]);
  return best;
}

function techLink(attackId: string, name: string, url: string | null): HTMLElement {
  const a = document.createElement("a");
  a.textContent = name;
  a.title = `${attackId} — ${name}`;
  if (url) { a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer"; }
  return a;
}

function render(m: Matrix): void {
  const root = $("att-matrix");
  root.innerHTML = "";
  let techCount = 0, subCount = 0, covered = 0;
  for (const tac of m.tactics) {
    const col = el("div", "att-col");
    const head = el("div", "att-col-head");
    head.innerHTML =
      `<div class="att-tac-name">${tac.name}</div>` +
      `<div class="att-tac-meta">${tac.attackId} · ${tac.techniques.length} tech.</div>`;
    col.appendChild(head);
    const bodyEl = el("div", "att-col-body");
    for (const t of tac.techniques) {
      techCount++;
      subCount += t.subtechniques.length;
      const cell = el("div", "att-cell");
      cell.dataset.s = `${t.attackId} ${t.name}`.toLowerCase() +
        " " + t.subtechniques.map((s) => `${s.attackId} ${s.name}`).join(" ").toLowerCase();
      const main = el("div", "att-cell-main");
      const id = el("span", "att-id"); id.textContent = t.attackId;
      main.appendChild(id);
      main.appendChild(techLink(t.attackId, t.name, t.url));
      let subsBox: HTMLElement | null = null;
      if (t.subtechniques.length) {
        const toggle = el("span", "att-sub-toggle");
        toggle.textContent = `▸ ${t.subtechniques.length}`;
        subsBox = el("div", "att-subs");
        for (const s of t.subtechniques) {
          const sd = el("div", "att-sub");
          const sid = el("span", "att-id"); sid.textContent = s.attackId.split(".").pop() || s.attackId;
          sd.appendChild(sid); sd.appendChild(document.createTextNode(" "));
          sd.appendChild(techLink(s.attackId, s.name, s.url));
          subsBox.appendChild(sd);
        }
        toggle.onclick = () => {
          const open = subsBox!.classList.toggle("open");
          toggle.textContent = `${open ? "▾" : "▸"} ${t.subtechniques.length}`;
        };
        main.appendChild(toggle);
      }
      // Validation coverage (BAS): border + badge based on the aggregated status.
      const cov = rollup(t);
      if (cov.status) {
        covered++;
        cell.style.borderLeft = `3px solid ${COV_COLOR[cov.status]}`;
        const badge = el("span", "att-cov");
        badge.textContent = "🛡" + (cov.tests || cov.detected + cov.prevented);
        badge.title = `${tr("tip.validation")} ${covLabel(cov.status)} · ${tr("tip.tests")} ${cov.tests}, ${tr("cov.detected")} ${cov.detected}, ${tr("cov.prevented")} ${cov.prevented}`;
        badge.style.cssText = `margin-left:6px;font-size:10px;color:${COV_COLOR[cov.status]}`;
        main.appendChild(badge);
      }
      cell.appendChild(main);
      if (subsBox) cell.appendChild(subsBox);
      bodyEl.appendChild(cell);
    }
    col.appendChild(bodyEl);
    root.appendChild(col);
  }
  const base = `${m.tactics.length} ${tr("attack.tactics")} · ${techCount} ${tr("attack.techniques")} · ${subCount} ${tr("attack.subtechniques")}`;
  $("att-stats").innerHTML = Object.keys(coverage).length
    ? `${base} · <span style="color:${COV_COLOR.tested}">🛡 ${covered} ${tr("attack.validated")}</span> ` +
      `<span style="color:#64748b">(<span style="color:${COV_COLOR.prevented}">■</span> ${tr("cov.prevented")} ` +
      `<span style="color:${COV_COLOR.detected}">■</span> ${tr("cov.detected")} ` +
      `<span style="color:${COV_COLOR.tested}">■</span> ${tr("cov.tested")})</span>`
    : base;
  applyFilter();
}

function applyFilter(): void {
  const q = ($("att-search") as HTMLInputElement).value.trim().toLowerCase();
  document.querySelectorAll<HTMLElement>(".att-cell").forEach((c) => {
    c.style.display = !q || (c.dataset.s ?? "").includes(q) ? "" : "none";
  });
}

async function load(domain: string): Promise<void> {
  const root = $("att-matrix");
  root.innerHTML = `<div style="padding:24px;color:var(--text-muted)">Loading…</div>`;
  try {
    const r = await fetch(`/api/attack/matrix?domain=${encodeURIComponent(domain)}`);
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      root.innerHTML = `<div style="padding:24px;color:var(--danger)">${(d as { error?: string }).error || `Error ${r.status}`}</div>`;
      return;
    }
    const matrix = (await r.json()) as Matrix;
    // Validation coverage (BAS) — best-effort, does not block rendering.
    try { coverage = ((await (await fetch("/api/attack/coverage")).json()) as { byAttackId: Record<string, Cov> }).byAttackId || {}; }
    catch { coverage = {}; }
    render(matrix);
  } catch (e) {
    root.innerHTML = `<div style="padding:24px;color:var(--danger)">${(e as Error).message}</div>`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  const sel = $("att-domain") as HTMLSelectElement;
  sel.onchange = () => void load(sel.value);
  ($("att-search") as HTMLInputElement).oninput = applyFilter;
  void load(sel.value);
});
