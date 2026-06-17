/**
 * landing.ts — Configurable main menu: drag-to-reorder the landing domain cards.
 * The order is saved per-user via the prefs API (key "landing-order" = list of card hrefs),
 * so it persists across sessions/devices and degrades gracefully (new cards go to the end).
 */
import { t } from "./i18n";

const PREF_KEY = "landing-order";
const cards = (grid: Element): HTMLAnchorElement[] => [...grid.querySelectorAll<HTMLAnchorElement>(".domain-card")];
const hrefOf = (c: HTMLAnchorElement): string => c.getAttribute("href") || "";
const currentOrder = (grid: Element): string[] => cards(grid).map(hrefOf);

async function loadOrder(): Promise<string[] | null> {
  try { const r = await fetch(`/api/prefs/${PREF_KEY}`); if (!r.ok) return null; const d = await r.json(); return Array.isArray(d.value) ? d.value : null; }
  catch { return null; }
}
async function saveOrder(order: string[]): Promise<void> {
  try { await fetch(`/api/prefs/${PREF_KEY}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ value: order }) }); } catch { /* offline */ }
}
function applyOrder(grid: Element, order: string[]): void {
  const list = cards(grid); const byHref = new Map(list.map((c) => [hrefOf(c), c]));
  const seen = new Set<string>();
  for (const h of order) { const c = byHref.get(h); if (c) { grid.appendChild(c); seen.add(h); } }       // saved order first
  for (const c of list) if (!seen.has(hrefOf(c))) grid.appendChild(c);                                    // new cards keep their tail position
}

document.addEventListener("DOMContentLoaded", async () => {
  const grid = document.querySelector(".domain-grid");
  const btn = document.getElementById("landing-reorder");
  const reset = document.getElementById("landing-reset");
  const label = document.getElementById("lr-label");
  if (!grid || !btn) return;

  const saved = await loadOrder();
  if (saved && saved.length) applyOrder(grid, saved);

  let editing = false; let dragged: HTMLAnchorElement | null = null;
  const setEditing = (on: boolean): void => {
    editing = on;
    grid.classList.toggle("reordering", on);
    cards(grid).forEach((c) => { c.draggable = on; });
    if (reset) reset.style.display = on ? "" : "none";
    if (label) label.textContent = on ? t("landing.reorderDone") : t("landing.reorder");
  };

  btn.addEventListener("click", () => setEditing(!editing));
  reset?.addEventListener("click", async () => { await saveOrder([]); location.reload(); });

  grid.addEventListener("dragstart", (e) => {
    const c = (e.target as HTMLElement).closest<HTMLAnchorElement>(".domain-card");
    if (!editing || !c) return;
    dragged = c; c.classList.add("dragging");
    try { (e as DragEvent).dataTransfer!.effectAllowed = "move"; } catch { /* */ }
  });
  grid.addEventListener("dragend", () => {
    if (!dragged) return;
    dragged.classList.remove("dragging"); dragged = null;
    void saveOrder(currentOrder(grid));
  });
  grid.addEventListener("dragover", (e) => {
    if (!editing || !dragged) return;
    e.preventDefault();
    const target = (e.target as HTMLElement).closest<HTMLAnchorElement>(".domain-card");
    if (!target || target === dragged) return;
    const r = target.getBoundingClientRect();
    const before = ((e as DragEvent).clientX - r.left) < r.width / 2;   // left half → insert before, else after
    grid.insertBefore(dragged, before ? target : target.nextSibling);
  });
  // while editing, a card click must NOT navigate
  grid.addEventListener("click", (e) => {
    if (editing && (e.target as HTMLElement).closest(".domain-card")) e.preventDefault();
  }, true);
});
