/**
 * landing.ts — Fusion-center main menu grouped into "approaches" (asset / exposure / threat /
 * risk / compliance / operations / platform). Two per-user personalisations, both saved via the
 * prefs API so they persist across sessions/devices and degrade gracefully:
 *   • Drag-to-reorder the domain cards WITHIN their approach   → key "landing-order" = { [groupId]: hrefs[] }
 *   • Pin favourite cards to a "Pinned" row at the very top    → key "landing-pins"  = hrefs[]
 * Pinning never moves a card out of its approach — the pinned row holds clones, and the original
 * card keeps a lit star so the two stay in sync.
 */
import { t } from "./i18n";

const PREF_KEY = "landing-order";
const PIN_KEY = "landing-pins";
type OrderMap = Record<string, string[]>;

const grids = (): HTMLElement[] => [...document.querySelectorAll<HTMLElement>(".domain-grid")];
const cardsIn = (grid: Element): HTMLAnchorElement[] => [...grid.querySelectorAll<HTMLAnchorElement>(".domain-card")];
const hrefOf = (c: HTMLAnchorElement): string => c.getAttribute("href") || "";
const groupOf = (grid: Element): string =>
  (grid as HTMLElement).dataset.group || (grid.closest<HTMLElement>(".approach")?.dataset.group ?? "");

/**
 * Populate the topbar "Go to…" dropdown from the visible cards, grouped by approach, so any
 * page is one selection away. Skips hidden cards (access-control / NICE filter) and re-reads
 * the live DOM, so it always reflects exactly what the user can see.
 */
function buildJumpMenu(): void {
  const sel = document.getElementById("jump-select") as HTMLSelectElement | null;
  if (!sel) return;
  sel.querySelectorAll("optgroup").forEach((g) => g.remove());
  for (const section of document.querySelectorAll<HTMLElement>("section.approach")) {
    if (section.style.display === "none") continue;
    const label = section.querySelector(".approach-title")?.textContent?.trim() || (section.dataset.group ?? "");
    const grid = section.querySelector(".domain-grid");
    if (!grid) continue;
    const og = document.createElement("optgroup");
    og.label = label;
    for (const card of grid.querySelectorAll<HTMLAnchorElement>(".domain-card")) {
      if ((card as HTMLElement).style.display === "none" || card.offsetParent === null) continue;
      const href = card.getAttribute("href");
      if (!href) continue;
      const title = card.querySelector(".domain-title")?.textContent?.trim() || href;
      const o = document.createElement("option");
      o.value = href; o.textContent = title;
      og.appendChild(o);
    }
    if (og.children.length) sel.appendChild(og);
  }
  if (!sel.dataset.bound) {
    sel.dataset.bound = "1";
    sel.addEventListener("change", () => { if (sel.value) window.location.href = sel.value; });
  }
}

/** Snapshot the current order of every approach grid. */
function currentMap(): OrderMap {
  const m: OrderMap = {};
  for (const g of grids()) m[groupOf(g)] = cardsIn(g).map(hrefOf);
  return m;
}
async function loadOrder(): Promise<OrderMap | null> {
  try {
    const r = await fetch(`/api/prefs/${PREF_KEY}`); if (!r.ok) return null;
    const d = await r.json(); const v = d.value;
    // Current format is an object map; tolerate (and ignore) the old flat-array format.
    return v && typeof v === "object" && !Array.isArray(v) ? (v as OrderMap) : null;
  } catch { return null; }
}
async function saveOrder(map: OrderMap): Promise<void> {
  try {
    await fetch(`/api/prefs/${PREF_KEY}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ value: map }) });
  } catch { /* offline */ }
}
function applyOrder(map: OrderMap): void {
  for (const grid of grids()) {
    const order = map[groupOf(grid)]; if (!Array.isArray(order)) continue;
    const list = cardsIn(grid); const byHref = new Map(list.map((c) => [hrefOf(c), c]));
    const seen = new Set<string>();
    for (const h of order) { const c = byHref.get(h); if (c) { grid.appendChild(c); seen.add(h); } } // saved order first
    for (const c of list) if (!seen.has(hrefOf(c))) grid.appendChild(c);                              // new cards keep their tail position
  }
}

// ── NICE-profile filter + per-group/card access control (config from /api/landing/config) ──
const NICE_PREF = "landing-nice";
interface LandingCfg { profiles: string[]; groupRelevance: Record<string, string[]>; cardRelevance: Record<string, string[]>; restrictions: { itemType: string; itemKey: string; profiles: string[] }[]; userProfiles: string[]; rbacDenied?: string[]; isAdmin: boolean }

async function loadLandingCfg(): Promise<LandingCfg | null> {
  try { const r = await fetch("/api/landing/config"); if (!r.ok) return null; return await r.json(); } catch { return null; }
}
async function loadNice(): Promise<string> {
  try { const r = await fetch(`/api/prefs/${NICE_PREF}`); if (!r.ok) return ""; const d = await r.json(); return typeof d.value === "string" ? d.value : ""; } catch { return ""; }
}
async function saveNice(v: string): Promise<void> {
  try { await fetch(`/api/prefs/${NICE_PREF}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ value: v }) }); } catch { /* offline */ }
}
const gridGroupOf = (c: HTMLAnchorElement): string => { const g = c.closest(".domain-grid"); return g ? groupOf(g) : ""; };
const relevanceOf = (cfg: LandingCfg, c: HTMLAnchorElement): string[] => cfg.cardRelevance[hrefOf(c)] || cfg.groupRelevance[gridGroupOf(c)] || [];

/** Hide cards/groups the (non-admin) user's NICE profile is not allowed to see. */
function applyAccess(cfg: LandingCfg): void {
  if (cfg.isAdmin) return; // admins see everything
  const up = new Set(cfg.userProfiles || []);
  const denied = new Set(cfg.rbacDenied || []); // RBAC: feature pages this role can't access
  const byCard = new Map<string, string[]>(), byGroup = new Map<string, string[]>();
  for (const r of cfg.restrictions || []) (r.itemType === "group" ? byGroup : byCard).set(r.itemKey, r.profiles || []);
  const ok = (ps: string[]): boolean => ps.length === 0 || ps.some((p) => up.has(p));
  const hide = (c: HTMLAnchorElement): void => { c.classList.add("access-hidden"); c.style.display = "none"; };
  for (const grid of grids()) {
    const section = grid.closest<HTMLElement>(".approach");
    const gr = byGroup.get(groupOf(grid));
    if (gr && !ok(gr)) { for (const c of cardsIn(grid)) hide(c); section?.classList.add("access-hidden-group"); if (section) section.style.display = "none"; continue; }
    for (const c of cardsIn(grid)) { const cr = byCard.get(hrefOf(c)); if ((cr && !ok(cr)) || denied.has(hrefOf(c))) hide(c); }
    if (section && !cardsIn(grid).some((c) => !c.classList.contains("access-hidden"))) { section.classList.add("access-hidden-group"); section.style.display = "none"; }
  }
}

/** Show only the cards relevant to the chosen NICE profile (empty string = all). Skips access-hidden items. */
function applyNiceFilter(cfg: LandingCfg, profile: string): void {
  for (const grid of grids()) {
    const section = grid.closest<HTMLElement>(".approach");
    if (section && section.classList.contains("access-hidden-group")) continue;
    let any = false;
    for (const c of cardsIn(grid)) {
      if (c.classList.contains("access-hidden")) continue;
      const show = !profile || relevanceOf(cfg, c).includes(profile);
      c.style.display = show ? "" : "none";
      if (show) any = true;
    }
    if (section) section.style.display = any ? "" : "none";
  }
}

/** Pinned favourites — a flat list of card hrefs, surfaced in a row at the top of the menu. */
async function loadPins(): Promise<string[]> {
  try {
    const r = await fetch(`/api/prefs/${PIN_KEY}`); if (!r.ok) return [];
    const d = await r.json(); const v = d.value;
    return Array.isArray(v) ? v.filter((x: unknown): x is string => typeof x === "string") : [];
  } catch { return []; }
}
async function savePins(pins: string[]): Promise<void> {
  try {
    await fetch(`/api/prefs/${PIN_KEY}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ value: pins }) });
  } catch { /* offline */ }
}

document.addEventListener("DOMContentLoaded", async () => {
  if (!grids().length) return;
  const btn = document.getElementById("landing-reorder");
  const reset = document.getElementById("landing-reset");
  const label = document.getElementById("lr-label");
  if (!btn) return;

  // NICE-profile access control (hide disallowed cards/groups) — must run before pins/reorder.
  const cfg = await loadLandingCfg();
  if (cfg) applyAccess(cfg);

  const saved = await loadOrder();
  if (saved) applyOrder(saved);

  // ── Pinned favourites ───────────────────────────────────────────────────────────────────
  // A star is injected into every real card; clicking it pins/unpins. Pinned cards are cloned
  // into the #pinned-grid row at the top (the originals stay put, with a lit star).
  const STAR_ON = "★", STAR_OFF = "☆"; // ★ / ☆
  let pins = await loadPins();
  const realCards = (): HTMLAnchorElement[] => [...document.querySelectorAll<HTMLAnchorElement>(".domain-grid .domain-card")];
  const pinnedSection = document.getElementById("pinned-approach");
  const pinnedGrid = document.getElementById("pinned-grid");
  const pinnedCount = document.getElementById("pinned-count");

  for (const c of realCards()) {                       // inject the star toggle (idempotent)
    if (c.querySelector(":scope > .pin-btn")) continue;
    const b = document.createElement("button");
    b.type = "button"; b.className = "pin-btn"; b.tabIndex = -1; b.textContent = STAR_OFF;
    c.appendChild(b);
  }
  const refreshStars = (): void => {
    const set = new Set(pins);
    for (const c of realCards()) {
      const on = set.has(hrefOf(c));
      c.classList.toggle("pinned", on);
      const b = c.querySelector<HTMLButtonElement>(":scope > .pin-btn");
      if (b) { b.textContent = on ? STAR_ON : STAR_OFF; b.title = on ? t("landing.unpin") : t("landing.pin"); }
    }
  };
  const renderPinned = (): void => {
    if (!pinnedSection || !pinnedGrid) return;
    pinnedGrid.textContent = "";
    const byHref = new Map(realCards().filter((c) => !c.classList.contains("access-hidden")).map((c) => [hrefOf(c), c]));
    let n = 0;
    for (const h of pins) {
      const src = byHref.get(h); if (!src) continue;                // skip pins whose card no longer exists / is access-hidden
      const clone = src.cloneNode(true) as HTMLAnchorElement;
      clone.classList.add("pinned");
      const cb = clone.querySelector<HTMLButtonElement>(".pin-btn");
      if (cb) { cb.textContent = STAR_ON; cb.title = t("landing.unpin"); } // clones are always pinned
      pinnedGrid.appendChild(clone); n++;
    }
    pinnedSection.style.display = n ? "" : "none";
    if (pinnedCount) pinnedCount.textContent = String(n);
  };
  const togglePin = (href: string): void => {
    if (!href) return;
    pins = pins.includes(href) ? pins.filter((h) => h !== href) : [...pins, href];
    void savePins(pins); refreshStars(); renderPinned();
  };
  refreshStars(); renderPinned();
  // Capture-phase so the toggle beats both the anchor navigation and the edit-mode click-suppressor.
  document.addEventListener("click", (e) => {
    const b = (e.target as HTMLElement).closest<HTMLElement>(".pin-btn"); if (!b) return;
    e.preventDefault(); e.stopPropagation();
    const card = b.closest<HTMLAnchorElement>(".domain-card");
    if (card) togglePin(hrefOf(card));
  }, true);

  let editing = false; let dragged: HTMLAnchorElement | null = null; let dragGrid: Element | null = null;
  const setEditing = (on: boolean): void => {
    editing = on;
    for (const g of grids()) { g.classList.toggle("reordering", on); cardsIn(g).forEach((c) => { c.draggable = on; }); }
    if (reset) reset.style.display = on ? "" : "none";
    if (label) label.textContent = on ? t("landing.reorderDone") : t("landing.reorder");
  };

  btn.addEventListener("click", () => setEditing(!editing));
  reset?.addEventListener("click", async () => { await saveOrder({}); location.reload(); });

  // ── NICE-profile filter dropdown ──
  const niceSel = document.getElementById("landing-nice") as HTMLSelectElement | null;
  if (niceSel && cfg) {
    for (const p of cfg.profiles) { const o = document.createElement("option"); o.value = p; o.textContent = p; niceSel.appendChild(o); }
    let savedNice = await loadNice();
    if (!cfg.profiles.includes(savedNice)) savedNice = "";
    niceSel.value = savedNice;
    applyNiceFilter(cfg, savedNice);
    niceSel.addEventListener("change", () => { applyNiceFilter(cfg, niceSel.value); void saveNice(niceSel.value); buildJumpMenu(); });
  }

  // Topbar "Go to…" dropdown — built after access + NICE filters so it lists only visible cards.
  buildJumpMenu();

  // Document-level drag handlers cover every approach grid; reordering is constrained to the
  // grid the drag started in, so a card never leaves its approach.
  document.addEventListener("dragstart", (e) => {
    const c = (e.target as HTMLElement).closest<HTMLAnchorElement>(".domain-card");
    if (!editing || !c) return;
    dragged = c; dragGrid = c.closest(".domain-grid"); c.classList.add("dragging");
    try { (e as DragEvent).dataTransfer!.effectAllowed = "move"; } catch { /* */ }
  });
  document.addEventListener("dragend", () => {
    if (!dragged) return;
    dragged.classList.remove("dragging"); dragged = null; dragGrid = null;
    void saveOrder(currentMap());
  });
  document.addEventListener("dragover", (e) => {
    if (!editing || !dragged || !dragGrid) return;
    const target = (e.target as HTMLElement).closest<HTMLAnchorElement>(".domain-card");
    if (!target || target === dragged) return;
    if (target.closest(".domain-grid") !== dragGrid) return;   // stay within the same approach
    e.preventDefault();
    const r = target.getBoundingClientRect();
    const before = ((e as DragEvent).clientX - r.left) < r.width / 2; // left half → insert before, else after
    dragGrid.insertBefore(dragged, before ? target : target.nextSibling);
  });
  // while editing, a card click must NOT navigate
  document.addEventListener("click", (e) => {
    if (editing && (e.target as HTMLElement).closest(".domain-card")) e.preventDefault();
  }, true);
});
