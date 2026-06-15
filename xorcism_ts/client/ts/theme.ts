/**
 * theme.ts — Display theme driven by CSS variables.
 *
 * The theme is applied by setting the `data-theme` attribute on <html>; the
 * variables are defined in css/style.css (:root + html[data-theme="…"]).
 * Choice persisted in localStorage. All the variants stay dark to
 * remain consistent with the modal windows (styled in dark).
 *
 * To avoid the flash on load, a small inline script in <head> already applies
 * the stored theme BEFORE rendering; this module re-applies it just in case.
 */

const STORAGE_KEY = "xorcism.theme";
const DEFAULT = "indigo";

export interface ThemeDef { code: string; label: string }

// Deliberately explicit labels (no translation: palette names).
export const THEMES: ThemeDef[] = [
  { code: "indigo", label: "Indigo (défaut)" },
  { code: "violet", label: "Violet" },
  { code: "emerald", label: "Emerald" },
  { code: "cyan", label: "Cyan" },
  { code: "amber", label: "Amber" },
  { code: "rose", label: "Rose" },
  { code: "midnight", label: "Midnight (sombre)" },
  { code: "slate", label: "Slate" },
];

export function getTheme(): string {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v && THEMES.some((t) => t.code === v)) return v;
  } catch {
    /* localStorage unavailable */
  }
  return DEFAULT;
}

/** Applies a theme (data-theme on <html>) and persists it. */
export function applyTheme(code: string): void {
  const valid = THEMES.some((t) => t.code === code) ? code : DEFAULT;
  document.documentElement.setAttribute("data-theme", valid);
  try { localStorage.setItem(STORAGE_KEY, valid); } catch { /* ignore */ }
}

/** Applies the stored theme (idempotent). To be called early. */
export function initTheme(): void {
  applyTheme(getTheme());
}

/** Builds the theme <select> (Settings panel). */
export function createThemeSelect(): HTMLSelectElement {
  const sel = document.createElement("select");
  sel.className = "theme-select";
  sel.style.cssText =
    "background:var(--bg);border:1px solid var(--border);border-radius:6px;" +
    "color:var(--text);font-size:12px;padding:4px 6px;cursor:pointer";
  const current = getTheme();
  THEMES.forEach((thm) => {
    const opt = document.createElement("option");
    opt.value = thm.code;
    opt.textContent = thm.label;
    if (thm.code === current) opt.selected = true;
    sel.appendChild(opt);
  });
  sel.onchange = () => applyTheme(sel.value);
  return sel;
}

// Applies the theme as soon as the module loads (the bundles are at the end of
// <body>: the <head> script already set the attribute, this serves as a safety net).
initTheme();
