/**
 * oscalcatalog.ts — OSCAL catalog / profile import for control-id resolution.
 *
 * The audit package can export an OSCAL System Security Plan, but its control-ids were derived from
 * XORCISM's internal control mappings. Importing a real OSCAL catalog (e.g. NIST SP 800-53 rev5) or a
 * profile lets the SSP exporter resolve each internal control to a *canonical* control-id and pull the
 * official control title — so the artifact lines up with the assessor's baseline.
 *
 * Parsing is tolerant of both a catalog (rich: groups/controls with titles) and a profile (control ids
 * only). Stored in XCOMPLIANCE.OSCALCONTROL; deterministic and idempotent per catalog id.
 */
import { getDb } from "./db";

export function ensureOscalTable(): void {
  getDb("XCOMPLIANCE").exec(`CREATE TABLE IF NOT EXISTS OSCALCONTROL(
    OscalControlID INTEGER PRIMARY KEY AUTOINCREMENT,
    CatalogId TEXT, CatalogTitle TEXT, ControlId TEXT, Title TEXT, Class TEXT,
    TenantID INTEGER, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_oscalctl_cat ON OSCALCONTROL(CatalogId);
    CREATE INDEX IF NOT EXISTS ix_oscalctl_cid ON OSCALCONTROL(ControlId);`);
}

interface FlatControl { id: string; title: string; cls: string; }
// Recursively collect controls from catalog groups/controls (OSCAL catalog shape).
function collectFromCatalog(node: Record<string, unknown>, out: FlatControl[]): void {
  const controls = (node.controls as Record<string, unknown>[]) || [];
  for (const c of controls) {
    if (c && c.id) out.push({ id: String(c.id), title: String(c.title || ""), cls: String(c.class || "") });
    collectFromCatalog(c, out); // nested enhancements
  }
  const groups = (node.groups as Record<string, unknown>[]) || [];
  for (const g of groups) collectFromCatalog(g, out);
}
// Profiles only reference ids (with-ids / matching) — collect those.
function collectFromProfile(profile: Record<string, unknown>, out: FlatControl[]): void {
  const imports = (profile.imports as Record<string, unknown>[]) || [];
  for (const im of imports) {
    const inc = (im["include-controls"] as Record<string, unknown>[]) || [];
    for (const sel of inc) for (const id of ((sel["with-ids"] as string[]) || [])) out.push({ id: String(id), title: "", cls: "" });
  }
}

export interface OscalImportResult { catalogId: string; catalogTitle: string; controls: number; kind: "catalog" | "profile"; }
export function importOscalCatalog(json: unknown, tenant: number | null): OscalImportResult {
  ensureOscalTable();
  const doc = json as Record<string, unknown>;
  const cat = doc.catalog as Record<string, unknown> | undefined;
  const prof = doc.profile as Record<string, unknown> | undefined;
  const root = (cat || prof) as Record<string, unknown> | undefined;
  if (!root) throw new Error("not an OSCAL catalog or profile (missing top-level 'catalog'/'profile')");
  const meta = (root.metadata as Record<string, unknown>) || {};
  const catalogTitle = String(meta.title || (cat ? "OSCAL catalog" : "OSCAL profile"));
  const catalogId = String(root.uuid || catalogTitle).slice(0, 120);
  const flat: FlatControl[] = [];
  if (cat) collectFromCatalog(cat, flat); else if (prof) collectFromProfile(prof, flat);
  // dedupe by id
  const seen = new Set<string>(); const rows = flat.filter((c) => { const k = c.id.toLowerCase(); if (seen.has(k)) return false; seen.add(k); return true; });

  const db = getDb("XCOMPLIANCE");
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM OSCALCONTROL WHERE CatalogId=?").run(catalogId); // re-import replaces
    const ins = db.prepare("INSERT INTO OSCALCONTROL (CatalogId, CatalogTitle, ControlId, Title, Class, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?)");
    const now = new Date().toISOString();
    for (const c of rows) ins.run(catalogId, catalogTitle, c.id, c.title, c.cls, tenant, now);
  });
  tx();
  return { catalogId, catalogTitle, controls: rows.length, kind: cat ? "catalog" : "profile" };
}

export interface OscalCatalogInfo { catalogId: string; catalogTitle: string; controls: number; }
export function listOscalCatalogs(tenant: number | null): OscalCatalogInfo[] {
  ensureOscalTable();
  const db = getDb("XCOMPLIANCE");
  const tw = tenant != null ? "WHERE (TenantID=? OR TenantID IS NULL)" : "";
  return (db.prepare(`SELECT CatalogId cid, CatalogTitle ct, COUNT(*) n FROM OSCALCONTROL ${tw} GROUP BY CatalogId, CatalogTitle ORDER BY ct`).all(...(tenant != null ? [tenant] : [])) as Record<string, unknown>[])
    .map((r) => ({ catalogId: String(r.cid), catalogTitle: String(r.ct), controls: Number(r.n) }));
}

/** Resolve a control reference (e.g. "AC-2", "ac-2(1)", "CC7.2") to a canonical OSCAL control id + title. */
export function resolveControlId(tenant: number | null, ref: string): { controlId: string; title: string } | null {
  if (!ref) return null;
  ensureOscalTable();
  const db = getDb("XCOMPLIANCE");
  const key = ref.toLowerCase().replace(/\s+/g, "");
  const tw = tenant != null ? "AND (TenantID=? OR TenantID IS NULL)" : "";
  const row = db.prepare(`SELECT ControlId cid, Title t FROM OSCALCONTROL WHERE REPLACE(LOWER(ControlId),' ','')=? ${tw} LIMIT 1`)
    .get(...(tenant != null ? [key, tenant] : [key])) as { cid: string; t: string } | undefined;
  return row ? { controlId: String(row.cid), title: String(row.t || "") } : null;
}
