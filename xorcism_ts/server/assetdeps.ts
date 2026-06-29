/**
 * assetdeps.ts — true asset→asset dependency edges.
 *
 * XORCISM holds several relationship signals, but none was a direct asset→asset edge:
 *   - BIADEPENDENCY links BIA *functions* (BIAENTRY rows), not assets;
 *   - CONNECTIONFORASSET links an asset to a connection, not to another asset;
 *   - APPLICATIONDEPENDENCY links applications (parent→subject), not assets.
 *
 * This module introduces ASSETDEPENDENCY (FromAssetID depends-on ToAssetID) and derives it from the
 * real data above, so dependency centrality (used by the BIA computation) reflects genuine
 * "what depends on what", not a proxy. Edges are deterministic and idempotent; a manual edge can also
 * be added. An edge From→To means "From depends on To", so an asset's importance is its **in-degree**
 * (how many other assets depend on it).
 */
import { getDb } from "./db";

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};

export function ensureAssetDependencyTable(): void {
  getDb("XORCISM").exec(`CREATE TABLE IF NOT EXISTS ASSETDEPENDENCY(
    AssetDependencyID INTEGER PRIMARY KEY AUTOINCREMENT,
    FromAssetID INTEGER, ToAssetID INTEGER, DependencyType TEXT, Source TEXT,
    TenantID INTEGER, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_assetdep_to ON ASSETDEPENDENCY(ToAssetID);
    CREATE INDEX IF NOT EXISTS ix_assetdep_from ON ASSETDEPENDENCY(FromAssetID);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_assetdep_edge ON ASSETDEPENDENCY(FromAssetID, ToAssetID, Source);`);
}

export function addAssetDependency(tenant: number | null, fromId: number, toId: number, depType = "manual", source = "manual"): { ok: boolean; created: boolean } {
  if (!Number.isFinite(fromId) || !Number.isFinite(toId) || fromId === toId) return { ok: false, created: false };
  ensureAssetDependencyTable();
  const db = getDb("XORCISM");
  const info = db.prepare(`INSERT OR IGNORE INTO ASSETDEPENDENCY (FromAssetID, ToAssetID, DependencyType, Source, TenantID, CreatedDate) VALUES (?,?,?,?,?,?)`)
    .run(fromId, toId, depType, source, tenant, new Date().toISOString());
  return { ok: true, created: info.changes > 0 };
}

export function removeAssetDependency(id: number): { ok: boolean } {
  ensureAssetDependencyTable();
  getDb("XORCISM").prepare("DELETE FROM ASSETDEPENDENCY WHERE AssetDependencyID=?").run(id);
  return { ok: true };
}

export interface AssetDepEdge { id: number; from: number; to: number; fromName: string; toName: string; type: string; source: string; }
export function listAssetDependencies(tenant: number | null, limit = 500): AssetDepEdge[] {
  ensureAssetDependencyTable();
  const db = getDb("XORCISM");
  const tw = tenant != null ? "WHERE (d.TenantID=? OR d.TenantID IS NULL)" : "";
  const rows = db.prepare(`SELECT d.AssetDependencyID id, d.FromAssetID f, d.ToAssetID t, d.DependencyType ty, d.Source src,
      a1.AssetName fn, a2.AssetName tn
    FROM ASSETDEPENDENCY d
    LEFT JOIN ASSET a1 ON a1.AssetID=d.FromAssetID LEFT JOIN ASSET a2 ON a2.AssetID=d.ToAssetID
    ${tw} ORDER BY d.AssetDependencyID DESC LIMIT ?`).all(...(tenant != null ? [tenant, limit] : [limit])) as Record<string, unknown>[];
  return rows.map((r) => ({ id: Number(r.id), from: Number(r.f), to: Number(r.t), fromName: String(r.fn || `#${r.f}`), toName: String(r.tn || `#${r.t}`), type: String(r.ty || ""), source: String(r.src || "") }));
}

/** In-degree per asset: how many assets depend ON it (= centrality for BIA). Empty map if no edges. */
export function assetDependencyDegree(tenant: number | null): Map<number, number> {
  const m = new Map<number, number>();
  const db = getDb("XORCISM");
  if (!has(db, "ASSETDEPENDENCY")) return m;
  const tw = tenant != null ? "WHERE (TenantID=? OR TenantID IS NULL)" : "";
  for (const r of db.prepare(`SELECT ToAssetID id, COUNT(*) n FROM ASSETDEPENDENCY ${tw} GROUP BY ToAssetID`).all(...(tenant != null ? [tenant] : [])) as { id: number; n: number }[])
    m.set(Number(r.id), Number(r.n));
  return m;
}

export interface DeriveResult { appEdges: number; networkEdges: number; totalEdges: number; }
/**
 * Derive asset→asset edges from existing data (idempotent — INSERT OR IGNORE):
 *   - app dependency: APPLICATIONDEPENDENCY (parent→subject app) mapped to the assets that host each app
 *     via APPLICATIONFORASSET → a directed, semantic "host depends on host" edge (Source='app');
 *   - network adjacency: two assets sharing a CONNECTIONFORASSET connection (Source='network', both directions).
 */
export function deriveAssetDependencies(tenant: number | null): DeriveResult {
  ensureAssetDependencyTable();
  const db = getDb("XORCISM");
  const out: DeriveResult = { appEdges: 0, networkEdges: 0, totalEdges: 0 };
  const add = (f: number, t: number, ty: string, src: string): boolean => {
    if (!f || !t || f === t) return false;
    return db.prepare(`INSERT OR IGNORE INTO ASSETDEPENDENCY (FromAssetID, ToAssetID, DependencyType, Source, TenantID, CreatedDate) VALUES (?,?,?,?,?,?)`)
      .run(f, t, ty, src, tenant, new Date().toISOString()).changes > 0;
  };

  // 1) application dependency → asset dependency
  try {
    if (has(db, "APPLICATIONDEPENDENCY") && has(db, "APPLICATIONFORASSET")) {
      const appAssets = new Map<number, number[]>();
      for (const r of db.prepare("SELECT ApplicationID app, AssetID asset FROM APPLICATIONFORASSET").all() as { app: number; asset: number }[])
        (appAssets.get(Number(r.app)) ?? appAssets.set(Number(r.app), []).get(Number(r.app))!).push(Number(r.asset));
      const deps = db.prepare("SELECT ApplicationParentID p, ApplicationSubjectID s FROM APPLICATIONDEPENDENCY").all() as { p: number; s: number }[];
      for (const d of deps) {
        const parents = appAssets.get(Number(d.p)) || [], subjects = appAssets.get(Number(d.s)) || [];
        for (const pa of parents) for (const sa of subjects) if (add(pa, sa, "application", "app")) out.appEdges++;
      }
    }
  } catch { /* */ }

  // 2) shared-connection network adjacency (bidirectional)
  try {
    if (has(db, "CONNECTIONFORASSET")) {
      const byConn = new Map<number, number[]>();
      for (const r of db.prepare("SELECT ConnectionID c, AssetID asset FROM CONNECTIONFORASSET WHERE ConnectionID IS NOT NULL").all() as { c: number; asset: number }[])
        (byConn.get(Number(r.c)) ?? byConn.set(Number(r.c), []).get(Number(r.c))!).push(Number(r.asset));
      for (const grp of byConn.values()) {
        const uniq = [...new Set(grp)];
        if (uniq.length < 2 || uniq.length > 40) continue; // skip singletons & implausibly large shared connections
        for (let i = 0; i < uniq.length; i++) for (let j = i + 1; j < uniq.length; j++) {
          if (add(uniq[i], uniq[j], "network", "network")) out.networkEdges++;
          if (add(uniq[j], uniq[i], "network", "network")) out.networkEdges++;
        }
      }
    }
  } catch { /* */ }

  out.totalEdges = out.appEdges + out.networkEdges;
  return out;
}
