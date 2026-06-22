/**
 * stixstore.ts — lossless STIX / IOC retention + full-text search.
 *
 * XORCISM normalizes STIX into relational tables (great for cross-domain joins) but does not keep the
 * original object, so any unmodeled property or extension is lost on round-trip. This module adds the
 * "store the original, index what you query" layer over XTHREAT:
 *   - STIXOBJECT keeps the full original object (RawJson) keyed by StixID;
 *   - the same payload is mirrored onto the inline RawJson column of the matching OBSERVABLE / IOC row;
 *   - STIXOBJECT_FTS (FTS5) indexes name / value / the whole payload for free-text search over IOCs.
 * See ensureStixObjectStore() in db.ts. Surfaced via GET /api/stix/object/:stixId, GET /api/stix/search,
 * POST /api/stix/ingest, POST /api/stix/backfill.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

function nextId(t: string, pk: string): number { return (getDb("XTHREAT").prepare(`SELECT COALESCE(MAX(${pk}),0)+1 n FROM ${t}`).get() as { n: number }).n; }
function tableExists(t: string): boolean { return !!getDb("XTHREAT").prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); }
function safeStringify(o: unknown): string { try { return JSON.stringify(o); } catch { return "{}"; } }
function splitList(s: unknown): string[] | undefined { const v = String(s ?? "").trim(); if (!v) return undefined; const a = v.split(/[,;|]/).map((x) => x.trim()).filter(Boolean); return a.length ? a : undefined; }

// XORCISM observable type → STIX SCO type (best-effort)
const SCO: Record<string, string> = {
  ipv4: "ipv4-addr", "ipv4-addr": "ipv4-addr", ip: "ipv4-addr", ipv6: "ipv6-addr", "ipv6-addr": "ipv6-addr",
  domain: "domain-name", "domain-name": "domain-name", hostname: "domain-name", url: "url",
  email: "email-addr", "email-addr": "email-addr", "email-address": "email-addr",
  file: "file", filehash: "file", hash: "file", md5: "file", sha1: "file", sha256: "file",
  "mac-addr": "mac-addr", mac: "mac-addr", "user-account": "user-account", mutex: "mutex",
  "windows-registry-key": "windows-registry-key", registry: "windows-registry-key", "autonomous-system": "autonomous-system",
};
function scoType(t: unknown): string {
  const k = String(t ?? "").trim().toLowerCase();
  return SCO[k] || (k ? k.replace(/[^a-z0-9-]/g, "-") : "x-observable");
}

/** Upsert one STIX object (keyed by its id) into the lossless store + FTS, and mirror it onto the
 *  inline RawJson column of the matching OBSERVABLE / IOC row. Returns the StixID it was stored under. */
export function storeStixObject(obj: any, opts: { source?: string; tenant?: number | null; mirror?: { table: string; pkCol: string; pkVal: number | string } } = {}): { id: number; stixId: string } | null {
  if (!obj || typeof obj !== "object") return null;
  const db = getDb("XTHREAT");
  const stixType = String(obj.type ?? "").trim() || "object";
  const stixId = String(obj.id ?? obj.stixId ?? "").trim() || `${stixType}--${randomUUID()}`;
  const name = String(obj.name ?? obj.value ?? obj.pattern ?? obj.description ?? "").slice(0, 500);
  const value = String(obj.value ?? obj.pattern ?? "").slice(0, 2000);
  const spec = String(obj.spec_version ?? "").trim();
  const raw = safeStringify(obj);
  const now = new Date().toISOString();
  const source = opts.source || "ingest";

  const ex = db.prepare("SELECT StixObjectID FROM STIXOBJECT WHERE StixID = ?").get(stixId) as { StixObjectID: number } | undefined;
  let id: number;
  if (ex) { id = ex.StixObjectID; db.prepare("UPDATE STIXOBJECT SET StixType=?, SpecVersion=?, Name=?, RawJson=?, Source=?, ModifiedDate=? WHERE StixObjectID=?").run(stixType, spec, name, raw, source, now, id); }
  else { id = nextId("STIXOBJECT", "StixObjectID"); db.prepare("INSERT INTO STIXOBJECT (StixObjectID, StixID, StixType, SpecVersion, Name, RawJson, Source, TenantID, CreatedDate, ModifiedDate) VALUES (?,?,?,?,?,?,?,?,?,?)").run(id, stixId, stixType, spec, name, raw, source, opts.tenant ?? null, now, now); }

  // FTS (standalone, app-maintained): replace the row for this StixID
  try {
    db.prepare("DELETE FROM STIXOBJECT_FTS WHERE stixId = ?").run(stixId);
    db.prepare("INSERT INTO STIXOBJECT_FTS (stixId, stixType, name, value, content) VALUES (?,?,?,?,?)").run(stixId, stixType, name, value, raw.slice(0, 30000));
  } catch { /* FTS5 unavailable */ }

  // mirror onto the inline RawJson column of the source CTI row. When the caller knows the row (the
  // per-row sync hooks) it passes the PK — works even when StixID is NULL (the common case). Otherwise
  // (external ingest) match any OBSERVABLE/IOC carrying this StixID.
  if (opts.mirror) { try { db.prepare(`UPDATE ${opts.mirror.table} SET RawJson=? WHERE ${opts.mirror.pkCol}=?`).run(raw, opts.mirror.pkVal); } catch { /* no RawJson column */ } }
  else { for (const t of ["OBSERVABLE", "IOC"]) { try { db.prepare(`UPDATE ${t} SET RawJson=? WHERE StixID=?`).run(raw, stixId); } catch { /* no RawJson column / no match */ } } }
  return { id, stixId };
}

/** Store a STIX bundle / object / array of objects losslessly. Returns how many objects were stored. */
export function storeBundle(input: any, opts: { source?: string; tenant?: number | null } = {}): { stored: number } {
  const objs: any[] = Array.isArray(input?.objects) ? input.objects : Array.isArray(input) ? input : input && input.type ? [input] : [];
  let n = 0;
  const tx = getDb("XTHREAT").transaction((arr: any[]) => { for (const o of arr) if (storeStixObject(o, opts)) n++; });
  tx(objs);
  return { stored: n };
}

/** Return the original STIX object for a StixID (from the lossless store, else the inline CTI columns). */
export function getStixObject(stixId: string): any | null {
  const db = getDb("XTHREAT");
  const r = db.prepare("SELECT RawJson FROM STIXOBJECT WHERE StixID = ?").get(stixId) as { RawJson: string } | undefined;
  if (r?.RawJson) { try { return JSON.parse(r.RawJson); } catch { /* corrupt */ } }
  for (const t of ["IOC", "OBSERVABLE"]) {
    try { const x = db.prepare(`SELECT RawJson FROM ${t} WHERE StixID=? AND RawJson IS NOT NULL LIMIT 1`).get(stixId) as { RawJson: string } | undefined; if (x?.RawJson) return JSON.parse(x.RawJson); } catch { /* */ }
  }
  return null;
}

/** Build a safe FTS5 MATCH expression from free-text. IOC-like input (IP/domain/hash/url) → phrase match. */
function ftsQuery(q: string): string {
  const s = String(q ?? "").replace(/"/g, " ").trim();
  if (!s) return "";
  if (/[^\w\s]/.test(s)) { const phrase = s.replace(/[^\w.\-:@/ ]/g, " ").replace(/\s+/g, " ").trim(); return phrase ? `"${phrase}"` : ""; }
  return s.split(/\s+/).filter((t) => t.length >= 2).slice(0, 8).map((t) => `${t}*`).join(" ");
}

/** Full-text search across stored STIX objects (IOC values + any nested field). */
export function searchStix(q: string, opts: { limit?: number } = {}): { stixId: string; type: string; name: string; snippet: string }[] {
  const match = ftsQuery(q); if (!match) return [];
  const lim = Math.min(200, Math.max(1, opts.limit || 50));
  try {
    return (getDb("XTHREAT").prepare(
      `SELECT stixId, stixType, name, snippet(STIXOBJECT_FTS, 4, '[', ']', '…', 12) AS snip
       FROM STIXOBJECT_FTS WHERE STIXOBJECT_FTS MATCH ? ORDER BY bm25(STIXOBJECT_FTS) LIMIT ?`
    ).all(match, lim) as any[]).map((r) => ({ stixId: String(r.stixId), type: String(r.stixType || ""), name: String(r.name || ""), snippet: String(r.snip || "") }));
  } catch { return []; }
}

// ── row → STIX builders (one place to map a CTI row to its STIX object) ──────────────
function observableRowToStix(r: any): any {
  const id = String(r.StixID ?? "").trim() || `x-observable--${r.ObservableGUID || r.ObservableID}`;
  return { type: scoType(r.ObservableType), id, spec_version: "2.1", value: r.Value ?? undefined, x_observable_type: r.ObservableType ?? undefined, description: r.Description || undefined, labels: splitList(r.Labels), x_opencti_score: r.Score ?? undefined, external_references_raw: r.ExternalReferences || undefined, created: r.CreatedDate || undefined };
}
function iocRowToStix(r: any): any {
  const id = String(r.StixID ?? "").trim() || `indicator--${r.IOCGUID || r.IOCID}`;
  return { type: "indicator", id, spec_version: String(r.SpecVersion || "2.1"), name: r.IOCName || undefined, description: r.IOCDescription || undefined, pattern: r.Pattern || undefined, pattern_type: r.PatternType || undefined, indicator_types: splitList(r.IndicatorTypes), labels: splitList(r.Labels), valid_from: r.ValidFrom || undefined, created: r.CreatedDate || undefined, confidence: r.Confidence ?? undefined };
}
function intelRowToStix(r: any): any {
  const id = r.IntelGUID ? `report--${r.IntelGUID}` : `x-intel--${r.IntelID}`;
  const obj: any = { type: "report", id, spec_version: "2.1", name: r.IntelName || undefined, description: r.IntelDescription || undefined, external_references_raw: r.IntelReference || undefined, x_intel_source: r.IntelSource || undefined, x_attack_tags: splitList(r.AttackTags), x_actor_tags: splitList(r.ActorTags), x_malware_tags: splitList(r.MalwareTags), x_cve_tags: splitList(r.CveTags), labels: splitList(r.IntelTags), published: r.IntelDate || r.CreatedDate || undefined };
  // INTELEXCHANGE.RawJson is the connector's original normalized item — retain it losslessly
  if (r.RawJson) { try { obj.x_original_payload = JSON.parse(r.RawJson); } catch { /* not JSON */ } }
  return obj;
}

/** Sync a single OBSERVABLE / IOC row (by id) into the store — the live hook for in-process writers
 *  (e.g. the malware scanner). */
export function syncObservableById(id: number): boolean {
  try { const r = getDb("XTHREAT").prepare("SELECT * FROM OBSERVABLE WHERE ObservableID = ?").get(id) as any; if (!r) return false; return !!storeStixObject(observableRowToStix(r), { source: "live", tenant: r.TenantID ?? null, mirror: { table: "OBSERVABLE", pkCol: "ObservableID", pkVal: id } }); } catch { return false; }
}
export function syncIocById(id: number): boolean {
  try { const r = getDb("XTHREAT").prepare("SELECT * FROM IOC WHERE IOCID = ?").get(id) as any; if (!r) return false; return !!storeStixObject(iocRowToStix(r), { source: "live", tenant: r.TenantID ?? null, mirror: { table: "IOC", pkCol: "IOCID", pkVal: id } }); } catch { return false; }
}

/** Reconcile the CTI tables (OBSERVABLE / IOC / INTELEXCHANGE) into the STIX store. `incremental`
 *  (default) only stores rows whose StixID is not yet in STIXOBJECT — catches connector/form writes
 *  cheaply; `incremental:false` rebuilds (refreshes) every row. Idempotent. */
export function syncStixStore(opts: { cap?: number; incremental?: boolean } = {}): { observables: number; iocs: number; intel: number; skipped: number } {
  const db = getDb("XTHREAT"); const cap = Math.max(1, opts.cap ?? 20000); const inc = opts.incremental !== false;
  let observables = 0, iocs = 0, intel = 0, skipped = 0;
  const seen = db.prepare("SELECT 1 FROM STIXOBJECT WHERE StixID = ?");
  // pkCol set → mirror RawJson onto that source row by PK; null (INTELEXCHANGE) → leave its RawJson
  // alone (the connector/runner owns it, it's the original normalized item).
  const run = (table: string, build: (r: any) => any, pkCol: string | null, bump: () => void): void => {
    if (!tableExists(table)) return;
    for (const r of db.prepare(`SELECT * FROM ${table} LIMIT ?`).all(cap) as any[]) {
      const obj = build(r);
      if (inc && seen.get(obj.id)) { skipped++; continue; }
      const mirror = pkCol ? { table, pkCol, pkVal: r[pkCol] } : undefined;
      if (storeStixObject(obj, { source: "sync", tenant: r.TenantID ?? null, mirror })) bump();
    }
  };
  db.transaction(() => {
    run("OBSERVABLE", observableRowToStix, "ObservableID", () => { observables++; });
    run("IOC", iocRowToStix, "IOCID", () => { iocs++; });
    run("INTELEXCHANGE", intelRowToStix, null, () => { intel++; });
  })();
  return { observables, iocs, intel, skipped };
}

/** Stats for the store (counts by source/type). */
export function stixStoreStats(): { total: number; bySource: Record<string, number>; ftsAvailable: boolean } {
  const db = getDb("XTHREAT");
  let total = 0; const bySource: Record<string, number> = {};
  try {
    total = (db.prepare("SELECT COUNT(*) n FROM STIXOBJECT").get() as { n: number }).n;
    for (const r of db.prepare("SELECT COALESCE(Source,'?') s, COUNT(*) n FROM STIXOBJECT GROUP BY Source").all() as any[]) bySource[String(r.s)] = Number(r.n);
  } catch { /* */ }
  let fts = false; try { db.prepare("SELECT 1 FROM STIXOBJECT_FTS LIMIT 1").get(); fts = true; } catch { /* */ }
  return { total, bySource, ftsAvailable: fts };
}

let syncTimer: NodeJS.Timeout | null = null;
/** Reconcile the STIX store at boot then every 10 min — picks up rows written out-of-process (CTI
 *  connectors / the Python runner) and via the explorer forms. Set XOR_STIX_SYNC=0 to disable. */
export function startStixStoreSync(): void {
  if (syncTimer || process.env.XOR_STIX_SYNC === "0") return;
  const tick = (): void => {
    try { const r = syncStixStore({ incremental: true }); if (r.observables + r.iocs + r.intel) console.log(`[stix] synced ${r.observables} obs + ${r.iocs} ioc + ${r.intel} intel into STIXOBJECT (skipped ${r.skipped})`); }
    catch (e) { console.warn(`[stix] sync: ${(e as Error).message}`); }
  };
  tick(); // boot reconciliation
  syncTimer = setInterval(tick, 10 * 60 * 1000);
  if (typeof syncTimer.unref === "function") syncTimer.unref();
  console.log("[stix] store sync started (boot + every 10 min; XOR_STIX_SYNC=0 to disable)");
}
