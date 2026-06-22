/** stixstore.ts (routes) — lossless STIX retention + full-text search.
 *  RBAC: read XTHREAT.OBSERVABLE to query; update XTHREAT.OBSERVABLE to ingest / backfill. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { getStixObject, searchStix, storeBundle, syncStixStore, stixStoreStats } from "../stixstore";
import { putBlob } from "../blobstore";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XTHREAT", "OBSERVABLE");
const wr = (req: Request) => userCan(req.user, "update", "XTHREAT", "OBSERVABLE");

// GET /api/stix/object/:stixId — the original STIX object (lossless)
router.get("/stix/object/:stixId", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const obj = getStixObject(String(req.params.stixId));
  if (!obj) return void res.status(404).json({ error: "not found", stixId: req.params.stixId });
  res.json(obj);
});

// GET /api/stix/search?q=&limit= — full-text search over stored STIX objects / IOC values
router.get("/stix/search", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const q = String(req.query.q ?? "").trim();
  if (!q) return void res.status(400).json({ error: "q required" });
  try { res.json({ q, results: searchStix(q, { limit: req.query.limit ? Number(req.query.limit) : 50 }) }); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/stix/stats — store size by source + FTS availability
router.get("/stix/stats", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  res.json(stixStoreStats());
});

// POST /api/stix/ingest — store a STIX bundle / object losslessly (body = STIX JSON). The raw bundle is
// also offloaded to the content-addressed blob store (object storage by hash) so the original large file
// is retained out-of-row; the returned bundleSha256 is the pointer (retrieve via GET /api/blob/:sha256).
router.post("/stix/ingest", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const body = req.body;
  if (!body || typeof body !== "object") return void res.status(400).json({ error: "STIX object or bundle required in body" });
  try {
    const out = storeBundle(body, { source: "ingest", tenant: ten(req) });
    let bundle: { sha256: string; size: number; dedup: boolean } | undefined;
    try { const raw = Buffer.from(JSON.stringify(body)); const b = putBlob(raw, { name: "stix-bundle.json", contentType: "application/json", pin: true }); bundle = { sha256: b.sha256, size: b.size, dedup: b.dedup }; } catch { /* CAS best-effort */ }
    xid.addAudit({ userId: req.user.UserID ?? null, action: "stix_ingest", resourceType: "STIXOBJECT", resourceKey: String(out.stored), ip: clientIp(req) });
    res.json({ ok: true, ...out, bundle });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/stix/backfill — (re)build STIXOBJECT from existing OBSERVABLE / IOC / INTELEXCHANGE rows
router.post("/stix/backfill", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  try {
    const out = syncStixStore({ incremental: false, cap: req.body && req.body.cap ? Number(req.body.cap) : 20000 });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "stix_backfill", resourceType: "STIXOBJECT", resourceKey: String(out.observables + out.iocs + out.intel), ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
