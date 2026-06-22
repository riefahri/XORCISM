/** blob.ts (routes) — content-addressed blob store: upload, retrieve (by sha256), stats, and the
 *  in-row-BLOB → CAS migration. Files live in the content-addressed store (see blobstore.ts). */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { getBlobMeta, readBlob, blobStoreStats, putBlob, migrateInRowBlobs, gcBlobs } from "../blobstore";
import * as xid from "../xid";

const router = Router();
const rd = (req: Request) => userCan(req.user, "read", "XORCISM", "DOCUMENT");
const wr = (req: Request) => userCan(req.user, "update", "XORCISM", "DOCUMENT");
const MAX_BYTES = 15 * 1024 * 1024;

router.get("/blob/stats", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  res.json(blobStoreStats());
});

// POST /api/blob — upload a large file (PCAP / sample / bundle) into the CAS. Body (reuses express.json,
// no multipart dep): { filename?, contentType?, dataBase64 }. Returns the sha256 hash pointer.
router.post("/blob", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const data = String(b.dataBase64 ?? "");
  if (!data) return void res.status(400).json({ error: "dataBase64 required" });
  let buf: Buffer; try { buf = Buffer.from(data, "base64"); } catch { return void res.status(400).json({ error: "invalid base64" }); }
  if (!buf.length) return void res.status(400).json({ error: "empty" });
  if (buf.length > MAX_BYTES) return void res.status(413).json({ error: `too large (max ${MAX_BYTES} bytes)` });
  const out = putBlob(buf, { name: b.filename ? String(b.filename) : undefined, contentType: b.contentType ? String(b.contentType) : undefined, pin: true });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "blob_put", resourceType: "FILEBLOB", resourceKey: out.sha256, ip: clientIp(req) });
  res.json({ ok: true, sha256: out.sha256, size: out.size, dedup: out.dedup });
});

// POST /api/blob/migrate — offload existing in-row BLOBs (OVAL definitions, DOCUMENT files) to the CAS.
// Superadmin only (global maintenance). { reclaim?: bool } nulls the BLOB after a verified read-back.
router.post("/blob/migrate", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!req.user.isSuperAdmin) return void res.status(403).json({ error: "superadmin only" });
  const b = (req.body || {}) as Record<string, unknown>;
  const results = migrateInRowBlobs({ reclaim: !!b.reclaim, cap: b.cap != null ? Number(b.cap) : undefined });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "blob_migrate", resourceType: "FILEBLOB", resourceKey: b.reclaim ? "reclaim" : "copy", ip: clientIp(req) });
  res.json({ ok: true, reclaim: !!b.reclaim, results });
});

// POST /api/blob/gc — reclaim blobs nothing references (mark-and-sweep). Superadmin only.
// dryRun defaults to true (report only); send { dryRun: false } to actually delete. graceHours protects fresh blobs.
router.post("/blob/gc", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!req.user.isSuperAdmin) return void res.status(403).json({ error: "superadmin only" });
  const b = (req.body || {}) as Record<string, unknown>;
  const out = gcBlobs({ dryRun: b.dryRun !== false, graceHours: b.graceHours != null ? Number(b.graceHours) : undefined });
  if (!out.dryRun) xid.addAudit({ userId: req.user.UserID ?? null, action: "blob_gc", resourceType: "FILEBLOB", resourceKey: String(out.deleted), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.get("/blob/:sha256", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const meta = getBlobMeta(String(req.params.sha256));
  if (!meta) return void res.status(404).json({ error: "not found" });
  const buf = readBlob(meta.sha256);
  if (!buf) return void res.status(410).json({ error: "registry present but file missing" });
  res.setHeader("Content-Type", meta.contentType || "application/octet-stream");
  res.setHeader("Content-Length", String(buf.length));
  res.setHeader("ETag", `"${meta.sha256}"`);
  if (meta.name) res.setHeader("Content-Disposition", `inline; filename="${meta.name.replace(/[^\w.\-]/g, "_")}"`);
  res.send(buf);
});

export default router;
