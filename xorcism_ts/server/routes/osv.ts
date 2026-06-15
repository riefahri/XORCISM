/**
 * osv.ts (routes) — OSV.dev integration for XVULNERABILITY.
 *   GET  /api/osv/lookup?id=…  → normalized fields (enriches the form, read)
 *   POST /api/osv/import {id}  → imports/updates a VULNERABILITY (write)
 * Mounted AFTER the auth gate; guarded by the rights on XVULNERABILITY.VULNERABILITY.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import * as xid from "../xid";
import { lookupOsv, importOsv, isValidOsvId } from "../osv";

const router = Router();
const DB = "XVULNERABILITY";
const TABLE = "VULNERABILITY";

// GET /api/osv/lookup?id=CVE-… — fetches the OSV fields (no writing)
router.get("/osv/lookup", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", DB, TABLE)) return void res.status(403).json({ error: "forbidden" });
  const id = String(req.query.id || "").trim();
  if (!id) return void res.status(400).json({ error: "id requis" });
  if (!isValidOsvId(id)) return void res.status(400).json({ error: "Identifiant OSV invalide" });
  try {
    res.json(await lookupOsv(id));
  } catch (e) {
    res.status(502).json({ error: (e as Error).message });
  }
});

// POST /api/osv/import { id } — imports or updates the VULNERABILITY
router.post("/osv/import", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", DB, TABLE)) return void res.status(403).json({ error: "forbidden" });
  const id = String((req.body as { id?: string })?.id || "").trim();
  if (!id) return void res.status(400).json({ error: "id requis" });
  if (!isValidOsvId(id)) return void res.status(400).json({ error: "Identifiant OSV invalide" });
  try {
    const r = await importOsv(id);
    xid.addAudit({ userId: req.user.UserID, action: "osv-import", detail: `${r.action} ${r.referential}`, ip: clientIp(req) });
    res.json(r);
  } catch (e) {
    res.status(502).json({ error: (e as Error).message });
  }
});

export default router;
