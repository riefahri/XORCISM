/**
 * circl.ts (routes) — Search / enrichment / import from CIRCL
 * vulnerability-lookup (KEV catalogs). Mounted AFTER the auth gate;
 * guarded by the rights on XVULNERABILITY.VULNERABILITY.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import * as xid from "../xid";
import { lookupCircl, searchCircl, importCircl } from "../circl";

const router = Router();
const DB = "XVULNERABILITY";
const TABLE = "VULNERABILITY";

// GET /api/circl/search?q=… — CVE id OR vendor/product
router.get("/circl/search", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", DB, TABLE)) return void res.status(403).json({ error: "forbidden" });
  const q = String(req.query.q || "").trim();
  if (!q) return void res.status(400).json({ error: "q requis" });
  try {
    res.json(await searchCircl(q));
  } catch (e) {
    res.status(502).json({ error: (e as Error).message });
  }
});

// GET /api/circl/lookup?id=CVE-… — normalized fields + KEV flag (read)
router.get("/circl/lookup", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", DB, TABLE)) return void res.status(403).json({ error: "forbidden" });
  const id = String(req.query.id || "").trim();
  if (!id) return void res.status(400).json({ error: "id requis" });
  try {
    res.json(await lookupCircl(id));
  } catch (e) {
    res.status(502).json({ error: (e as Error).message });
  }
});

// POST /api/circl/import { id } — imports/updates the VULNERABILITY (with KEV)
router.post("/circl/import", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", DB, TABLE)) return void res.status(403).json({ error: "forbidden" });
  const id = String((req.body as { id?: string })?.id || "").trim();
  if (!id) return void res.status(400).json({ error: "id requis" });
  try {
    const r = await importCircl(id);
    xid.addAudit({ userId: req.user.UserID, action: "circl-import", detail: `${r.action} ${r.referential}${r.kev ? " [KEV]" : ""}`, ip: clientIp(req) });
    res.json(r);
  } catch (e) {
    res.status(502).json({ error: (e as Error).message });
  }
});

export default router;
