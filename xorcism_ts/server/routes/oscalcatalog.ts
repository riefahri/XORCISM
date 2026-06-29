/**
 * oscalcatalog.ts (routes) — import / list OSCAL catalogs & profiles for control-id resolution.
 * RBAC: XCOMPLIANCE.AUDIT (write to import, read to list). Used by the audit-package OSCAL export.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { importOscalCatalog, listOscalCatalogs } from "../oscalcatalog";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

// POST /api/oscal/catalog — body is an OSCAL catalog or profile JSON document
router.post("/oscal/catalog", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(importOscalCatalog(req.body, tenantOf(req))); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// GET /api/oscal/catalogs — imported catalogs with control counts
router.get("/oscal/catalogs", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(listOscalCatalogs(tenantOf(req))); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
