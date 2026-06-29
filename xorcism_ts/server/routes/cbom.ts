/**
 * cbom.ts (routes) — Cryptographic Bill of Materials inventory + import.
 * RBAC on XORCISM.ASSET (CBOM is an asset crypto-inventory). Feeds PQCMM quantum readiness.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { cbomInventory, importCbom, seedCbom } from "../cbom";
import * as xid from "../xid";

const router = Router();

// GET /api/cbom — the cryptographic-asset inventory + quantum-readiness rollup + worklist
router.get("/cbom", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(cbomInventory(tenant));
});

// POST /api/cbom/import — import a CycloneDX 1.6 CBOM (or {cryptoAssets:[]} / array). Body: {cbom, assetId?}
router.post("/cbom/import", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const cbom = b.cbom ?? b.bom ?? b;
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = importCbom(cbom, { tenant, assetId: b.assetId != null ? Number(b.assetId) : null, source: b.source ? String(b.source) : "CBOM import" });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "cbom_import", resourceType: "CRYPTOASSET", resourceKey: "import", detail: `imported=${out.imported} quantum-vulnerable=${out.quantumVulnerable}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/cbom/seed — seed a small demo CBOM for the tenant (idempotent)
router.post("/cbom/seed", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? 1 : (req.user.tenantId ?? 1);
  res.json({ ok: true, ...seedCbom(tenant) });
});

export default router;
