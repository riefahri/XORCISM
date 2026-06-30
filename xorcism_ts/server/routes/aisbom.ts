/**
 * aisbom.ts (routes) — AI SBOM minimum-elements conformance (CISA / G7).
 * List/create AI-SBOM instances, edit per-element coverage, roll up completeness.
 * RBAC on XCOMPLIANCE.AUDIT (it's a compliance/transparency conformance assessment).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { listAiSboms, aiSbomDetail, createAiSbom, setCoverage, deleteAiSbom, seedAiSbom } from "../aisbom";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const canRead = (req: Request) => userCan(req.user, "read", "XCOMPLIANCE", "AUDIT");
const canWrite = (req: Request) => userCan(req.user, "create", "XCOMPLIANCE", "AUDIT");

// GET /api/ai-sbom — list AI-SBOM instances (+ completeness). ?id=N → full detail of one.
router.get("/ai-sbom", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  const id = req.query.id != null ? Number(req.query.id) : null;
  if (id != null && Number.isFinite(id)) {
    const d = aiSbomDetail(id, ten(req));
    if (!d) return void res.status(404).json({ error: "not found" });
    return void res.json(d);
  }
  res.json(listAiSboms(ten(req)));
});

router.get("/ai-sbom/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  const d = aiSbomDetail(Number(req.params.id), ten(req));
  if (!d) return void res.status(404).json({ error: "not found" });
  res.json(d);
});

// POST /api/ai-sbom — create an AI-SBOM instance for an AI system
router.post("/ai-sbom", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.name || !String(b.name).trim()) return void res.status(400).json({ error: "name required" });
  const out = createAiSbom({ name: String(b.name), producer: b.producer ? String(b.producer) : undefined, version: b.version ? String(b.version) : undefined, format: b.format ? String(b.format) : undefined, notes: b.notes ? String(b.notes) : undefined }, ten(req));
  xid.addAudit({ userId: req.user.UserID ?? null, action: "ai_sbom_create", resourceType: "AISBOM", resourceKey: String(out.id), detail: String(b.name), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

// POST /api/ai-sbom/:id/coverage — set coverage for one element {elementId, status, value, notes}
router.post("/ai-sbom/:id/coverage", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const elementId = Number(b.elementId);
  if (!Number.isFinite(elementId)) return void res.status(400).json({ error: "elementId required" });
  const ok = setCoverage(Number(req.params.id), elementId, { status: b.status != null ? String(b.status) : undefined, value: b.value != null ? String(b.value) : undefined, notes: b.notes != null ? String(b.notes) : undefined }, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.delete("/ai-sbom/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const ok = deleteAiSbom(Number(req.params.id), ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "ai_sbom_delete", resourceType: "AISBOM", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

// POST /api/ai-sbom/seed — seed a demo AI-SBOM for the tenant (idempotent)
router.post("/ai-sbom/seed", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? 1 : (req.user.tenantId ?? 1);
  res.json({ ok: true, ...seedAiSbom(tenant) });
});

export default router;
