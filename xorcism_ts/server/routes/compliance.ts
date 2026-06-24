/**
 * compliance.ts (routes) — Compliance / GRC inventory + governance worklist + guided create.
 * Read-only inventory + a guided "new audit" create endpoint; guarded by RBAC on
 * XCOMPLIANCE.AUDIT. Generic CRUD also via the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { complianceInventory, createAudit } from "../compliance";
import { listFindingRemediations, createFindingRemediation, updateFindingRemediation, deleteFindingRemediation } from "../findingremediation";
import * as xid from "../xid";

const router = Router();

const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const who = (req: Request): string => String(req.user!.Email ?? req.user!.UserID ?? "");

// GET /api/compliance-management — audits inventory + open-findings/policy worklist
router.get("/compliance-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(complianceInventory(tenant));
});

// POST /api/compliance-management/audit — guided creation of an AUDIT
router.post("/compliance-management/audit", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = createAudit({
      name,
      type: b.type ? String(b.type) : undefined,
      category: b.category ? String(b.category) : undefined,
      status: b.status ? String(b.status) : undefined,
      auditor: b.auditor ? String(b.auditor) : undefined,
      scope: b.scope ? String(b.scope) : undefined,
      description: b.description ? String(b.description) : undefined,
      date: b.date ? String(b.date) : undefined,
      closureDate: b.closureDate ? String(b.closureDate) : undefined,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "audit_create", resourceType: "AUDIT",
      resourceKey: String(out.id), detail: `name="${name}" type="${String(b.type || "")}"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// ── Remediation plans for audit findings (1 finding → many plans) ──

// GET /api/compliance-management/finding/:id/remediations — the finding + its remediation plans
router.get("/compliance-management/finding/:id/remediations", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDITFINDING")) return void res.status(403).json({ error: "forbidden" });
  const out = listFindingRemediations(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "finding not found" });
  res.json(out);
});

// POST /api/compliance-management/finding/:id/remediation — create a remediation plan
router.post("/compliance-management/finding/:id/remediation", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "AUDITFINDING") && !userCan(req.user, "update", "XCOMPLIANCE", "AUDITFINDING")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try {
    const out = createFindingRemediation(Number(req.params.id), {
      name: String(b.name), description: b.description ? String(b.description) : undefined, type: b.type ? String(b.type) : undefined,
      status: b.status ? String(b.status) : undefined, priority: b.priority ? String(b.priority) : undefined,
      ownerPersonId: b.ownerPersonId != null && b.ownerPersonId !== "" ? Number(b.ownerPersonId) : null, targetDate: b.targetDate ? String(b.targetDate) : undefined,
    }, ten(req), who(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "finding_remediation_create", resourceType: "AUDITFINDING", resourceKey: String(req.params.id), detail: `plan #${out.id} "${String(b.name)}"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/compliance-management/remediation/:id — update a plan (status / progress / fields)
router.post("/compliance-management/remediation/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XCOMPLIANCE", "AUDITFINDING")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  try {
    const out = updateFindingRemediation(Number(req.params.id), {
      name: b.name != null ? String(b.name) : undefined, description: b.description != null ? String(b.description) : undefined, type: b.type != null ? String(b.type) : undefined,
      status: b.status != null ? String(b.status) : undefined, priority: b.priority != null ? String(b.priority) : undefined,
      ownerPersonId: b.ownerPersonId !== undefined ? (b.ownerPersonId != null && b.ownerPersonId !== "" ? Number(b.ownerPersonId) : null) : undefined,
      targetDate: b.targetDate != null ? String(b.targetDate) : undefined, progress: b.progress != null && b.progress !== "" ? Number(b.progress) : undefined,
    }, ten(req));
    if (!out.ok) return void res.status(404).json({ error: "not found" });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// DELETE /api/compliance-management/remediation/:id — remove a plan
router.delete("/compliance-management/remediation/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "delete", "XCOMPLIANCE", "AUDITFINDING")) return void res.status(403).json({ error: "forbidden" });
  const out = deleteFindingRemediation(Number(req.params.id), ten(req));
  if (!out.ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "finding_remediation_delete", resourceType: "AUDITFINDING", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

export default router;
