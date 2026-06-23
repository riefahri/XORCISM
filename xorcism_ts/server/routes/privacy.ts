/** privacy.ts (routes) — GDPR / DPO cockpit. RBAC on XCOMPLIANCE.AUDIT (compliance domain). */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { privacyDashboard, createProcessing, createDsar, updateDsarStatus, recordBreach } from "../privacy";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const canRead = (req: Request) => userCan(req.user, "read", "XCOMPLIANCE", "AUDIT");
const canWrite = (req: Request) => userCan(req.user, "update", "XCOMPLIANCE", "AUDIT");

router.get("/privacy", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(privacyDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/privacy/processing", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  try {
    const out = createProcessing({ name, purpose: b.purpose ? String(b.purpose) : undefined, legalBasis: b.legalBasis ? String(b.legalBasis) : undefined,
      dataCategories: b.dataCategories ? String(b.dataCategories) : undefined, specialCategories: !!b.specialCategories, dataSubjects: b.dataSubjects ? String(b.dataSubjects) : undefined,
      recipients: b.recipients ? String(b.recipients) : undefined, retention: b.retention ? String(b.retention) : undefined, crossBorder: !!b.crossBorder,
      transferSafeguard: b.transferSafeguard ? String(b.transferSafeguard) : undefined, riskLevel: b.riskLevel ? String(b.riskLevel) : undefined, controller: b.controller ? String(b.controller) : undefined }, ten(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "privacy_create_processing", resourceType: "PRIVACYPROCESSING", resourceKey: String(out.id), detail: name, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.post("/privacy/dsar", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const subjectName = String(b.subjectName ?? "").trim();
  if (!subjectName) return void res.status(400).json({ error: "subjectName required" });
  try {
    const out = createDsar({ subjectName, subjectEmail: b.subjectEmail ? String(b.subjectEmail) : undefined, requestType: b.requestType ? String(b.requestType) : undefined,
      receivedDate: b.receivedDate ? String(b.receivedDate) : undefined, channel: b.channel ? String(b.channel) : undefined, assignedTo: b.assignedTo ? String(b.assignedTo) : undefined, notes: b.notes ? String(b.notes) : undefined }, ten(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "privacy_create_dsar", resourceType: "DSAR", resourceKey: String(out.id), detail: subjectName, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.post("/privacy/dsar/:id/status", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const status = String((req.body || {}).status ?? "").trim();
  if (!status) return void res.status(400).json({ error: "status required" });
  const ok = updateDsarStatus(Number(req.params.id), status, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.post("/privacy/breach", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const title = String(b.title ?? "").trim();
  if (!title) return void res.status(400).json({ error: "title required" });
  try {
    const out = recordBreach({ title, description: b.description ? String(b.description) : undefined, detectedDate: b.detectedDate ? String(b.detectedDate) : undefined,
      affectedSubjects: b.affectedSubjects != null ? Number(b.affectedSubjects) : undefined, dataCategories: b.dataCategories ? String(b.dataCategories) : undefined,
      severity: b.severity ? String(b.severity) : undefined, riskToSubjects: b.riskToSubjects ? String(b.riskToSubjects) : undefined }, ten(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "privacy_record_breach", resourceType: "PRIVACYBREACH", resourceKey: String(out.id), detail: title, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
