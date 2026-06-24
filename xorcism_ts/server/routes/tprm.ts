/** tprm.ts (routes) — Third-Party Risk Management cockpit. RBAC anchored on the existing
 * XCOMPLIANCE.QUESTIONNAIREFORORGANISATION TPRM resource. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import {
  tprmDashboard, getVendor, createVendor, updateVendor, deleteVendor,
  linkRun, assessPosture, addFinding, updateFinding,
} from "../tprm";
import * as xid from "../xid";

const router = Router();
const RES = "QUESTIONNAIREFORORGANISATION";
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete") => userCan(req.user, act, "XCOMPLIANCE", RES);

router.get("/tprm", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(tprmDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/tprm/vendor/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  const out = getVendor(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json(out);
});

router.post("/tprm/vendor", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "create")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try {
    const out = createVendor(b, ten(req), req.user.Email ?? String(req.user.UserID ?? ""));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "tprm_vendor_create", resourceType: "TPRMVENDOR", resourceKey: String(out.id), detail: String(b.name), ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.post("/tprm/vendor/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  const ok = updateVendor(Number(req.params.id), (req.body || {}) as Record<string, unknown>, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.delete("/tprm/vendor/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "delete")) return void res.status(403).json({ error: "forbidden" });
  const ok = deleteVendor(Number(req.params.id), ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "tprm_vendor_delete", resourceType: "TPRMVENDOR", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

router.post("/tprm/vendor/:id/assess", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  try {
    const out = await assessPosture(Number(req.params.id), ten(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "tprm_assess_posture", resourceType: "TPRMVENDOR", resourceKey: String(req.params.id), detail: out.ok ? `grade ${out.grade}` : (out.error || ""), ip: clientIp(req) });
    res.json(out);
  } catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

router.post("/tprm/vendor/:id/link-run", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const runId = b.runId != null && String(b.runId) !== "" ? Number(b.runId) : null;
  const ok = linkRun(Number(req.params.id), runId, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.post("/tprm/vendor/:id/finding", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.title ?? "").trim()) return void res.status(400).json({ error: "title required" });
  const ok = addFinding(Number(req.params.id), {
    source: b.source ? String(b.source) : "manual", category: b.category ? String(b.category) : undefined,
    title: String(b.title), detail: b.detail ? String(b.detail) : undefined, severity: b.severity ? String(b.severity) : undefined,
  }, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.post("/tprm/finding/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = updateFinding(Number(req.params.id), { status: b.status != null ? String(b.status) : undefined, severity: b.severity != null ? String(b.severity) : undefined }, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

export default router;
