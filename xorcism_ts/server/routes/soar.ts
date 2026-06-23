/** soar.ts (routes) — SOAR cockpit: orchestration playbooks + action catalogue + run engine.
 *  RBAC on XINCIDENT.INCIDENT (response domain). Runs default to simulate (dry-run, no side effects). */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { soarDashboard, createSoarPlaybook, setSoarPlaybookEnabled, deleteSoarPlaybook, runSoarPlaybook, soarRunDetail } from "../soar";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const canRead = (req: Request) => userCan(req.user, "read", "XINCIDENT", "INCIDENT");
const canWrite = (req: Request) => userCan(req.user, "update", "XINCIDENT", "INCIDENT");

router.get("/soar", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(soarDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/soar/playbook", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  const actions = Array.isArray(b.actions) ? (b.actions as Record<string, unknown>[]).map((a) => ({ actionType: String(a.actionType ?? ""), name: a.name ? String(a.name) : undefined, params: a.params ? String(a.params) : undefined, onFailure: a.onFailure ? String(a.onFailure) : undefined })) : [];
  try {
    const out = createSoarPlaybook({ name, description: b.description ? String(b.description) : undefined, triggerType: b.triggerType ? String(b.triggerType) : undefined, category: b.category ? String(b.category) : undefined, actions }, ten(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "soar_create_playbook", resourceType: "SOARPLAYBOOK", resourceKey: String(out.id), detail: name, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.post("/soar/playbook/:id/enabled", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const ok = setSoarPlaybookEnabled(Number(req.params.id), !!(req.body || {}).enabled, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.delete("/soar/playbook/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  const ok = deleteSoarPlaybook(id, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "soar_delete_playbook", resourceType: "SOARPLAYBOOK", resourceKey: String(id), ip: clientIp(req) });
  res.json({ ok: true });
});

router.post("/soar/playbook/:id/run", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const mode = String((req.body || {}).mode ?? "simulate");
  const out = runSoarPlaybook(Number(req.params.id), ten(req), { mode });
  if (!out) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "soar_run_playbook", resourceType: "SOARPLAYBOOK", resourceKey: String(req.params.id), detail: `${mode} → ${out.status}`, ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.get("/soar/run/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  const out = soarRunDetail(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json(out);
});

export default router;
