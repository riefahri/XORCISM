/** ctem.ts (routes) — CTEM (ctem.org) exposure cockpit. RBAC: read XVULNERABILITY.VULNERABILITY;
 *  write actions (classify / discover / advance / remediate / assign) gate on update. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { ctemDashboard, ctemCatalogue, discoverCtemExposures, createExposure, advanceStage, setExposureStatus, assignExposure } from "../ctem";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XVULNERABILITY", "VULNERABILITY");
const wr = (req: Request) => userCan(req.user, "update", "XVULNERABILITY", "VULNERABILITY");

router.get("/ctem", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(ctemDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/ctem/catalogue", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(ctemCatalogue()); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/ctem/discover", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  try {
    const out = discoverCtemExposures(ten(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "ctem_discover", resourceType: "CTEMEXPOSURE", resourceKey: String(out.created), ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/ctem/exposure", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.ctemId ?? "").trim()) return void res.status(400).json({ error: "ctemId required" });
  const out = createExposure({ ctemId: String(b.ctemId), title: b.title ? String(b.title) : undefined, severity: b.severity ? String(b.severity) : undefined, assetId: b.assetId != null ? Number(b.assetId) : undefined, evidence: b.evidence ? String(b.evidence) : undefined, stage: b.stage ? String(b.stage) : undefined }, ten(req));
  res.json({ ok: true, ...out });
});

router.post("/ctem/exposure/:id/stage", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const out = advanceStage(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true, ...out });
});

router.post("/ctem/exposure/:id/status", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = setExposureStatus(Number(req.params.id), { status: b.status ? String(b.status) : undefined, severity: b.severity ? String(b.severity) : undefined, stage: b.stage ? String(b.stage) : undefined }, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  if (b.status && /remediat/i.test(String(b.status))) xid.addAudit({ userId: req.user.UserID ?? null, action: "ctem_remediate", resourceType: "CTEMEXPOSURE", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

router.post("/ctem/exposure/:id/assign", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = assignExposure(Number(req.params.id), { ownerPersonId: b.ownerPersonId != null ? Number(b.ownerPersonId) : undefined, severity: b.severity ? String(b.severity) : undefined }, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

export default router;
