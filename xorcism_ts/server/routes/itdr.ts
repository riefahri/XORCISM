/** itdr.ts (routes) — Identity Threat Detection & Response cockpit. RBAC anchored on XORCISM.IDENTITY
 * (the identity resource). Detections are computed live from IDENTITYSIGNIN telemetry + IDENTITY
 * posture; analysts triage them (status workflow) and can raise an incident from a detection. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { runItdrDetectors, itdrDashboard, setDetectionStatus, raiseIncidentFromDetection } from "../itdr";
import { itdrInvestigate } from "../aiassist";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete") => userCan(req.user, act, "XORCISM", "IDENTITY");

// GET /api/itdr — run the detectors, then return the cockpit dashboard.
router.get("/itdr", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  try {
    try { runItdrDetectors(ten(req)); } catch { /* detection best-effort; still return what we have */ }
    res.json(itdrDashboard(ten(req)));
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/itdr/scan — explicit re-scan (update detection (worklist).
router.post("/itdr/scan", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  try {
    const r = runItdrDetectors(ten(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "itdr_scan", resourceType: "IDENTITYDETECTION", detail: `created=${r.created} updated=${r.updated}`, ip: clientIp(req) });
    res.json({ ok: true, ...r });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/itdr/detection/:id/status { status, notes? }
router.post("/itdr/detection/:id/status", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { status?: string; notes?: string };
  const ok = setDetectionStatus(Number(req.params.id), String(b.status || ""), ten(req), req.user.Email ?? String(req.user.UserID ?? ""), b.notes);
  if (!ok) return void res.status(400).json({ error: "invalid status or detection not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "itdr_status", resourceType: "IDENTITYDETECTION", resourceKey: String(req.params.id), detail: b.status, ip: clientIp(req) });
  res.json({ ok: true });
});

// POST /api/itdr/detection/:id/investigate — local-AI investigation brief for the detection.
router.post("/itdr/detection/:id/investigate", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  try {
    const out = await itdrInvestigate({ detectionId: Number(req.params.id), tenant: ten(req) });
    res.json(out);
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/itdr/detection/:id/incident — raise an XINCIDENT.ALERT from the detection.
router.post("/itdr/detection/:id/incident", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "create")) return void res.status(403).json({ error: "forbidden" });
  const out = raiseIncidentFromDetection(Number(req.params.id), ten(req), req.user.Email ?? String(req.user.UserID ?? ""));
  if (!out.ok) return void res.status(400).json({ error: out.error || "failed" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "itdr_raise_incident", resourceType: "ALERT", resourceKey: String(out.alertId ?? ""), detail: `from detection ${req.params.id}`, ip: clientIp(req) });
  res.json({ ok: true, alertId: out.alertId });
});

export default router;
