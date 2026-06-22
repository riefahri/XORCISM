/** devsecops.ts (routes) — DevSecOps operations cockpit. RBAC on XORCISM.APPLICATION (the SDLC apps);
 *  GET dashboard + register app / record pipeline scan / set security gate. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { devsecopsDashboard, createApp, recordScan, setGate, appAsvs, setAsvsLevel, setAsvsStatus } from "../devsecops";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XORCISM", "APPLICATION");
const wr = (req: Request) => userCan(req.user, "update", "XORCISM", "APPLICATION");

router.get("/devsecops", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(devsecopsDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/devsecops/app", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  const out = createApp({ name: String(b.name), repo: b.repo ? String(b.repo) : undefined, language: b.language ? String(b.language) : undefined, team: b.team ? String(b.team) : undefined, criticality: b.criticality ? String(b.criticality) : undefined, pipelineUrl: b.pipelineUrl ? String(b.pipelineUrl) : undefined, defaultBranch: b.defaultBranch ? String(b.defaultBranch) : undefined, ownerPersonId: b.ownerPersonId != null ? Number(b.ownerPersonId) : undefined }, ten(req));
  res.json({ ok: true, ...out });
});

router.post("/devsecops/scan", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (b.appId == null || !String(b.scanType ?? "").trim()) return void res.status(400).json({ error: "appId and scanType required" });
  const out = recordScan({ appId: Number(b.appId), scanType: String(b.scanType), tool: b.tool ? String(b.tool) : undefined, critical: Number(b.critical) || 0, high: Number(b.high) || 0, medium: Number(b.medium) || 0, low: Number(b.low) || 0, branch: b.branch ? String(b.branch) : undefined, url: b.url ? String(b.url) : undefined }, ten(req));
  xid.addAudit({ userId: req.user.UserID ?? null, action: "devsecops_scan", resourceType: "DEVSECOPSSCAN", resourceKey: String(out.id), detail: `${b.scanType} gate=${out.gatePassed}`, ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.post("/devsecops/gate", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.scanType ?? "").trim() || !String(b.maxSeverity ?? "").trim()) return void res.status(400).json({ error: "scanType and maxSeverity required" });
  setGate({ appId: b.appId != null ? Number(b.appId) : null, scanType: String(b.scanType), maxSeverity: String(b.maxSeverity), blockOnFail: b.blockOnFail !== false, enabled: b.enabled !== false }, ten(req));
  res.json({ ok: true });
});

// GET /api/devsecops/asvs/:appId — per-app OWASP ASVS verification (requirements ≤ target level + status)
router.get("/devsecops/asvs/:appId", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const out = appAsvs(Number(req.params.appId), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json(out);
});

router.post("/devsecops/asvs/:appId/level", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const lvl = Number((req.body || {}).level);
  if (!(lvl >= 0 && lvl <= 3)) return void res.status(400).json({ error: "level 0-3 required" });
  if (!setAsvsLevel(Number(req.params.appId), lvl, ten(req))) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.post("/devsecops/asvs/:appId/status", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.shortcode ?? "").trim() || !String(b.status ?? "").trim()) return void res.status(400).json({ error: "shortcode and status required" });
  setAsvsStatus(Number(req.params.appId), String(b.shortcode), String(b.status), ten(req));
  res.json({ ok: true });
});

export default router;
