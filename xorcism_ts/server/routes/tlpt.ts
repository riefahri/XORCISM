/**
 * tlpt.ts (routes) — Threat-Led Penetration Testing (TIBER-EU). Read endpoints + CRUD for the
 * engagement, its 3-phase milestones (sign-off), attack scenarios, flags (Prevent/Detect outcome),
 * findings + remediation, the team roster, plus AI scenario proposals and a Test Summary Report.
 * Guarded by RBAC on XCOMPLIANCE.AUDIT (a regulated assurance test, like crisis/journeys).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import {
  listEngagements, engagement, createEngagement, deleteEngagement, setMilestone,
  addScenario, deleteScenario, addFlag, deleteFlag, setFlagOutcome,
  addFinding, deleteFinding, setFindingStatus, addTeamMember, deleteTeamMember, seedDemo,
} from "../tlpt";
import * as ai from "../ai";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const who = (req: Request): string => String(req.user!.DisplayName || req.user!.Email || req.user!.UserID || "user");
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, act, "XCOMPLIANCE", "AUDIT")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};

// GET /api/tlpt — list TLPT engagements (+ reference vocab)
router.get("/tlpt", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  res.json(listEngagements(tenantOf(req)));
});

// GET /api/tlpt/:id — full engagement (milestones/scenarios/flags/findings/teams/scorecard)
router.get("/tlpt/:id", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  const m = engagement(Number(req.params.id), tenantOf(req));
  if (!m) return void res.status(404).json({ error: "not found" });
  res.json(m);
});

// POST /api/tlpt — create an engagement (seeds the TIBER milestone workflow)
router.post("/tlpt", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.name) return void res.status(400).json({ error: "name required" });
  const tenant = req.user!.isSuperAdmin ? 1 : (req.user!.tenantId ?? 1);
  const out = createEngagement({
    name: String(b.name), entity: b.entity != null ? String(b.entity) : undefined, authority: b.authority != null ? String(b.authority) : undefined,
    scope: b.scope != null ? String(b.scope) : undefined, criticalFunctions: b.criticalFunctions != null ? String(b.criticalFunctions) : undefined,
    tiProvider: b.tiProvider != null ? String(b.tiProvider) : undefined, rtProvider: b.rtProvider != null ? String(b.rtProvider) : undefined,
    whiteTeamLead: b.whiteTeamLead != null ? String(b.whiteTeamLead) : undefined, controlTeamLead: b.controlTeamLead != null ? String(b.controlTeamLead) : undefined,
  }, tenant);
  xid.addAudit({ userId: req.user!.UserID ?? null, action: "tlpt_create", resourceType: "tlpt", resourceKey: String(out.id), detail: String(b.name), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.delete("/tlpt/:id", (req: Request, res: Response) => {
  if (!auth(req, res, "delete")) return;
  if (!deleteEngagement(Number(req.params.id), tenantOf(req))) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

// POST /api/tlpt/milestone/:mid — set a milestone status + sign-off
router.post("/tlpt/milestone/:mid", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = setMilestone(Number(req.params.mid), String(b.status || "pending"), who(req), b.docLink != null ? String(b.docLink) : undefined, tenantOf(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user!.UserID ?? null, action: "tlpt_milestone", resourceType: "tlpt", resourceKey: String(req.params.mid), detail: String(b.status), ip: clientIp(req) });
  res.json({ ok: true });
});

// scenarios
router.post("/tlpt/:id/scenario", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const out = addScenario(Number(req.params.id), req.body || {}, tenantOf(req));
  if (!out) return void res.status(404).json({ error: "engagement not found" });
  res.json({ ok: true, ...out });
});
router.delete("/tlpt/scenario/:sid", (req: Request, res: Response) => {
  if (!auth(req, res, "delete")) return;
  if (!deleteScenario(Number(req.params.sid), tenantOf(req))) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

// flags (+ Prevent/Detect outcome)
router.post("/tlpt/:id/flag", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const out = addFlag(Number(req.params.id), req.body || {}, tenantOf(req));
  if (!out) return void res.status(404).json({ error: "engagement not found" });
  res.json({ ok: true, ...out });
});
router.post("/tlpt/flag/:fid/outcome", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = setFlagOutcome(Number(req.params.fid), {
    reached: b.reached !== undefined ? !!b.reached : undefined, detected: b.detected !== undefined ? !!b.detected : undefined,
    prevented: b.prevented !== undefined ? !!b.prevented : undefined,
    timeToDetectHours: b.timeToDetectHours !== undefined ? (b.timeToDetectHours === "" || b.timeToDetectHours == null ? null : Number(b.timeToDetectHours)) : undefined,
  }, tenantOf(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});
router.delete("/tlpt/flag/:fid", (req: Request, res: Response) => {
  if (!auth(req, res, "delete")) return;
  if (!deleteFlag(Number(req.params.fid), tenantOf(req))) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

// findings
router.post("/tlpt/:id/finding", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const out = addFinding(Number(req.params.id), req.body || {}, tenantOf(req));
  if (!out) return void res.status(404).json({ error: "engagement not found" });
  res.json({ ok: true, ...out });
});
router.post("/tlpt/finding/:fid/status", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  if (!setFindingStatus(Number(req.params.fid), String(b.status || "Open"), tenantOf(req))) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});
router.delete("/tlpt/finding/:fid", (req: Request, res: Response) => {
  if (!auth(req, res, "delete")) return;
  if (!deleteFinding(Number(req.params.fid), tenantOf(req))) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

// team roster
router.post("/tlpt/:id/team", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const out = addTeamMember(Number(req.params.id), req.body || {}, tenantOf(req));
  if (!out) return void res.status(404).json({ error: "engagement not found" });
  res.json({ ok: true, ...out });
});
router.delete("/tlpt/team/:tid", (req: Request, res: Response) => {
  if (!auth(req, res, "delete")) return;
  if (!deleteTeamMember(Number(req.params.tid), tenantOf(req))) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

// AI: propose TTI scenarios / generate Test Summary Report (offline fallback)
router.post("/tlpt/:id/ai/scenarios", async (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  const m = engagement(Number(req.params.id), tenantOf(req));
  if (!m) return void res.status(404).json({ error: "not found" });
  res.json(await ai.tlptProposeScenarios(m));
});
router.post("/tlpt/:id/ai/report", async (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  const m = engagement(Number(req.params.id), tenantOf(req));
  if (!m) return void res.status(404).json({ error: "not found" });
  res.json(await ai.tlptReport(m));
});

// POST /api/tlpt/seed — seed a demo engagement (idempotent)
router.post("/tlpt/seed", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const tenant = req.user!.isSuperAdmin ? 1 : (req.user!.tenantId ?? 1);
  res.json({ ok: true, ...seedDemo(tenant) });
});

export default router;
