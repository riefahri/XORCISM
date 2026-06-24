/**
 * crisis.ts (routes) — Crisis management & tabletop-exercise readiness.
 * Read-only inventory guarded by read on XCOMPLIANCE.AUDIT; the launch action needs create.
 * CRUD stays in the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import {
  crisisInventory, launchExercise, exerciseDetail, startExercise, endExercise,
  deliverInject, logExerciseEvent, addExerciseParticipant, addExerciseInject,
} from "../crisis";
import * as xid from "../xid";

const router = Router();

const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const who = (req: Request): string => String(req.user!.Email ?? req.user!.UserID ?? "");
function needUpdate(req: Request, res: Response): boolean {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, "update", "XCOMPLIANCE", "AUDIT")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
}

// GET /api/crisis-management — tabletop-exercise inventory + scenario library + worklist
router.get("/crisis-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(crisisInventory(tenant));
});

// POST /api/crisis-management/launch { scenarioId, name?, date? } — schedule a tabletop exercise
// from a scenario template: create the AUDIT (AuditType='Tabletop Exercise') + copy its injects.
router.post("/crisis-management/launch", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { scenarioId?: unknown; name?: unknown; date?: unknown };
  const scenarioId = Number(b.scenarioId) || 0;
  if (!scenarioId) return void res.status(400).json({ error: "scenarioId required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = launchExercise(scenarioId, {
      name: b.name ? String(b.name) : undefined,
      date: b.date ? String(b.date) : undefined,
      tenant,
    });
    xid.addAudit({
      userId: req.user.UserID ?? null, action: "crisis_launch_exercise", resourceType: "audit",
      resourceKey: String(out.auditId), detail: `scenario=${scenarioId} (${out.scenario}) injects=${out.injects}`, ip: clientIp(req),
    });
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(400).json({ error: String((e as Error).message || e) });
  }
});

// ── Exercise runtime (OpenAEV-style): play the scenario, deliver injects, log reactions ──

// GET /api/crisis-management/exercise/:id — full runtime (timeline injects + participants + reaction log)
router.get("/crisis-management/exercise/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const out = exerciseDetail(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "exercise not found" });
  res.json(out);
});

// POST /api/crisis-management/exercise/:id/start | /end — control the running clock
router.post("/crisis-management/exercise/:id/start", (req: Request, res: Response) => {
  if (!needUpdate(req, res)) return;
  try {
    const out = startExercise(Number(req.params.id), ten(req), who(req));
    xid.addAudit({ userId: req.user!.UserID ?? null, action: "crisis_exercise_start", resourceType: "audit", resourceKey: String(req.params.id), ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});
router.post("/crisis-management/exercise/:id/end", (req: Request, res: Response) => {
  if (!needUpdate(req, res)) return;
  try {
    const out = endExercise(Number(req.params.id), ten(req), who(req));
    xid.addAudit({ userId: req.user!.UserID ?? null, action: "crisis_exercise_end", resourceType: "audit", resourceKey: String(req.params.id), ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/crisis-management/inject/:id/deliver — "send" an inject (email/SMS/… → timeline)
router.post("/crisis-management/inject/:id/deliver", (req: Request, res: Response) => {
  if (!needUpdate(req, res)) return;
  try { res.json(deliverInject(Number(req.params.id), ten(req), who(req))); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/crisis-management/exercise/:id/inject — add an ad-hoc inject to a running exercise
router.post("/crisis-management/exercise/:id/inject", (req: Request, res: Response) => {
  if (!needUpdate(req, res)) return;
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.title ?? "").trim()) return void res.status(400).json({ error: "title required" });
  try {
    res.json({ ok: true, ...addExerciseInject(Number(req.params.id), {
      title: String(b.title), channel: b.channel ? String(b.channel) : undefined, offsetMinutes: b.offsetMinutes != null && b.offsetMinutes !== "" ? Number(b.offsetMinutes) : null,
      sender: b.sender ? String(b.sender) : undefined, recipients: b.recipients ? String(b.recipients) : undefined, subject: b.subject ? String(b.subject) : undefined,
      description: b.description ? String(b.description) : undefined, injectType: b.injectType ? String(b.injectType) : undefined, expectedAction: b.expectedAction ? String(b.expectedAction) : undefined,
    }, ten(req)) });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/crisis-management/exercise/:id/participant — add a participant (with contact details)
router.post("/crisis-management/exercise/:id/participant", (req: Request, res: Response) => {
  if (!needUpdate(req, res)) return;
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try {
    res.json({ ok: true, ...addExerciseParticipant(Number(req.params.id), {
      personId: b.personId != null && b.personId !== "" ? Number(b.personId) : null, name: String(b.name), role: b.role ? String(b.role) : undefined,
      team: b.team ? String(b.team) : undefined, email: b.email ? String(b.email) : undefined, phone: b.phone ? String(b.phone) : undefined, attended: b.attended === true || b.attended === "true",
    }, ten(req)) });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/crisis-management/exercise/:id/log — record a timestamped reaction / decision / note
router.post("/crisis-management/exercise/:id/log", (req: Request, res: Response) => {
  if (!needUpdate(req, res)) return;
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.message ?? "").trim()) return void res.status(400).json({ error: "message required" });
  try {
    res.json({ ok: true, ...logExerciseEvent(Number(req.params.id), {
      injectId: b.injectId != null && b.injectId !== "" ? Number(b.injectId) : null, participantId: b.participantId != null && b.participantId !== "" ? Number(b.participantId) : null,
      eventType: b.eventType ? String(b.eventType) : "note", message: String(b.message), channel: b.channel ? String(b.channel) : undefined,
    }, ten(req), who(req)) });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
