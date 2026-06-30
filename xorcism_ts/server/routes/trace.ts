/**
 * trace.ts (routes) — TRACE threat-modeling (Oak Security, CC BY 4.0) layered on THREATMODEL.
 * Read endpoints + CRUD for the 5 model objects, collusion, STRIDE threats, phase-approval gates,
 * coverage scorecard, AI assist (extract / propose-STRIDE / report), and a demo seed.
 * Guarded by RBAC on XORCISM.THREATMODEL.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import {
  listTraceModels, traceModel, createTraceModel, addTraceObject, deleteTraceObject,
  addCollusion, deleteCollusion, addTraceThreat, setThreatTraceLink, advancePhase, seedTraceDemo,
} from "../trace";
import * as ai from "../ai";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

// GET /api/trace — list TRACE models (+ phase/pillar/STRIDE reference)
router.get("/trace", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  res.json(listTraceModels(tenantOf(req)));
});

// GET /api/trace/:id — full TRACE model (objects, threats, attack trees, phases, coverage)
router.get("/trace/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const m = traceModel(Number(req.params.id), tenantOf(req));
  if (!m) return void res.status(404).json({ error: "not found" });
  res.json(m);
});

// POST /api/trace — create a TRACE model (seeds the 6-phase workflow)
router.post("/trace", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.name) return void res.status(400).json({ error: "name required" });
  const tenant = req.user.isSuperAdmin ? 1 : (req.user.tenantId ?? 1);
  const out = createTraceModel({ name: String(b.name), pillar: b.pillar != null ? String(b.pillar) : undefined, description: b.description != null ? String(b.description) : undefined, scope: b.scope != null ? String(b.scope) : undefined }, tenant);
  xid.addAudit({ userId: req.user.UserID ?? null, action: "trace_create", resourceType: "trace", resourceKey: String(out.id), detail: String(b.name), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

// POST /api/trace/:id/object — add a model object (type = actor|role|asset|invariant|edge)
router.post("/trace/:id/object", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const out = addTraceObject(Number(req.params.id), String(b.type || ""), b, tenantOf(req));
  if (!out) return void res.status(400).json({ error: "invalid type or model not found" });
  res.json({ ok: true, ...out });
});

// DELETE /api/trace/object/:type/:oid — remove a model object
router.delete("/trace/object/:type/:oid", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "delete", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const ok = deleteTraceObject(String(req.params.type), Number(req.params.oid), tenantOf(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

// POST /api/trace/:id/collusion — add a collusion/coordination surface (phase 5)
router.post("/trace/:id/collusion", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const out = addCollusion(Number(req.params.id), { actors: String(b.actors || ""), quorum: b.quorum != null ? String(b.quorum) : undefined, credible: !!b.credible, notes: b.notes != null ? String(b.notes) : undefined }, tenantOf(req));
  if (!out) return void res.status(404).json({ error: "model not found" });
  res.json({ ok: true, ...out });
});
router.delete("/trace/collusion/:cid", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "delete", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  if (!deleteCollusion(Number(req.params.cid), tenantOf(req))) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

// POST /api/trace/:id/threat — add a STRIDE threat (optionally traced to a model object)
router.post("/trace/:id/threat", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "THREATMODELTHREAT") && !userCan(req.user, "create", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const out = addTraceThreat(Number(req.params.id), {
    title: String(b.title || ""), stride: b.stride != null ? String(b.stride) : undefined, description: b.description != null ? String(b.description) : undefined,
    likelihood: b.likelihood != null ? String(b.likelihood) : undefined, impact: b.impact != null ? String(b.impact) : undefined,
    traceType: b.traceType != null ? String(b.traceType) : undefined, traceId: b.traceId != null ? Number(b.traceId) : undefined,
  }, tenantOf(req));
  if (!out) return void res.status(404).json({ error: "model not found" });
  res.json({ ok: true, ...out });
});

// POST /api/trace/threat/:tid/link — trace an existing threat to a model object
router.post("/trace/threat/:tid/link", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "THREATMODELTHREAT") && !userCan(req.user, "update", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = setThreatTraceLink(Number(req.params.tid), b.traceType != null ? String(b.traceType) : null, b.traceId != null ? Number(b.traceId) : null, tenantOf(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

// POST /api/trace/:id/phase — advance/approve a workflow phase (sequential approval gate)
router.post("/trace/:id/phase", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const by = String(req.user.DisplayName || req.user.Email || req.user.UserID || "user");
  const out = advancePhase(Number(req.params.id), Number(b.phase), String(b.status || "in-progress"), by, tenantOf(req));
  if (!out.ok) return void res.status(400).json(out);
  xid.addAudit({ userId: req.user.UserID ?? null, action: "trace_phase", resourceType: "trace", resourceKey: `${req.params.id}:${b.phase}`, detail: String(b.status), ip: clientIp(req) });
  res.json(out);
});

// POST /api/trace/ai/extract — AI: extract candidate TRACE objects from pasted sources (offline fallback)
router.post("/trace/ai/extract", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const out = await ai.traceExtractObjects(String(b.text || ""), b.pillar != null ? String(b.pillar) : undefined);
  res.json(out);
});

// POST /api/trace/:id/ai/stride — AI: propose STRIDE threats for the model's objects (offline fallback)
router.post("/trace/:id/ai/stride", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const m = traceModel(Number(req.params.id), tenantOf(req));
  if (!m) return void res.status(404).json({ error: "not found" });
  res.json(await ai.traceProposeStride(m));
});

// POST /api/trace/:id/ai/report — AI: narrate the roadmap & report (phase 6, offline fallback)
router.post("/trace/:id/ai/report", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const m = traceModel(Number(req.params.id), tenantOf(req));
  if (!m) return void res.status(404).json({ error: "not found" });
  res.json(await ai.traceReport(m));
});

// POST /api/trace/seed — seed a demo TRACE model (idempotent)
router.post("/trace/seed", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? 1 : (req.user.tenantId ?? 1);
  res.json({ ok: true, ...seedTraceDemo(tenant) });
});

export default router;
