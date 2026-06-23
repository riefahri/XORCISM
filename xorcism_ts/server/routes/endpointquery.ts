/** endpointquery.ts (routes) — Tanium-style real-time endpoint querying ("Interact").
 *  Ask a sensor question of the online XOR fleet and read back the aggregated answer grid. */
import { Router, Request, Response } from "express";
import { clientIp } from "../auth";
import { endpointQueryDashboard, askQuestion, questionResults, sensorById } from "../endpointquery";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/endpoint-query", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  try { res.json(endpointQueryDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/endpoint-query/ask", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const b = (req.body || {}) as Record<string, unknown>;
  const sensorId = String(b.sensorId ?? "").trim();
  if (!sensorById(sensorId)) return void res.status(400).json({ error: "unknown sensor" });
  const out = askQuestion(sensorId, { filter: b.filter ? String(b.filter).slice(0, 120) : undefined, userId: req.user.UserID, userName: req.user.DisplayName || req.user.Email }, ten(req));
  if (!out) return void res.status(400).json({ error: "could not ask" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "endpoint_query", resourceType: "ENDPOINTQUESTION", resourceKey: String(out.questionId), detail: `${out.sensor} → ${out.targeted} agent(s)`, ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.get("/endpoint-query/question/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const out = questionResults(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json(out);
});

export default router;
