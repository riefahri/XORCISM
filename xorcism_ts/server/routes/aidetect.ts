/**
 * aidetect.ts (routes) — AI runtime anomaly detection (/ai-detection). Read-only; RBAC mirrors the
 * AI inventory (read XORCISM.ASSET). A GET runs the detectors (idempotent) over the usage telemetry.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { aiDetectionDashboard, recordAiUsage } from "../aidetect";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/ai-detection", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(aiDetectionDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/ai-detection/usage — ingest a daily usage rollup (agent / AI-gateway connector)
router.post("/ai-detection/usage", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as any;
  const rows = Array.isArray(b) ? b : Array.isArray(b.rows) ? b.rows : [b];
  let n = 0;
  try {
    for (const r of rows) { if (r && r.aiSystemId && r.day) { recordAiUsage(ten(req), r); n++; } }
    xid.addAudit({ userId: req.user.UserID ?? null, action: "ai_usage_ingest", resourceType: "AIUSAGE", resourceKey: String(n), ip: clientIp(req) });
    res.json({ ingested: n, ...aiDetectionDashboard(ten(req)) });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
