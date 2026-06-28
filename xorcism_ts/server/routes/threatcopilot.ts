/**
 * threatcopilot.ts (routes) — Threat-Intel Copilot (/threat-copilot).
 * Read-gated on XVULNERABILITY.VULNERABILITY (the data the copilot reasons over).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { decisionReadyFeed, copilotAnswer, CopilotMode } from "../threatcopilot";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null);
const canRead = (req: Request): boolean => userCan(req.user!, "read", "XVULNERABILITY", "VULNERABILITY");

// GET /api/threat-copilot/feed — decision-ready triage (Act / Prioritise / Track)
router.get("/threat-copilot/feed", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(decisionReadyFeed(tenantOf(req), Math.min(Number(req.query.limit) || 100, 300))); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/threat-copilot/ask { mode, question } — the Vera-style multi-mode analyst
router.post("/threat-copilot/ask", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { mode?: unknown; question?: unknown };
  const mode = String(b.mode || "ask") as CopilotMode;
  const question = String(b.question || "").slice(0, 2000);
  try {
    const out = await copilotAnswer(mode, question, tenantOf(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "threat_copilot_ask", resourceType: "VULNERABILITY",
      detail: `mode=${out.mode} offline=${out.offline} q="${question.slice(0, 80)}" queries=${out.queries.length}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
