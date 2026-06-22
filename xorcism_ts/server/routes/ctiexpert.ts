/** ctiexpert.ts (routes) — CTI-Expert: AI-orchestrated OSINT investigation cockpit.
 *  RBAC: read XTHREAT.INTELEXCHANGE; the investigate action (creates intel + observables) gates on update. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { ctiExpertDashboard, listInvestigations, getInvestigation, runInvestigation, type TargetKind } from "../ctiexpert";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XTHREAT", "INTELEXCHANGE");
const wr = (req: Request) => userCan(req.user, "update", "XTHREAT", "INTELEXCHANGE");

router.get("/cti-expert", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(ctiExpertDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/cti-expert/list", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json({ investigations: listInvestigations(ten(req)) }); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/cti-expert/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const inv = getInvestigation(Number(req.params.id), ten(req));
  if (!inv) return void res.status(404).json({ error: "not found" });
  res.json(inv);
});

router.post("/cti-expert/investigate", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!wr(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const target = String(b.target ?? "").trim();
  if (!target) return void res.status(400).json({ error: "target required" });
  if (target.length > 400) return void res.status(400).json({ error: "target too long" });
  const kind = b.kind ? (String(b.kind) as TargetKind) : undefined;
  try {
    const out = await runInvestigation(target, kind, ten(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "cti_investigate", resourceType: "CTIINVESTIGATION", resourceKey: String(out.id), ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
