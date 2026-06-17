/**
 * cti.ts (routes) — "CTI that acts": intel cross-referenced with the asset inventory,
 * and one-click ticketing. Mounted under /api (authenticated).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import * as xid from "../xid";
import { intelImpact, ticketForCve } from "../cti";

const router = Router();
function tenantOf(req: Request): number | null { return req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null); }
const CVE_RX = /^CVE-\d{4}-\d{3,7}$/i;

// GET /api/cti/impact — threat intel (KEV + reports) that affects your inventory
router.get("/cti/impact", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XVULNERABILITY", "VULNERABILITY")) return void res.status(403).json({ error: "forbidden" });
  res.json(intelImpact(tenantOf(req)));
});

// POST /api/cti/ticket { cve } — open a ticket for an intel match
router.post("/cti/ticket", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XTICKET", "TICKET")) return void res.status(403).json({ error: "forbidden" });
  const cve = String((req.body as { cve?: unknown })?.cve ?? "").trim();
  if (!CVE_RX.test(cve)) return void res.status(400).json({ error: "valid CVE id required" });
  const r = ticketForCve(tenantOf(req), cve, req.user.Email);
  xid.addAudit({ userId: req.user.UserID, action: "cti_ticket", resourceType: "ticket", resourceKey: `XTICKET.TICKET#${r.ticketId}`, detail: `${cve} ${r.created ? "created" : "existing"}`, ip: clientIp(req) });
  res.json({ ok: true, ...r });
});

export default router;
