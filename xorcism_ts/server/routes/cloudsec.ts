/** cloudsec.ts (routes) — Cloud Security Management inventory + AWS compliance checker. RBAC on XORCISM.ASSET. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { cloudInventory, evaluateAwsCompliance, cloudComplianceView, AwsSnapshot } from "../cloudsec";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null);

// GET /api/cloud-security — cloud asset inventory + exposure worklist + CCM posture reference
router.get("/cloud-security", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(cloudInventory(tenantOf(req))); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/cloud-security/compliance — stored AWS compliance findings + summary
router.get("/cloud-security/compliance", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(cloudComplianceView(tenantOf(req))); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/cloud-security/aws-check — run the CIS-AWS compliance checker over a posture snapshot
// Body: { snapshot: {...} } (account password policy, IAM users, root, CloudTrail, AWS Config).
router.post("/cloud-security/aws-check", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { snapshot?: unknown };
  const snap = (b.snapshot && typeof b.snapshot === "object" ? b.snapshot : b) as AwsSnapshot;
  if (!snap || typeof snap !== "object") return void res.status(400).json({ error: "snapshot required" });
  try {
    const out = evaluateAwsCompliance(snap, tenantOf(req), { persist: true });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "cloud_aws_check", resourceType: "CLOUDFINDING",
      resourceKey: out.account, detail: `account=${out.account} pass=${out.summary.pass} fail=${out.summary.fail} score=${out.summary.score}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
