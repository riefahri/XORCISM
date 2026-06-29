/** cloudsec.ts (routes) — Cloud Security Management inventory + AWS compliance checker. RBAC on XORCISM.ASSET. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { cloudInventory, evaluateAwsCompliance, evaluateAzureCompliance, evaluateGcpCompliance, cloudComplianceView, AwsSnapshot, AzureSnapshot, GcpSnapshot } from "../cloudsec";
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

// POST /api/cloud-security/azure-check — CIS Microsoft Azure Foundations subset (Entra ID password/MFA)
router.post("/cloud-security/azure-check", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { snapshot?: unknown };
  const snap = (b.snapshot && typeof b.snapshot === "object" ? b.snapshot : b) as AzureSnapshot;
  if (!snap || typeof snap !== "object") return void res.status(400).json({ error: "snapshot required" });
  try {
    const out = evaluateAzureCompliance(snap, tenantOf(req), { persist: true });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "cloud_azure_check", resourceType: "CLOUDFINDING", resourceKey: out.account, detail: `tenant=${out.account} pass=${out.summary.pass} fail=${out.summary.fail} score=${out.summary.score}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/cloud-security/gcp-check — CIS Google Cloud Foundations subset (MFA/2SV, SA keys, IAM)
router.post("/cloud-security/gcp-check", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { snapshot?: unknown };
  const snap = (b.snapshot && typeof b.snapshot === "object" ? b.snapshot : b) as GcpSnapshot;
  if (!snap || typeof snap !== "object") return void res.status(400).json({ error: "snapshot required" });
  try {
    const out = evaluateGcpCompliance(snap, tenantOf(req), { persist: true });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "cloud_gcp_check", resourceType: "CLOUDFINDING", resourceKey: out.account, detail: `project=${out.account} pass=${out.summary.pass} fail=${out.summary.fail} score=${out.summary.score}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
