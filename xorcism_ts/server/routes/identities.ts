/**
 * identities.ts (routes) — IAM inventory + risk worklist.
 * Read-only; guarded by read on XORCISM.IDENTITY. CRUD is the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { identityInventory } from "../identities";

const router = Router();

// GET /api/identities — identity inventory (human + non-human) with governance findings
router.get("/identities", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "IDENTITY")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(identityInventory(tenant));
});

export default router;
