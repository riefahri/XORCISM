/**
 * auditpack.ts (routes) — Audit & Accreditation package: a traceable, evidence-cited, AI-narrated report
 * (control implementation, regulatory adherence + audit trail, cyber-risk posture, BIA). RBAC: XCOMPLIANCE.AUDIT.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { generateAuditPackage, auditPackageMarkdown, auditPackageOscal } from "../auditpack";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

// GET /api/audit-package?format=json|md|oscal|poam — generate the audit & accreditation package
router.get("/audit-package", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  try {
    const pkg = await generateAuditPackage(tenantOf(req));
    const fmt = String(req.query.format || "json");
    if (fmt === "md") {
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="audit-accreditation-package.md"`);
      return void res.send(auditPackageMarkdown(pkg));
    }
    if (fmt === "oscal" || fmt === "poam") {
      const profile = ["soc2", "iso27001", "nistcsf"].includes(String(req.query.profile)) ? String(req.query.profile) : undefined;
      const doc = auditPackageOscal(pkg, fmt === "poam" ? "poam" : "ssp", { profile, tenant: tenantOf(req) });
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="xorcism-${fmt === "poam" ? "poam" : "ssp"}${profile ? "-" + profile : ""}.oscal.json"`);
      return void res.send(JSON.stringify(doc, null, 2));
    }
    res.json({ ...pkg, markdown: auditPackageMarkdown(pkg) });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
