/**
 * admin.ts (routes) — Multi-tenant administration.
 * - Super-admin (System tenant): manages the tenants + global config
 *   (roles, permissions, resources) + all users.
 * - Tenant admin: manages only the users of THEIR tenant.
 */

import { Router, Request, Response } from "express";
import * as xid from "../xid";
import { hashPassword, passwordPolicyError, clientIp } from "../auth";
import { listDatabases, listTables, getSchema, backupDatabases, correlateCveToAssets } from "../db";
import { tr } from "../i18n";

const router = Router();

const APP_PAGES = [
  { path: "/", label: "Explorateur" },
  { path: "/bia", label: "BIA Audit" },
  { path: "/dashboard", label: "Dashboard" },
  { path: "/stix-graph", label: "STIX Graph" },
  { path: "/connectors", label: "Connectors" },
  { path: "/pentest", label: "Pentest mode (scan en masse)" },
  { path: "/admin", label: "Administration" },
];

// ── Tenant scope helpers ───────────────────────────────────────────────────

function superOnly(req: Request, res: Response): boolean {
  if (req.user!.isSuperAdmin) return true;
  res.status(403).json({ error: tr(req, "err.adminOnly") });
  return false;
}

/** The (non-super) admin can only act on a user of their tenant. */
function canActOnUser(req: Request, userId: number): boolean {
  if (req.user!.isSuperAdmin) return true;
  const u = xid.getUserById(userId);
  return !!u && u.TenantID === req.user!.tenantId;
}

// ── Database backup (super-admin) ────────────────────────────────────────
// POST /api/admin/backup — consistent snapshot of all the databases in DB_DIR/backups
router.post("/backup", async (req: Request, res: Response) => {
  if (!superOnly(req, res)) return;
  try {
    const r = await backupDatabases();
    xid.addAudit({
      userId: req.user!.UserID, action: "db_backup", resourceType: "database",
      detail: `${r.files.length} bases → ${r.dir}`, ip: clientIp(req),
    });
    res.json(r);
  } catch (e) {
    res.status(500).json({ error: (e as Error).message });
  }
});

// POST /api/admin/correlate-cve — CVE→assets correlation via CPE (super-admin)
router.post("/correlate-cve", (req: Request, res: Response) => {
  if (!superOnly(req, res)) return;
  try {
    const r = correlateCveToAssets();
    xid.addAudit({
      userId: req.user!.UserID, action: "cve_correlation", resourceType: "asset",
      detail: `${r.links} liens (${r.assetsMatched} actifs, ${r.cvesMatched} CVE)`, ip: clientIp(req),
    });
    res.json(r);
  } catch (e) {
    res.status(500).json({ error: (e as Error).message });
  }
});

// ── Tenants (super-admin only) ──────────────────────────────────────────

router.get("/tenants", (req: Request, res: Response) => {
  if (!superOnly(req, res)) return;
  const tenants = xid.listTenants().map((t) => ({
    ...t,
    userCount: xid.listUsers(t.TenantID).length,
  }));
  res.json(tenants);
});

router.post("/tenants", (req: Request, res: Response) => {
  if (!superOnly(req, res)) return;
  const { name } = req.body as { name?: string };
  if (!name || !name.trim())
    return void res.status(400).json({ error: tr(req, "err.badRequest") });
  const id = xid.ensureTenant(name.trim(), false);
  xid.addAudit({
    userId: req.user!.UserID,
    action: "tenant_created",
    resourceType: "tenant",
    resourceKey: name.trim(),
    ip: clientIp(req),
    tenantId: id,
  });
  res.json({ id });
});

router.post("/tenants/:id/active", (req: Request, res: Response) => {
  if (!superOnly(req, res)) return;
  const id = Number(req.params.id);
  const active = !!(req.body as { active?: boolean }).active;
  xid.setTenantActive(id, active);
  xid.addAudit({
    userId: req.user!.UserID,
    action: active ? "tenant_enabled" : "tenant_disabled",
    resourceType: "tenant",
    resourceKey: String(id),
    ip: clientIp(req),
    tenantId: id,
  });
  res.json({ ok: true });
});

// ── Users (scoped by tenant) ──────────────────────────────────────────

router.get("/users", (req: Request, res: Response) => {
  // Super-admin: all (or ?tenantId=); tenant admin: their tenant
  const scope = req.user!.isSuperAdmin
    ? req.query.tenantId
      ? Number(req.query.tenantId)
      : undefined
    : req.user!.tenantId ?? undefined;
  const users = xid.listUsers(scope ?? undefined);
  res.json(
    users.map((u) => ({
      ...u,
      roles: xid.getUserRoles(Number(u.UserID)).map((r) => r.RoleName),
    }))
  );
});

router.post("/users", (req: Request, res: Response) => {
  const { email, displayName, password, roleIds, tenantId } = req.body as {
    email?: string;
    displayName?: string;
    password?: string;
    roleIds?: number[];
    tenantId?: number;
  };
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
    return void res.status(400).json({ error: tr(req, "err.emailInvalid") });
  if (xid.findUserByEmail(email))
    return void res.status(409).json({ error: tr(req, "err.emailExists") });
  const policy = passwordPolicyError(password ?? "");
  if (policy) return void res.status(400).json({ error: tr(req, policy) });

  // Target tenant: super-admin can choose; tenant admin → their tenant
  const targetTenant = req.user!.isSuperAdmin
    ? Number(tenantId) || req.user!.tenantId
    : req.user!.tenantId;

  const uid = xid.createUser({
    email,
    displayName,
    passwordHash: hashPassword(password!),
    mustChange: true,
    createdBy: req.user!.UserID,
    tenantId: targetTenant,
  });
  (roleIds ?? []).forEach((rid) => xid.assignRole(uid, Number(rid)));
  xid.addAudit({
    userId: req.user!.UserID,
    action: "user_created",
    resourceType: "user",
    resourceKey: email,
    ip: clientIp(req),
    tenantId: targetTenant,
  });
  res.json({ id: uid });
});

router.post("/users/:id/lock", (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!canActOnUser(req, id)) return void res.status(403).json({ error: tr(req, "err.adminOnly") });
  const locked = !!(req.body as { locked?: boolean }).locked;
  xid.setUserLock(id, locked);
  if (locked) xid.deleteUserSessions(id);
  xid.addAudit({
    userId: req.user!.UserID,
    action: locked ? "user_locked" : "user_unlocked",
    resourceType: "user",
    resourceKey: String(id),
    ip: clientIp(req),
    tenantId: req.user!.tenantId,
  });
  res.json({ ok: true });
});

router.post("/users/:id/reset-password", (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!canActOnUser(req, id)) return void res.status(403).json({ error: tr(req, "err.adminOnly") });
  const { password } = req.body as { password?: string };
  const policy = passwordPolicyError(password ?? "");
  if (policy) return void res.status(400).json({ error: tr(req, policy) });
  xid.setPassword(id, hashPassword(password!), 1);
  xid.deleteUserSessions(id);
  xid.addAudit({
    userId: req.user!.UserID,
    action: "user_password_reset",
    resourceType: "user",
    resourceKey: String(id),
    ip: clientIp(req),
    tenantId: req.user!.tenantId,
  });
  res.json({ ok: true });
});

router.post("/users/:id/roles", (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!canActOnUser(req, id)) return void res.status(403).json({ error: tr(req, "err.adminOnly") });
  const { roleIds } = req.body as { roleIds?: number[] };
  const current = xid.getUserRoles(id).map((r) => r.RoleID);
  current.forEach((rid) => xid.removeRole(id, rid));
  (roleIds ?? []).forEach((rid) => xid.assignRole(id, Number(rid)));
  xid.addAudit({
    userId: req.user!.UserID,
    action: "user_roles_set",
    resourceType: "user",
    resourceKey: String(id),
    detail: JSON.stringify(roleIds ?? []),
    ip: clientIp(req),
    tenantId: req.user!.tenantId,
  });
  res.json({ ok: true });
});

// ── Roles (global — super-admin only) ──────────────────────────────────

router.get("/roles", (_req: Request, res: Response) => {
  res.json(xid.listRoles()); // visible for assigning to users
});

router.post("/roles", (req: Request, res: Response) => {
  if (!superOnly(req, res)) return;
  const { name, description } = req.body as { name?: string; description?: string };
  if (!name) return void res.status(400).json({ error: tr(req, "err.roleNameRequired") });
  const id = xid.ensureRole(name, description ?? "");
  xid.addAudit({ userId: req.user!.UserID, action: "role_created", resourceKey: name, ip: clientIp(req) });
  res.json({ id });
});

// ── Resources & permissions (global config — super-admin only) ────────

router.get("/resources", (req: Request, res: Response) => {
  if (!superOnly(req, res)) return;
  const databases = listDatabases().map((db) => ({ db, tables: listTables(db) }));
  res.json({ pages: APP_PAGES, databases });
});

router.get("/fields", (req: Request, res: Response) => {
  if (!superOnly(req, res)) return;
  const db = String(req.query.db || "");
  const table = String(req.query.table || "");
  if (!db || !table) return void res.status(400).json({ error: tr(req, "err.badRequest") });
  res.json((getSchema(db, table) as { name: string }[]).map((c) => c.name));
});

router.get("/permissions/:roleId", (req: Request, res: Response) => {
  if (!superOnly(req, res)) return;
  res.json(xid.getRolePermissions(Number(req.params.roleId)));
});

router.post("/permissions/:roleId", (req: Request, res: Response) => {
  if (!superOnly(req, res)) return;
  const roleId = Number(req.params.roleId);
  const { resourceType, resourceKey, c, r, u, d } = req.body as {
    resourceType: string;
    resourceKey: string;
    c: boolean;
    r: boolean;
    u: boolean;
    d: boolean;
  };
  if (!resourceType || !resourceKey)
    return void res.status(400).json({ error: tr(req, "err.badRequest") });
  xid.setPermission(roleId, resourceType, resourceKey, { c: !!c, r: !!r, u: !!u, d: !!d });
  xid.addAudit({
    userId: req.user!.UserID,
    action: "permission_set",
    resourceType,
    resourceKey,
    detail: `role=${roleId} C${+!!c}R${+!!r}U${+!!u}D${+!!d}`,
    ip: clientIp(req),
  });
  res.json({ ok: true });
});

// ── Audit (scoped by tenant for tenant admins) ────────────────────────

router.get("/audit", (req: Request, res: Response) => {
  const limit = Math.min(Number(req.query.limit) || 200, 1000);
  const scope = req.user!.isSuperAdmin ? undefined : req.user!.tenantId ?? undefined;
  res.json(xid.listAudit(limit, scope ?? undefined));
});

// Common filters for the exports (tenant-scoped for non-super admins).
function auditFilters(req: Request) {
  const q = req.query;
  return {
    action: q.action ? String(q.action) : undefined,
    userId: q.userId ? Number(q.userId) : undefined,
    since: q.since ? String(q.since) : undefined,
    until: q.until ? String(q.until) : undefined,
    tenantId: req.user!.isSuperAdmin ? undefined : (req.user!.tenantId ?? undefined),
  };
}

// GET /api/admin/audit/export — paginated/filtered JSON (SIEM pull; no 200 cap)
router.get("/audit/export", (req: Request, res: Response) => {
  res.json(xid.queryAudit({
    ...auditFilters(req),
    limit: Number(req.query.limit) || 1000,
    offset: Number(req.query.offset) || 0,
  }));
});

// GET /api/admin/audit/export.jsonl — JSON Lines stream (bulk SIEM ingestion)
router.get("/audit/export.jsonl", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="xorcism-audit.jsonl"');
  const filters = auditFilters(req);
  const pageSize = 5000;
  let offset = 0;
  // Streaming pagination so as not to load the whole log into memory.
  for (;;) {
    const rows = xid.queryAudit({ ...filters, limit: pageSize, offset });
    if (!rows.length) break;
    for (const r of rows) res.write(JSON.stringify(r) + "\n");
    if (rows.length < pageSize) break;
    offset += pageSize;
  }
  res.end();
});

// ── Current context (for the UI) ──────────────────────────────────────────────

router.get("/whoami", (req: Request, res: Response) => {
  res.json({
    isSuperAdmin: req.user!.isSuperAdmin,
    tenantId: req.user!.tenantId,
    tenantName: req.user!.tenantName,
  });
});

export default router;
