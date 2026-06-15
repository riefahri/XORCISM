/**
 * notifications.ts (routes) — user notifications (header bell +
 * browser notifications). Stored in XORCISM.NOTIFICATION. Mounted AFTER
 * the auth gate.
 *
 *   GET  /api/notifications            → { items, unread } of the current user
 *   POST /api/notifications/:id/read   → mark a notification as read
 *   POST /api/notifications/read-all   → mark all as read
 *   POST /api/notifications            → create (self; broadcast/other user = admin)
 */
import { Router, Request, Response } from "express";
import {
  listNotifications, unreadNotificationCount, markNotificationRead,
  markAllNotificationsRead, createNotification, notifyUsers,
} from "../db";
import * as xid from "../xid";
import { clientIp } from "../auth";

const router = Router();

const LEVELS = new Set(["info", "success", "warning", "error"]);

// GET /api/notifications — list + unread counter of the current user
router.get("/notifications", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const limit = Math.min(Number(req.query.limit) || 30, 100);
  res.json({
    items: listNotifications(req.user.UserID, limit),
    unread: unreadNotificationCount(req.user.UserID),
  });
});

// POST /api/notifications/:id/read
router.post("/notifications/:id/read", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return void res.status(400).json({ error: "id invalide" });
  const ok = markNotificationRead(req.user.UserID, id);
  res.json({ ok, unread: unreadNotificationCount(req.user.UserID) });
});

// POST /api/notifications/read-all
router.post("/notifications/read-all", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const changed = markAllNotificationsRead(req.user.UserID);
  res.json({ ok: true, changed, unread: 0 });
});

// POST /api/notifications — creates a notification.
//   target: "me" (default) | "all" | <UserID>. "all"/other user ⇒ admin required.
router.post("/notifications", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const b = req.body as { title?: string; message?: string; level?: string; link?: string; target?: unknown };
  const title = String(b.title || "").trim();
  if (!title) return void res.status(400).json({ error: "titre requis" });
  const level = LEVELS.has(String(b.level)) ? String(b.level) : "info";
  const message = b.message != null ? String(b.message).slice(0, 4000) : null;
  const link = b.link != null ? String(b.link).slice(0, 1000) : null;

  const target = b.target ?? "me";
  const base = { title: title.slice(0, 300), message, level, link, source: "user", tenantId: req.user.tenantId };

  // self
  if (target === "me" || target === undefined) {
    const id = createNotification({ ...base, userId: req.user.UserID });
    return void res.json({ ok: true, created: 1, id });
  }
  // broadcast / other user ⇒ admin
  if (!req.user.isAdmin) return void res.status(403).json({ error: "réservé aux administrateurs" });

  if (target === "all") {
    // super-admin: all; tenant admin: their tenant only
    const users = xid.listUsers(req.user.isSuperAdmin ? null : req.user.tenantId);
    const ids = users.map((u) => Number(u.UserID)).filter((n) => Number.isInteger(n) && n > 0);
    const created = notifyUsers(ids, base);
    xid.addAudit({ userId: req.user.UserID, action: "notify_broadcast", resourceType: "notification",
      detail: `${created} destinataires`, ip: clientIp(req) });
    return void res.json({ ok: true, created });
  }

  const uid = Number(target);
  if (!Number.isInteger(uid) || uid <= 0) return void res.status(400).json({ error: "cible invalide" });
  const id = createNotification({ ...base, userId: uid });
  xid.addAudit({ userId: req.user.UserID, action: "notify_user", resourceType: "notification",
    resourceKey: String(uid), ip: clientIp(req) });
  res.json({ ok: true, created: 1, id });
});

export default router;
