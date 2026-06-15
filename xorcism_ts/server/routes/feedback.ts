/**
 * feedback.ts (routes) — feature ratings + improvement requests.
 * Mounted AFTER the auth gate (req.user required). Triage restricted to admins.
 */
import { Router, Request, Response } from "express";
import * as xid from "../xid";
import { clientIp } from "../auth";

const router = Router();

// POST /api/feedback  { type:'rating'|'improvement', feature, rating, title, message }
router.post("/feedback", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const b = req.body as { type?: string; feature?: string; rating?: number; title?: string; message?: string };
  const type = b.type === "improvement" ? "improvement" : "rating";
  if (type === "improvement") {
    if (!b.title || !b.message) return void res.status(400).json({ error: "Titre et description requis." });
    xid.addFeedback({ userId: req.user.UserID, email: req.user.Email, type, title: b.title.slice(0, 200), message: String(b.message).slice(0, 5000) });
  } else {
    const rating = Math.max(1, Math.min(5, Number(b.rating) || 0));
    if (!b.feature) return void res.status(400).json({ error: "Fonctionnalité requise." });
    xid.addFeedback({ userId: req.user.UserID, email: req.user.Email, type, featureKey: b.feature, rating, message: (b.message || "").slice(0, 2000) });
  }
  xid.addAudit({ userId: req.user.UserID, action: "feedback", detail: type, ip: clientIp(req) });
  res.json({ ok: true });
});

// GET /api/feedback/mine — my contributions + community averages
router.get("/feedback/mine", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  res.json({ mine: xid.listFeedbackByUser(req.user.UserID), averages: xid.feedbackAverages() });
});

// GET /api/feedback/all — admin (triage)
router.get("/feedback/all", (req: Request, res: Response) => {
  if (!req.user?.isAdmin) return void res.status(403).json({ error: "admin" });
  res.json(xid.listAllFeedback());
});

// POST /api/feedback/:id/status — admin
router.post("/feedback/:id/status", (req: Request, res: Response) => {
  if (!req.user?.isAdmin) return void res.status(403).json({ error: "admin" });
  const valid = ["new", "reviewing", "planned", "done", "declined"];
  const s = String((req.body as { status?: string }).status || "new");
  xid.setFeedbackStatus(Number(req.params.id), valid.includes(s) ? s : "new");
  res.json({ ok: true });
});

export default router;
