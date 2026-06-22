/** landing.ts (routes) — landing-menu NICE filter + access config for the current user. */
import { Router, Request, Response } from "express";
import { landingConfig } from "../landingaccess";

const router = Router();

router.get("/landing/config", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  try { res.json(landingConfig(req.user)); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
