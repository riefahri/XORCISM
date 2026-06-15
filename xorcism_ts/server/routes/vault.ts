/**
 * vault.ts (routes) — Encryption vault management (admin only).
 * Setup (creation + recovery key), unlock, lock,
 * recovery. The passphrase only transits to derive the key in memory;
 * it is never stored.
 */
import { Router, Request, Response } from "express";
import * as vault from "../vault";
import * as xid from "../xid";
import { clientIp } from "../auth";

const router = Router();

function adminOnly(req: Request, res: Response): boolean {
  if (!req.user?.isAdmin) { res.status(403).json({ error: "Réservé aux administrateurs" }); return false; }
  return true;
}

router.get("/vault/status", (req: Request, res: Response) => {
  if (!adminOnly(req, res)) return;
  res.json(vault.status());
});

router.post("/vault/setup", (req: Request, res: Response) => {
  if (!adminOnly(req, res)) return;
  const passphrase = String((req.body as { passphrase?: string }).passphrase || "");
  try {
    const { recoveryKey } = vault.setup(passphrase);
    xid.addAudit({ userId: req.user!.UserID, action: "vault_setup", resourceType: "vault", ip: clientIp(req) });
    res.json({ ok: true, recoveryKey }); // shown only ONCE
  } catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

router.post("/vault/unlock", (req: Request, res: Response) => {
  if (!adminOnly(req, res)) return;
  try {
    vault.unlock(String((req.body as { passphrase?: string }).passphrase || ""));
    xid.addAudit({ userId: req.user!.UserID, action: "vault_unlock", resourceType: "vault", ip: clientIp(req) });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

router.post("/vault/lock", (req: Request, res: Response) => {
  if (!adminOnly(req, res)) return;
  vault.lock();
  xid.addAudit({ userId: req.user!.UserID, action: "vault_lock", resourceType: "vault", ip: clientIp(req) });
  res.json({ ok: true });
});

router.post("/vault/recover", (req: Request, res: Response) => {
  if (!adminOnly(req, res)) return;
  const { recoveryKey, newPassphrase } = req.body as { recoveryKey?: string; newPassphrase?: string };
  try {
    vault.recover(String(recoveryKey || ""), String(newPassphrase || ""));
    xid.addAudit({ userId: req.user!.UserID, action: "vault_recover", resourceType: "vault", ip: clientIp(req) });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

export default router;
