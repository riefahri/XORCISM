/**
 * worker_api.ts — Remote agents (workers) API, authenticated by TOKEN (no session).
 *
 * A remote worker (e.g. Kali VM) runs `connectors/runner.py --remote <URL> --token <T> --name <N>`
 * and calls:
 *   POST /api/worker/claim            → claims a job assigned to it (or unassigned)
 *   POST /api/worker/job/:id/log      → appends live log lines
 *   POST /api/worker/job/:id/result   → returns the normalized result (status 'collected')
 *
 * The database IMPORT is done by the LOCAL runner (which has DB access) on the 'collected' jobs.
 * This router is mounted BEFORE the session gate (token auth only).
 */
import { Router, Request, Response, NextFunction } from "express";
import { getWorkerByToken, touchWorker, claimRemoteJob, getJob, appendJobLog, attachRemoteResult, Worker } from "../jobs";

const router = Router();

interface WReq extends Request { worker?: Worker; }

function auth(req: WReq, res: Response, next: NextFunction): void {
  const h = req.headers.authorization || "";
  const m = /^Bearer\s+(.+)$/.exec(h);
  const token = m ? m[1].trim() : "";
  if (!token) return void res.status(401).json({ error: "jeton requis" });
  const w = getWorkerByToken(token);
  if (!w) return void res.status(401).json({ error: "jeton invalide" });
  req.worker = w;
  next();
}

// POST /api/worker/claim { capabilities?:[...] }
router.post("/worker/claim", auth, (req: WReq, res: Response) => {
  const w = req.worker!;
  touchWorker(w.name, "running");
  // capabilities: those declared at creation, otherwise those sent by the worker
  let caps: string[] = [];
  try { caps = w.capabilities ? JSON.parse(w.capabilities) : []; } catch { caps = []; }
  if (!caps.length && Array.isArray((req.body as { capabilities?: unknown }).capabilities)) {
    caps = ((req.body as { capabilities: unknown[] }).capabilities).map((c) => String(c));
  }
  const job = claimRemoteJob(w.name, caps);
  if (!job) {
    touchWorker(w.name, "idle");
    return void res.json({ job: null });
  }
  res.json({ job: { JobID: job.JobID, connector: job.connector, params: job.params, target: job.target } });
});

// POST /api/worker/job/:id/log { chunk }
router.post("/worker/job/:id/log", auth, (req: WReq, res: Response) => {
  const job = getJob(Number(req.params.id));
  if (!job || job.worker !== req.worker!.name) return void res.status(404).json({ error: "job inconnu" });
  appendJobLog(job.JobID, String((req.body as { chunk?: string }).chunk || ""));
  res.json({ ok: true });
});

// POST /api/worker/job/:id/result { ok, result, exit_code, error }
router.post("/worker/job/:id/result", auth, (req: WReq, res: Response) => {
  const w = req.worker!;
  const job = getJob(Number(req.params.id));
  if (!job || job.worker !== w.name) return void res.status(404).json({ error: "job inconnu" });
  const b = req.body as { ok?: boolean; result?: unknown; exit_code?: number; error?: string };
  attachRemoteResult(
    job.JobID,
    !!b.ok,
    b.result != null ? JSON.stringify(b.result) : null,
    typeof b.exit_code === "number" ? b.exit_code : null,
    b.error ? String(b.error) : null
  );
  touchWorker(w.name, "idle");
  res.json({ ok: true });
});

export default router;
