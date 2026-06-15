/**
 * ai.ts (routes) — local LLM (Ollama): "Ask the threat model" (RAG over XORCISM)
 * and OCIL answer suggestion. All the routes are authenticated (mounted under /api).
 */
import { Router, Request, Response } from "express";
import { askThreatModel, suggestOcilAnswer, ollamaStatus } from "../ai";

const router = Router();

function aiError(e: unknown): string {
  const m = String((e as Error)?.message || e);
  if (/ECONNREFUSED|fetch failed|ENOTFOUND|ETIMEDOUT/i.test(m)) {
    return `Local AI unreachable. Start Ollama (\`ollama serve\`) at ${process.env.OLLAMA_URL || "http://localhost:11434"} and pull a model.`;
  }
  return m;
}

// GET /api/ai/status — is the local AI reachable + available model(s)
router.get("/ai/status", async (_req: Request, res: Response) => {
  res.json(await ollamaStatus());
});

// POST /api/ai/ask { question } — "Ask the threat model" (RAG ATT&CK/KEV/asset + LLM)
router.post("/ai/ask", async (req: Request, res: Response) => {
  const q = String((req.body as { question?: unknown })?.question ?? "").trim();
  if (!q) return void res.status(400).json({ error: "question requise" });
  if (q.length > 2000) return void res.status(400).json({ error: "question trop longue" });
  try {
    res.json(await askThreatModel(q));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

// POST /api/ai/suggest-answer { question, description? } — OCIL answer draft
router.post("/ai/suggest-answer", async (req: Request, res: Response) => {
  const body = req.body as { question?: unknown; description?: unknown };
  const q = String(body?.question ?? "").trim();
  const d = body?.description ? String(body.description) : undefined;
  if (!q) return void res.status(400).json({ error: "question requise" });
  try {
    res.json(await suggestOcilAnswer(q, d));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

export default router;
