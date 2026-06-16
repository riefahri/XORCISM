/**
 * sigma.ts (routes) — Sigma rule conversion to SPL / KQL / EQL.
 * POST /api/sigma/convert { yaml } → { title, level, logsource, attackTags, spl, kql, eql, engine }
 *
 * Uses pySigma (xorcism_python/sigma_convert.py) for production field mapping when
 * it is installed on the host; otherwise (or per backend that pySigma can't emit)
 * falls back to the built-in TypeScript converter. Mounted after the auth gate.
 */
import { Router, Request, Response } from "express";
import { execFile } from "child_process";
import path from "path";
import { convertSigma } from "../sigma";

const router = Router();

// dist/server/routes → ../../../.. = repository root → xorcism_python/
const PYSIGMA_SCRIPT = path.resolve(__dirname, "../../../../xorcism_python/sigma_convert.py");
const PYTHON = process.env.XORCISM_PYTHON || "python";

interface PyResult { engine?: string; version?: string; spl?: string; kql?: string; eql?: string; error?: string }

/** Convert via pySigma; resolves null if pySigma/python is unavailable or errors. */
function pysigmaConvert(yaml: string): Promise<PyResult | null> {
  return new Promise((resolve) => {
    const child = execFile(
      PYTHON, [PYSIGMA_SCRIPT],
      { timeout: 20000, windowsHide: true, maxBuffer: 4 * 1024 * 1024 },
      (err, stdout) => {
        if (err) return resolve(null);
        try {
          const j = JSON.parse(String(stdout).trim()) as PyResult;
          if (j && !j.error && (j.spl || j.kql || j.eql)) return resolve(j);
        } catch { /* not JSON */ }
        resolve(null);
      },
    );
    try { child.stdin?.end(yaml); } catch { /* spawn failed → callback handles it */ }
  });
}

router.post("/sigma/convert", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const yaml = (req.body as { yaml?: string }).yaml;
  if (!yaml || typeof yaml !== "string" || !yaml.trim())
    return void res.status(400).json({ error: "Missing 'yaml'." });
  if (yaml.length > 200_000) return void res.status(413).json({ error: "Rule too large." });

  // Built-in conversion: always available, supplies metadata + per-backend fallback.
  let builtin: ReturnType<typeof convertSigma>;
  try { builtin = convertSigma(yaml); } catch (e) {
    return void res.status(422).json({ error: String(e instanceof Error ? e.message : e) });
  }

  // Prefer pySigma (real field-mapping pipelines) when present.
  const py = await pysigmaConvert(yaml);
  res.json({
    title: builtin.title,
    level: builtin.level,
    status: builtin.status,
    logsource: builtin.logsource,
    attackTags: builtin.attackTags,
    spl: py?.spl ?? builtin.spl,
    kql: py?.kql ?? builtin.kql,
    eql: py?.eql ?? builtin.eql,
    engine: py ? `pysigma${py.version ? ` ${py.version}` : ""}` : "builtin",
  });
});

export default router;
