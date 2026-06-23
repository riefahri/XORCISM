/**
 * hunting.ts — Threat Hunting domain/capability.
 *
 * Reads the HUNT / HUNTATTACK / HUNTIOC, IOC and XTHREAT (ATT&CK technique,
 * threat actor, hypothesis) tables to drive a hunting overview, and exposes an
 * AI hunt assistant backed by the local LLM agent (Ollama) in ./ai.
 *
 * No data leaves the machine: the agent runs through the local Ollama server.
 */
import crypto from "crypto";
import { getDb } from "./db";
import { ollamaChat, OLLAMA_MODEL } from "./ai";

function nowTs(): string {
  return new Date().toISOString().slice(0, 19).replace("T", " ");
}

const STOPWORDS = new Set([
  "what", "which", "most", "current", "threat", "threats", "hunt", "hunting", "actor",
  "technique", "techniques", "detect", "detection", "with", "from", "that", "this", "your",
  "our", "are", "the", "for", "and", "how", "should", "could", "would", "have", "about",
]);

/** Extracts up to 6 search keywords (or ATT&CK IDs) from a focus string. */
function keywords(focus: string): string[] {
  const raw = (focus || "").toLowerCase();
  const ids = (raw.match(/t\d{4}(?:\.\d{3})?/g) || []); // ATT&CK technique IDs
  const words = raw.split(/[^a-z0-9.]+/).filter((w) => w.length >= 4 && !STOPWORDS.has(w));
  return Array.from(new Set([...ids, ...words])).slice(0, 6);
}

// ── Overview ────────────────────────────────────────────────────────────────

export interface HuntingOverview {
  stats: {
    hunts: number;
    iocs: number;
    hypotheses: number;
    techniquesHunted: number;
    sigmaRules: number;
  };
  huntsByStatus: { status: string; count: number }[];
  iocsByType: { type: string; count: number }[];
  recentHunts: {
    HuntID: number; HuntName: string; HuntStatus: string; HuntDate: string;
    HuntTool: string; AttackTags: string; HuntFindings: string;
    techCount: number; iocCount: number;
  }[];
  recentIocs: { IOCID: number; IOCName: string; IOCtype: string; Pattern: string; Confidence: number }[];
  hypotheses: { HypothesisID: number; HypothesisName: string; ConfidenceLevel: string }[];
  topTechniques: { AttackID: string; Name: string; count: number }[];
}

/** Aggregates the hunting picture from the XTHREAT database (best-effort, each block isolated). */
export function huntingOverview(): HuntingOverview {
  const xt = getDb("XTHREAT");
  const one = <T>(sql: string, def: T): T => {
    try { return (xt.prepare(sql).get() as { v: T })?.v ?? def; } catch { return def; }
  };
  const many = <T>(sql: string): T[] => {
    try { return xt.prepare(sql).all() as T[]; } catch { return []; }
  };

  return {
    stats: {
      hunts: one<number>("SELECT COUNT(*) AS v FROM HUNT", 0),
      iocs: one<number>("SELECT COUNT(*) AS v FROM IOC", 0),
      hypotheses: one<number>("SELECT COUNT(*) AS v FROM HYPOTHESIS", 0),
      techniquesHunted: one<number>("SELECT COUNT(DISTINCT AttackID) AS v FROM HUNTATTACK", 0),
      sigmaRules: one<number>("SELECT COUNT(*) AS v FROM SIGMARULE", 0),
    },
    huntsByStatus: many<{ status: string; count: number }>(
      "SELECT COALESCE(NULLIF(TRIM(HuntStatus),''),'(unset)') AS status, COUNT(*) AS count " +
      "FROM HUNT GROUP BY status ORDER BY count DESC, status"),
    iocsByType: many<{ type: string; count: number }>(
      "SELECT COALESCE(NULLIF(TRIM(IOCtype),''),'indicator') AS type, COUNT(*) AS count " +
      "FROM IOC GROUP BY type ORDER BY count DESC, type LIMIT 12"),
    recentHunts: many(
      "SELECT h.HuntID, COALESCE(h.HuntName,'') AS HuntName, COALESCE(h.HuntStatus,'') AS HuntStatus, " +
      "COALESCE(h.HuntDate,'') AS HuntDate, COALESCE(h.HuntTool,'') AS HuntTool, " +
      "COALESCE(h.AttackTags,'') AS AttackTags, COALESCE(h.HuntFindings,'') AS HuntFindings, " +
      "(SELECT COUNT(*) FROM HUNTATTACK a WHERE a.HuntID=h.HuntID) AS techCount, " +
      "(SELECT COUNT(*) FROM HUNTIOC i WHERE i.HuntID=h.HuntID) AS iocCount " +
      "FROM HUNT h ORDER BY h.HuntID DESC LIMIT 12"),
    recentIocs: many(
      "SELECT IOCID, COALESCE(IOCName,'') AS IOCName, COALESCE(IOCtype,'indicator') AS IOCtype, " +
      "COALESCE(Pattern,'') AS Pattern, COALESCE(Confidence,0) AS Confidence " +
      "FROM IOC ORDER BY IOCID DESC LIMIT 12"),
    hypotheses: many(
      "SELECT HypothesisID, COALESCE(HypothesisName,'') AS HypothesisName, " +
      "COALESCE(ConfidenceLevel,'') AS ConfidenceLevel FROM HYPOTHESIS ORDER BY HypothesisID DESC LIMIT 10"),
    topTechniques: many<{ AttackID: string; Name: string; count: number }>(
      "SELECT a.AttackID AS AttackID, COALESCE(t.Name,'') AS Name, COUNT(*) AS count " +
      "FROM HUNTATTACK a LEFT JOIN ATTACKTECHNIQUE t ON t.AttackID=a.AttackID " +
      "GROUP BY a.AttackID ORDER BY count DESC, a.AttackID LIMIT 12"),
  };
}

// ── TaHiTI methodology (Targeted Hunting integrating Threat Intelligence) ──────
// A structured 3-phase hunting methodology (Initiate → Hunt → Finalize) built around a hunt
// backlog of "investigation abstracts" triggered mainly by threat intelligence. We add two
// optional HUNT columns (TahitiPhase, TahitiTrigger) and surface the picture as a phase funnel.

function huntCols(): Set<string> {
  try { return new Set((getDb("XTHREAT").prepare(`PRAGMA table_info("HUNT")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}

/** Adds the TaHiTI columns to HUNT (idempotent) so a hunt can carry its phase + trigger. */
export function ensureTahitiColumns(): void {
  try {
    const xt = getDb("XTHREAT");
    if (!xt.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='HUNT'").get()) return;
    const c = huntCols();
    if (!c.has("TahitiPhase")) xt.exec(`ALTER TABLE "HUNT" ADD COLUMN "TahitiPhase" TEXT`);
    if (!c.has("TahitiTrigger")) xt.exec(`ALTER TABLE "HUNT" ADD COLUMN "TahitiTrigger" TEXT`);
  } catch { /* best-effort */ }
}

export const TAHITI_PHASES: { key: string; name: string; order: number; description: string; steps: string[] }[] = [
  { key: "initiate", name: "1 · Initiate", order: 1,
    description: "Create and prioritize hunting investigation abstracts from triggers (threat intelligence first) — building and grooming the hunt backlog.",
    steps: ["Capture a trigger (TI, monitoring, red team, incident…)", "Write a short investigation abstract (title + hypothesis + priority)", "Prioritize it into the hunt backlog"] },
  { key: "hunt", name: "2 · Hunt", order: 2,
    description: "Take an abstract from the backlog and run the investigation: define → refine → execute → analyse, testing the hypothesis against the data.",
    steps: ["Define the investigation (scope, data sources, ATT&CK techniques)", "Refine into concrete queries / analytics", "Execute the hunt across the estate", "Analyse results — confirm or reject the hypothesis"] },
  { key: "finalize", name: "3 · Finalize", order: 3,
    description: "Document the outcome and hand it off: new detections to monitoring, findings to incident response, and lessons learned back into the backlog.",
    steps: ["Document findings & verdict (TP / FP / inconclusive)", "Hand off detections to security monitoring (Sigma)", "Escalate confirmed threats to incident response", "Capture lessons learned / spawn follow-up abstracts"] },
];

// The TaHiTI hunt triggers (where investigation abstracts come from).
export const TAHITI_TRIGGERS = [
  "Threat Intelligence", "Security Monitoring", "Other Hunt", "Red Teaming",
  "Security Incident", "Vulnerability / Threat Landscape", "Crown Jewel Analysis",
];

/** Map a hunt to a TaHiTI phase: explicit TahitiPhase wins, else derive from its status. */
function derivePhase(explicit: string, status: string, workflow: string): string {
  const e = (explicit || "").trim().toLowerCase();
  if (e.startsWith("init")) return "initiate";
  if (e === "hunt" || e.startsWith("hunt")) return "hunt";
  if (e.startsWith("final")) return "finalize";
  const s = `${status} ${workflow}`.toLowerCase();
  if (/(complete|closed|finaliz|true positive|false positive|no finding|resolved|done|reported)/.test(s)) return "finalize";
  if (/(active|in[\s-]?progress|hunting|ongoing|investigat|analy)/.test(s)) return "hunt";
  return "initiate"; // proposed / new / backlog / draft / unset
}

export interface TahitiOverview {
  phases: { key: string; name: string; order: number; description: string; steps: string[]; count: number;
            hunts: { HuntID: number; HuntName: string; status: string; trigger: string | null; techCount: number }[] }[];
  triggers: { name: string; count: number }[];
  summary: { totalHunts: number; withTrigger: number; backlog: number };
}

/** The TaHiTI picture: hunts bucketed into the 3 phases + a trigger breakdown. */
export function tahitiOverview(): TahitiOverview {
  ensureTahitiColumns();
  const xt = getDb("XTHREAT");
  const c = huntCols();
  const phaseCol = c.has("TahitiPhase") ? "COALESCE(TahitiPhase,'')" : "''";
  const trigCol = c.has("TahitiTrigger") ? "COALESCE(TahitiTrigger,'')" : "''";
  const wfCol = c.has("WorkflowStatus") ? "COALESCE(WorkflowStatus,'')" : "''";
  let rows: { HuntID: number; HuntName: string; HuntStatus: string; wf: string; phase: string; trigger: string; techCount: number }[] = [];
  try {
    rows = xt.prepare(
      `SELECT h.HuntID, COALESCE(h.HuntName,'') AS HuntName, COALESCE(h.HuntStatus,'') AS HuntStatus, ` +
      `${wfCol} AS wf, ${phaseCol} AS phase, ${trigCol} AS trigger, ` +
      `(SELECT COUNT(*) FROM HUNTATTACK a WHERE a.HuntID=h.HuntID) AS techCount FROM HUNT h ORDER BY h.HuntID DESC`,
    ).all() as typeof rows;
  } catch { rows = []; }

  const buckets = new Map<string, TahitiOverview["phases"][number]["hunts"]>();
  for (const p of TAHITI_PHASES) buckets.set(p.key, []);
  const trigCounts = new Map<string, number>();
  let withTrigger = 0;
  for (const r of rows) {
    const key = derivePhase(r.phase, r.HuntStatus, r.wf);
    (buckets.get(key) || buckets.get("initiate"))!.push({
      HuntID: r.HuntID, HuntName: r.HuntName || `Hunt #${r.HuntID}`,
      status: r.HuntStatus || "(unset)", trigger: r.trigger || null, techCount: r.techCount,
    });
    if (r.trigger && r.trigger.trim()) { withTrigger++; trigCounts.set(r.trigger.trim(), (trigCounts.get(r.trigger.trim()) || 0) + 1); }
  }
  const phases = TAHITI_PHASES.map((p) => ({ ...p, count: buckets.get(p.key)!.length, hunts: buckets.get(p.key)!.slice(0, 50) }));
  const triggers = TAHITI_TRIGGERS.map((name) => ({ name, count: trigCounts.get(name) || 0 }))
    .concat([...trigCounts.entries()].filter(([n]) => !TAHITI_TRIGGERS.includes(n)).map(([name, count]) => ({ name, count })))
    .filter((t, i, a) => a.findIndex((x) => x.name === t.name) === i);
  return { phases, triggers, summary: { totalHunts: rows.length, withTrigger, backlog: buckets.get("initiate")!.length } };
}

// ── AI hunt assistant (RAG over HUNT / IOC / XTHREAT + local LLM agent) ────────

/** Builds the RAG context for a hunt focus from HUNT, IOC and XTHREAT tables. */
export function buildHuntContext(focus: string): { text: string; sources: string[] } {
  const xt = getDb("XTHREAT");
  const kw = keywords(focus);
  const blocks: string[] = [];
  const sources: string[] = [];
  const like = (cols: string[]): { where: string; args: string[] } => {
    const parts: string[] = [];
    const args: string[] = [];
    for (const k of kw) for (const c of cols) { parts.push(`${c} LIKE ?`); args.push(`%${k}%`); }
    return { where: parts.length ? parts.join(" OR ") : "1=1", args };
  };

  // 1) ATT&CK techniques matching the focus — with detection guidance + data sources.
  try {
    if (kw.length) {
      const { where, args } = like(["Name", "AttackID", "Description"]);
      const rows = xt.prepare(
        `SELECT AttackID, Name, COALESCE(Detection,'') AS Detection, COALESCE(DataSources,'') AS DataSources, ` +
        `COALESCE(Platforms,'') AS Platforms FROM ATTACKTECHNIQUE WHERE Deprecated=0 AND (${where}) LIMIT 12`
      ).all(...args) as { AttackID: string; Name: string; Detection: string; DataSources: string; Platforms: string }[];
      if (rows.length) {
        blocks.push("Relevant MITRE ATT&CK techniques (with detection/data sources):\n" + rows.map((r) =>
          `- ${r.AttackID} ${r.Name}` +
          (r.DataSources ? `\n    data sources: ${r.DataSources.slice(0, 200)}` : "") +
          (r.Detection ? `\n    detection: ${r.Detection.slice(0, 300)}` : "")).join("\n"));
        sources.push("ATT&CK");
      }
    }
  } catch { /* skip */ }

  // 2) Threat actors matching the focus.
  try {
    if (kw.length) {
      const { where, args } = like(["ThreatActorName", "ThreatActorDescription", "country"]);
      const rows = xt.prepare(
        `SELECT ThreatActorName, COALESCE(ThreatActorDescription,'') AS d, COALESCE(country,'') AS country ` +
        `FROM THREATACTOR WHERE ${where} LIMIT 8`
      ).all(...args) as { ThreatActorName: string; d: string; country: string }[];
      if (rows.length) {
        blocks.push("Known threat actors matching the focus:\n" + rows.map((r) =>
          `- ${r.ThreatActorName}${r.country ? ` (${r.country})` : ""}: ${r.d.slice(0, 180)}`).join("\n"));
        sources.push("threat-actors");
      }
    }
  } catch { /* skip */ }

  // 3) IOCs matching the focus (or most recent if no keyword hit).
  try {
    let rows: { IOCName: string; IOCtype: string; Pattern: string }[] = [];
    if (kw.length) {
      const { where, args } = like(["IOCName", "IOCDescription", "Pattern", "Labels"]);
      rows = xt.prepare(
        `SELECT COALESCE(IOCName,'') AS IOCName, COALESCE(IOCtype,'indicator') AS IOCtype, ` +
        `COALESCE(Pattern,'') AS Pattern FROM IOC WHERE ${where} LIMIT 15`
      ).all(...args) as typeof rows;
    }
    if (!rows.length) {
      rows = xt.prepare(
        "SELECT COALESCE(IOCName,'') AS IOCName, COALESCE(IOCtype,'indicator') AS IOCtype, " +
        "COALESCE(Pattern,'') AS Pattern FROM IOC ORDER BY IOCID DESC LIMIT 10"
      ).all() as typeof rows;
    }
    if (rows.length) {
      blocks.push("IOCs to pivot on:\n" + rows.map((r) =>
        `- [${r.IOCtype}] ${r.IOCName}${r.Pattern ? ` ${r.Pattern.slice(0, 120)}` : ""}`).join("\n"));
      sources.push("IOC");
    }
  } catch { /* skip */ }

  // 4) Existing hunts + open hypotheses (avoid duplicating effort).
  try {
    const hunts = xt.prepare(
      "SELECT HuntName, COALESCE(HuntStatus,'?') AS HuntStatus, COALESCE(AttackTags,'') AS AttackTags " +
      "FROM HUNT ORDER BY HuntID DESC LIMIT 8").all() as { HuntName: string; HuntStatus: string; AttackTags: string }[];
    if (hunts.length) {
      blocks.push("Existing hunts (do not duplicate):\n" + hunts.map((h) =>
        `- [${h.HuntStatus}] ${h.HuntName}${h.AttackTags ? ` (ATT&CK: ${h.AttackTags})` : ""}`).join("\n"));
      sources.push("hunts");
    }
    const hyp = xt.prepare("SELECT HypothesisName FROM HYPOTHESIS ORDER BY HypothesisID DESC LIMIT 6")
      .all() as { HypothesisName: string }[];
    if (hyp.length) {
      blocks.push("Current hunt hypotheses:\n" + hyp.map((h) => `- ${h.HypothesisName}`).join("\n"));
      sources.push("hypotheses");
    }
  } catch { /* skip */ }

  return { text: blocks.join("\n\n"), sources };
}

/** AI hunt assistant: builds a structured, actionable hunt package for a focus. */
export async function generateHunt(focus: string): Promise<{ plan: string; sources: string[]; model: string }> {
  const { text, sources } = buildHuntContext(focus);
  const system =
    "You are a senior threat hunter. From the analyst's FOCUS, produce a concrete, structured threat-hunting " +
    "package grounded in the provided CONTEXT (the organisation's own XORCISM data: ATT&CK techniques with " +
    "detection guidance and data sources, threat actors, existing hunts/hypotheses and IOCs). " +
    "Return Markdown with exactly these sections:\n" +
    "1. **Hypothesis** — one testable sentence.\n" +
    "2. **ATT&CK techniques** — bullet list, each starting with the technique ID (e.g. T1059.001).\n" +
    "3. **Data sources / log sources** — what telemetry to query.\n" +
    "4. **Detection logic** — pseudo-query or Sigma-style logic; you may give a SPL, KQL or EQL snippet.\n" +
    "5. **IOCs / pivots** — concrete indicators to chase (prefer those in the CONTEXT).\n" +
    "6. **Next steps & expected findings**.\n" +
    "Prefer techniques, actors and IOCs that appear in the CONTEXT; explicitly say when relevant data is missing. " +
    "Never invent IOCs or asset names absent from the CONTEXT. Be concise and operational.";
  const user = `FOCUS: ${focus}\n\nCONTEXT (from XORCISM HUNT / IOC / ATT&CK / threat actors):\n${text || "(no organisation-specific data retrieved)"}`;
  const plan = await ollamaChat([{ role: "system", content: system }, { role: "user", content: user }]);
  return { plan, sources, model: OLLAMA_MODEL };
}

// ── Persist a generated hunt into the HUNT table (+ HUNTATTACK links) ─────────

export interface SaveHuntInput {
  name: string;
  description?: string;
  status?: string;
  tool?: string;
  findings?: string;
  source?: string;
  techniques?: string[]; // ATT&CK IDs, e.g. ["T1059", "T1071.001"]
}

/** Inserts a HUNT row and its HUNTATTACK technique links. Returns the new HuntID + link count. */
export function saveHunt(input: SaveHuntInput): { huntId: number; links: number } {
  const xt = getDb("XTHREAT");
  const techniques = Array.from(new Set(
    (input.techniques || [])
      .map((s) => String(s).trim().toUpperCase())
      .filter((s) => /^T\d{4}(\.\d{3})?$/.test(s))
  ));
  const attackTags = techniques.join(", ");

  const tx = xt.transaction(() => {
    const huntId = ((xt.prepare("SELECT COALESCE(MAX(HuntID),0) AS m FROM HUNT").get() as { m: number }).m) + 1;
    xt.prepare(
      "INSERT INTO HUNT (HuntID, HuntGUID, HuntName, HuntDescription, CreatedDate, HuntStatus, HuntTool, " +
      "AttackTags, HuntFindings, HuntSource) VALUES (?,?,?,?,?,?,?,?,?,?)"
    ).run(
      huntId, crypto.randomUUID(), input.name.slice(0, 300), (input.description || "").slice(0, 8000), nowTs(),
      (input.status || "Proposed").slice(0, 60), (input.tool || "").slice(0, 200),
      attackTags, (input.findings || "").slice(0, 8000), (input.source || "AI hunt assistant").slice(0, 200)
    );
    let links = 0;
    let nextLinkId = ((xt.prepare("SELECT COALESCE(MAX(HuntAttackID),0) AS m FROM HUNTATTACK").get() as { m: number }).m);
    const ins = xt.prepare(
      "INSERT OR IGNORE INTO HUNTATTACK (HuntAttackID, HuntID, AttackID, CreatedDate) VALUES (?,?,?,?)"
    );
    for (const aid of techniques) {
      nextLinkId += 1;
      const info = ins.run(nextLinkId, huntId, aid, nowTs());
      if (info.changes) links += 1; else nextLinkId -= 1;
    }
    return { huntId, links };
  });
  return tx();
}
