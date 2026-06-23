/**
 * loghunt.ts — AI host-log threat hunting.
 *
 * The XOR agent collects recent host logs (Sysmon, PowerShell, Security/process-creation on
 * Windows; journald/auth on Linux) and ships them here. The server runs a two-stage analysis:
 *   1. a deterministic heuristic pass (always) — flags well-known malicious patterns mapped to
 *      ATT&CK (encoded PowerShell, download cradles, LOLBins, LSASS dumping, log clearing, …);
 *   2. the local AI (Ollama) — given the events + the heuristic flags, it writes a concise
 *      DFIR analysis (verdict + notable activity + techniques + next hunt). Falls back to a
 *      deterministic summary when Ollama is unreachable, so the feature always returns something.
 *
 * The run is stored in XAGENT.LOGHUNT + a log_hunt agent event, and — when something suspicious
 * is found — spawns a HUNT (TaHiTI: trigger "Security Monitoring", phase "Hunt") so it lands in
 * the hunting backlog. No host data leaves the machine: the AI is the local Ollama.
 */
import { getDb } from "./db";
import { getAgentDb, addAgentEvent, listAgents } from "./agents";
import { ollamaChat } from "./ai";
import { saveHunt } from "./hunting";

const nowSql = (): string => new Date().toISOString().slice(0, 19).replace("T", " ");

export interface LogEvent { time?: string; id?: string | number; channel?: string; process?: string; cmd?: string; parent?: string; user?: string; raw?: string }
export interface LogHuntPayload { source?: string; host?: string; os?: string; events?: LogEvent[] }

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const maxSev = (a: string, b: string): string => (SEV_RANK[a] >= SEV_RANK[b] ? a : b);

// Heuristic detections: a regex over the event text → an ATT&CK technique + severity.
const RULES: { rx: RegExp; technique: string; name: string; severity: string }[] = [
  { rx: /lsass|sekurlsa|mimikatz|comsvcs\.dll.*minidump|procdump.*lsass/i, technique: "T1003.001", name: "LSASS / credential dumping", severity: "critical" },
  { rx: /-enc(odedcommand)?\b|frombase64string|-e\s+[A-Za-z0-9+/]{40,}/i, technique: "T1027", name: "Encoded / obfuscated PowerShell", severity: "high" },
  { rx: /downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|invoke-expression|\biex\s*\(/i, technique: "T1059.001", name: "PowerShell download cradle / IEX", severity: "high" },
  { rx: /certutil.*(-urlcache|-decode|-encode)|bitsadmin\s+\/transfer/i, technique: "T1105", name: "LOLBin ingress tool transfer (certutil/bitsadmin)", severity: "high" },
  { rx: /\bmshta\b|regsvr32.*scrobj|rundll32.*javascript|\binstallutil\b/i, technique: "T1218", name: "Signed-binary proxy execution (LOLBin)", severity: "high" },
  { rx: /wmic\s+process\s+call\s+create|win32_process/i, technique: "T1047", name: "WMI process execution", severity: "medium" },
  { rx: /vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no/i, technique: "T1490", name: "Shadow-copy / recovery deletion (ransomware precursor)", severity: "high" },
  { rx: /wevtutil\s+cl|clear-eventlog|\bsc\s+stop\s+eventlog/i, technique: "T1070.001", name: "Event-log clearing", severity: "high" },
  { rx: /schtasks\s+\/create|new-scheduledtask|\bat\s+\d{1,2}:\d{2}/i, technique: "T1053.005", name: "Scheduled-task persistence", severity: "medium" },
  { rx: /reg(\.exe)?\s+add.*\\(run|runonce)\b|currentversion\\run/i, technique: "T1547.001", name: "Run-key persistence", severity: "medium" },
  { rx: /\bsc\s+create|new-service/i, technique: "T1543.003", name: "New service persistence", severity: "medium" },
  { rx: /-w\s+hidden|-windowstyle\s+hidden|-nop\b|-noprofile|executionpolicy\s+bypass|-exec\s+bypass/i, technique: "T1059.001", name: "Suspicious PowerShell flags (hidden/bypass)", severity: "medium" },
  { rx: /\bpsexec\b|wmic\s+\/node:|enter-pssession|invoke-command\s+-computername|\bwinrm\b/i, technique: "T1021", name: "Lateral movement (remote exec)", severity: "medium" },
  { rx: /net\s+(user|group|localgroup).*\/(add|domain)|nltest\s+\/domain_trusts|whoami\s+\/priv|net\s+group\s+"domain admins"/i, technique: "T1087", name: "Account / domain discovery", severity: "low" },
];

function eventLine(e: LogEvent): string {
  if (e.raw && !e.cmd && !e.process) return String(e.raw);
  const parts = [
    e.time ? `[${e.time}]` : "", e.channel ? e.channel : "", e.id != null ? `EID ${e.id}` : "",
    e.process ? `proc=${e.process}` : "", e.parent ? `parent=${e.parent}` : "", e.user ? `user=${e.user}` : "",
    e.cmd ? `cmd=${e.cmd}` : "", (!e.cmd && e.raw) ? e.raw : "",
  ].filter(Boolean);
  return parts.join(" ");
}

export interface LogHuntResult {
  logHuntId: number; severity: string; techniques: string[]; summary: string;
  findings: { technique: string; name: string; severity: string; evidence: string }[];
  ai: boolean; model: string; huntId: number | null; events: number;
}

/** Analyse a batch of host log events with heuristics + the local AI; persist + maybe spawn a hunt. */
export async function analyzeHostLogs(agent: string, payload: LogHuntPayload): Promise<LogHuntResult> {
  const source = String(payload.source || "host-logs").slice(0, 60);
  const host = String(payload.host || agent).slice(0, 200);
  const os = String(payload.os || "").slice(0, 120);
  const events = Array.isArray(payload.events) ? payload.events.slice(0, 400) : [];
  const lines = events.map(eventLine).filter(Boolean);

  // 1. Heuristic pass.
  const findings: LogHuntResult["findings"] = [];
  const techSet = new Set<string>();
  let severity = "info";
  for (const line of lines) {
    for (const r of RULES) {
      if (r.rx.test(line)) {
        findings.push({ technique: r.technique, name: r.name, severity: r.severity, evidence: line.slice(0, 240) });
        techSet.add(r.technique); severity = maxSev(severity, r.severity);
      }
    }
  }
  // de-dupe findings by technique+evidence
  const seen = new Set<string>();
  const uniqFindings = findings.filter((f) => { const k = `${f.technique}|${f.evidence}`; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 60);

  // 2. Local AI pass (best-effort; deterministic fallback on failure).
  const sampleLines = lines.slice(0, 120).map((l) => l.slice(0, 300));
  const flagText = uniqFindings.length
    ? uniqFindings.slice(0, 25).map((f) => `- ${f.severity.toUpperCase()} ${f.technique} ${f.name}: ${f.evidence}`).join("\n")
    : "(no heuristic flags)";
  let summary = "";
  let ai = false;
  let model = "deterministic";
  try {
    const sys = "You are a senior DFIR threat hunter. Analyse the host log events for signs of compromise. " +
      "Be concise and specific. Output: (1) a one-line verdict (benign / suspicious / likely-malicious), " +
      "(2) the notable activity with the responsible process/command, (3) the relevant MITRE ATT&CK technique IDs (Txxxx), " +
      "(4) one recommended next hunting step. Do not invent events that are not present.";
    const user = `HOST: ${host} (${os})\nLOG SOURCE: ${source}\nEVENTS (${lines.length}):\n${sampleLines.join("\n").slice(0, 9000)}\n\nHEURISTIC FLAGS:\n${flagText}`;
    summary = await ollamaChat([{ role: "system", content: sys }, { role: "user", content: user }], 0.2, 90000);
    if (summary) { ai = true; model = process.env.OLLAMA_MODEL || "llama3.1:8b"; }
  } catch {
    ai = false;
  }
  if (!summary) {
    summary = uniqFindings.length
      ? `Heuristic analysis flagged ${uniqFindings.length} suspicious event(s) across ${lines.length} log line(s). Highest severity: ${severity.toUpperCase()}. Techniques: ${[...techSet].join(", ") || "none"}. Top: ${uniqFindings.slice(0, 5).map((f) => f.name).join("; ")}. (Local AI unreachable — heuristic summary.)`
      : `No obvious malicious patterns in ${lines.length} ${source} event(s). (Local AI unreachable — heuristic summary.)`;
    model = "deterministic (Ollama unreachable)";
  }

  // Techniques: heuristic ∪ AI-extracted Txxxx from the narrative.
  for (const m of summary.match(/T\d{4}(?:\.\d{3})?/g) || []) techSet.add(m.toUpperCase());
  const techniques = [...techSet];

  // 3. Persist LOGHUNT + event + (when suspicious) a TaHiTI hunt.
  const db = getAgentDb();
  const a = listAgents().find((x) => x.name === agent);
  let huntId: number | null = null;
  if (SEV_RANK[severity] >= SEV_RANK.medium) {
    try {
      const sv = saveHunt({
        name: `AI log hunt: ${host} (${source})`.slice(0, 200),
        description: summary.slice(0, 8000),
        status: SEV_RANK[severity] >= SEV_RANK.high ? "In progress" : "Proposed",
        tool: "local-AI log hunt", source: `agent:${host}`,
        findings: uniqFindings.map((f) => `${f.severity.toUpperCase()} ${f.technique} ${f.name}: ${f.evidence}`).join("\n").slice(0, 8000),
        techniques,
      });
      huntId = sv.huntId;
      // Tag the spawned hunt into the TaHiTI funnel (column-aware).
      try {
        const xt = getDb("XTHREAT");
        const cols = new Set((xt.prepare(`PRAGMA table_info("HUNT")`).all() as { name: string }[]).map((c) => c.name));
        const sets: string[] = []; const args: unknown[] = [];
        if (cols.has("TahitiPhase")) { sets.push("TahitiPhase = ?"); args.push("Hunt"); }
        if (cols.has("TahitiTrigger")) { sets.push("TahitiTrigger = ?"); args.push("Security Monitoring"); }
        if (sets.length) { args.push(huntId); xt.prepare(`UPDATE HUNT SET ${sets.join(", ")} WHERE HuntID = ?`).run(...args); }
      } catch { /* tahiti columns optional */ }
    } catch { huntId = null; }
  }

  const r = db.prepare(
    `INSERT INTO LOGHUNT(agent,asset_name,host_os,source,event_count,severity,summary,findings,techniques,model,ai_used,hunt_id,created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(agent, a?.asset_name ?? null, os || (a?.os ?? null), source, lines.length, severity,
    summary.slice(0, 8000), JSON.stringify(uniqFindings), techniques.join(", "), model, ai ? 1 : 0, huntId, nowSql());

  addAgentEvent(agent, {
    type: "log_hunt",
    severity: SEV_RANK[severity] >= SEV_RANK.high ? "high" : SEV_RANK[severity] >= SEV_RANK.medium ? "medium" : "info",
    title: `AI log hunt (${source}): ${severity.toUpperCase()} — ${uniqFindings.length} flag${uniqFindings.length === 1 ? "" : "s"} in ${lines.length} event${lines.length === 1 ? "" : "s"}${huntId ? ` → hunt #${huntId}` : ""}`,
    detail: { source, host, severity, findings: uniqFindings.length, techniques, ai, huntId },
  });

  return { logHuntId: Number(r.lastInsertRowid), severity, techniques, summary, findings: uniqFindings, ai, model, huntId, events: lines.length };
}
