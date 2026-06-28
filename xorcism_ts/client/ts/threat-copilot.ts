/**
 * threat-copilot.ts — Threat-Intel Copilot (/threat-copilot).
 * Decision-ready triage (Act/Prioritise/Track) + a multi-mode analyst (Ask/Investigate/Draft/Challenge)
 * that shows the queries it ran and the sources it cited. Exvora-inspired; grounded in XORCISM data.
 */
export {}; // module scope (keeps $/esc local) — esbuild bundles this entry standalone
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface DecisionItem { vid: number; cve: string; title: string; decision: "Act" | "Prioritise" | "Track"; confidence: string; kev: boolean; epss: number | null; cvss: number | null; ssvc: string | null; assets: number; why: string; }
interface Feed { scope: string; summary: { act: number; prioritise: number; track: number; total: number }; items: DecisionItem[]; }
interface CopilotQuery { label: string; detail: string; count?: number }
interface CopilotSource { type: string; ref: string; label: string }
interface CopilotAnswer { mode: string; answer: string; queries: CopilotQuery[]; sources: CopilotSource[]; model: string; offline: boolean }

let mode = "ask";
const pct = (e: number | null): string => (e == null ? "—" : `${(e * 100).toFixed(0)}%`);

async function loadFeed(): Promise<void> {
  try {
    const r = await fetch("/api/threat-copilot/feed");
    const d = (await r.json()) as Feed;
    if (!r.ok) throw new Error((d as unknown as { error?: string }).error || `HTTP ${r.status}`);
    $("tc-scope").textContent = `— scope: ${d.scope === "estate" ? "your asset estate" : "global KEV / high-EPSS frontier"}`;
    $("tc-chips").innerHTML =
      `<div class="tc-chip act"><div class="n">${d.summary.act}</div><div class="l">Act now</div></div>` +
      `<div class="tc-chip prioritise"><div class="n">${d.summary.prioritise}</div><div class="l">Prioritise</div></div>` +
      `<div class="tc-chip track"><div class="n">${d.summary.track}</div><div class="l">Track</div></div>` +
      `<div class="tc-chip scope"><div class="n">${d.summary.total}</div><div class="l">scored total</div></div>`;
    const body = $("tc-feed-body");
    if (!d.items.length) { body.innerHTML = `<tr><td colspan="7" class="muted">No scored vulnerabilities found.</td></tr>`; return; }
    body.innerHTML = d.items.map((i) =>
      `<tr>
        <td><span class="pill ${i.decision}">${i.decision}</span></td>
        <td><span class="cve">${esc(i.cve)}</span>${i.kev ? ' <span class="kev" title="CISA KEV — actively exploited">KEV</span>' : ""}<div class="muted" style="font-size:11px;max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(i.title)}</div></td>
        <td style="max-width:280px">${esc(i.why)}</td>
        <td>${pct(i.epss)}</td>
        <td>${i.cvss == null ? "—" : esc(i.cvss)}</td>
        <td>${i.assets || "—"}</td>
        <td>${esc(i.confidence)}</td>
      </tr>`).join("");
  } catch (e) { $("tc-feed-body").innerHTML = `<tr><td colspan="7" class="muted">⚠️ ${esc(String(e))}</td></tr>`; }
}

async function run(): Promise<void> {
  const q = ($("tc-q") as HTMLTextAreaElement).value.trim();
  const btn = $("tc-run") as HTMLButtonElement; btn.disabled = true;
  $("tc-status").textContent = "Thinking…"; $("tc-answer").style.display = "none"; $("tc-metawrap").style.display = "none";
  try {
    const r = await fetch("/api/threat-copilot/ask", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode, question: q }) });
    const d = (await r.json()) as CopilotAnswer;
    if (!r.ok) throw new Error((d as unknown as { error?: string }).error || `HTTP ${r.status}`);
    $("tc-answer").textContent = d.answer; $("tc-answer").style.display = "block";
    $("tc-prov").innerHTML = d.offline ? `<span class="badge-off">offline synthesis</span>` : `<span class="badge-ai">local AI: ${esc(d.model)}</span>`;
    $("tc-queries").innerHTML = d.queries.map((qq) => `<div class="tc-q">${esc(qq.label)}${qq.count != null ? ` <span class="c">(${qq.count})</span>` : ""}<div class="muted" style="font-size:10.5px">${esc(qq.detail)}</div></div>`).join("") || `<div class="muted">none</div>`;
    $("tc-sources").innerHTML = d.sources.map((s) => `<span class="src"><span class="t">${esc(s.type)}</span> ${esc(s.label)}</span>`).join("") || `<div class="muted">none</div>`;
    $("tc-metawrap").style.display = "flex";
    $("tc-status").textContent = "";
  } catch (e) { $("tc-status").textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll<HTMLButtonElement>(".tc-mode").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(".tc-mode").forEach((x) => x.classList.remove("active"));
    b.classList.add("active"); mode = b.dataset.mode || "ask";
  }));
  $("tc-run").addEventListener("click", () => void run());
  ($("tc-q") as HTMLTextAreaElement).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter" && (e as KeyboardEvent).ctrlKey) void run(); });
  void loadFeed();
});
