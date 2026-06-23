/**
 * hunting.ts — Threat Hunting page. Renders the hunting overview (HUNT / IOC /
 * XTHREAT) and drives the AI hunt assistant (/api/hunting/*) backed by the
 * local Ollama agent. Generated plans can be saved back into the HUNT table.
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string {
  return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
}

const EXAMPLE_KEYS = ["hunt.ex1", "hunt.ex2", "hunt.ex3", "hunt.ex4"];

interface Overview {
  stats: { hunts: number; iocs: number; hypotheses: number; techniquesHunted: number; sigmaRules: number };
  huntsByStatus: { status: string; count: number }[];
  iocsByType: { type: string; count: number }[];
  recentHunts: { HuntID: number; HuntName: string; HuntStatus: string; HuntDate: string; HuntTool: string;
    AttackTags: string; HuntFindings: string; techCount: number; iocCount: number }[];
  recentIocs: { IOCID: number; IOCName: string; IOCtype: string; Pattern: string; Confidence: number }[];
  hypotheses: { HypothesisID: number; HypothesisName: string; ConfidenceLevel: string }[];
  topTechniques: { AttackID: string; Name: string; count: number }[];
}

function bars(el: HTMLElement, rows: { label: string; count: number }[]): void {
  const max = Math.max(1, ...rows.map((r) => r.count));
  el.innerHTML = rows.length
    ? rows.map((r) => `<div class="row"><span class="lab" title="${esc(r.label)}">${esc(r.label)}</span>` +
        `<span class="bar" style="width:${Math.round((r.count / max) * 160)}px"></span>` +
        `<span class="cnt">${r.count}</span></div>`).join("")
    : '<span class="muted">—</span>';
}

async function loadOverview(): Promise<void> {
  let d: Overview;
  try {
    const r = await fetch("/api/hunting/overview");
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    d = await r.json() as Overview;
  } catch (e) {
    $("stats").innerHTML = `<span class="muted">${esc(t("hunt.loadErr"))} ${esc(e)}</span>`;
    return;
  }

  const s = d.stats;
  $("stats").innerHTML = [
    [t("hunt.stat.hunts"), s.hunts], [t("hunt.stat.tech"), s.techniquesHunted], [t("hunt.stat.iocs"), s.iocs],
    [t("hunt.stat.hyp"), s.hypotheses], [t("hunt.stat.sigma"), s.sigmaRules],
  ].map(([l, n]) => `<div class="stat"><div class="n">${n}</div><div class="l">${esc(l)}</div></div>`).join("");

  bars($("by-status"), d.huntsByStatus.map((r) => ({ label: r.status, count: r.count })));
  bars($("by-ioc"), d.iocsByType.map((r) => ({ label: r.type, count: r.count })));

  $("top-tech").innerHTML = d.topTechniques.length
    ? d.topTechniques.map((te) => `<span class="chip" title="${esc(te.Name)}">${esc(te.AttackID)}${te.Name ? " " + esc(te.Name) : ""} · ${te.count}</span>`).join(" ")
    : `<span class="muted">${esc(t("hunt.noTech"))}</span>`;

  $("hunts-body").innerHTML = d.recentHunts.length
    ? d.recentHunts.map((h) => `<tr>
        <td><a href="/?db=XTHREAT&table=HUNT&editCol=HuntID&editVal=${h.HuntID}" title="${esc(t("hunt.editHunt"))}">${esc(h.HuntName)}</a></td>
        <td><span class="pill">${esc(h.HuntStatus || "—")}</span></td>
        <td>${esc(h.HuntDate || "")}</td>
        <td>${esc(h.HuntTool || "")}</td>
        <td>${esc(h.AttackTags || "")} ${h.techCount ? `<span class="muted">(${h.techCount})</span>` : ""}</td>
        <td>${h.iocCount || 0}</td>
        <td>${esc((h.HuntFindings || "").slice(0, 120))}</td></tr>`).join("")
    : `<tr><td colspan="7" class="muted">${esc(t("hunt.noHunts"))}</td></tr>`;

  $("iocs-body").innerHTML = d.recentIocs.length
    ? d.recentIocs.map((i) => `<tr><td><a href="/?db=XTHREAT&table=IOC&editCol=IOCID&editVal=${i.IOCID}">${esc(i.IOCName)}</a></td><td><span class="pill">${esc(i.IOCtype)}</span></td>` +
        `<td class="mono">${esc((i.Pattern || "").slice(0, 80))}</td><td>${i.Confidence || ""}</td></tr>`).join("")
    : `<tr><td colspan="4" class="muted">${esc(t("hunt.noIoc"))}</td></tr>`;

  $("hyp-body").innerHTML = d.hypotheses.length
    ? d.hypotheses.map((h) => `<tr><td><a href="/?db=XTHREAT&table=HYPOTHESIS&editCol=HypothesisID&editVal=${h.HypothesisID}">${esc(h.HypothesisName)}</a></td><td><span class="pill">${esc(h.ConfidenceLevel || "—")}</span></td></tr>`).join("")
    : `<tr><td colspan="2" class="muted">${esc(t("hunt.noHyp"))}</td></tr>`;
}

async function refreshStatus(): Promise<void> {
  const el = $("ai-status");
  try {
    const s = await (await fetch("/api/ai/status")).json() as { reachable: boolean; model: string };
    if (s.reachable) { el.textContent = `🟢 Ollama · ${s.model}`; el.className = "ai-badge ai-up"; }
    else { el.textContent = t("hunt.aiDown"); el.className = "ai-badge ai-down"; }
  } catch { el.textContent = t("hunt.aiDown"); el.className = "ai-badge ai-down"; }
}

/** Pulls "Tnnnn(.nnn)" ATT&CK IDs out of the generated plan to prefill the save form. */
function techsFromPlan(plan: string): string[] {
  return Array.from(new Set((plan.match(/T\d{4}(?:\.\d{3})?/g) || []).map((s) => s.toUpperCase()))).slice(0, 20);
}

let lastFocus = "";
async function generate(): Promise<void> {
  const focus = ($("focus") as HTMLTextAreaElement).value.trim();
  if (!focus) return;
  lastFocus = focus;
  const out = $("plan"), meta = $("plan-meta"), btn = $("gen-btn") as HTMLButtonElement;
  out.className = ""; out.textContent = t("hunt.generating");
  meta.textContent = ""; btn.disabled = true; $("save-box").style.display = "none";
  try {
    const r = await fetch("/api/hunting/generate", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ focus }),
    });
    const d = await r.json() as { plan?: string; sources?: string[]; model?: string; error?: string };
    if (!r.ok) { out.textContent = "⚠️ " + (d.error || `${t("hunt.errHttp")} ${r.status}`); return; }
    out.textContent = d.plan || t("hunt.emptyResp");
    meta.textContent = (d.sources && d.sources.length)
      ? `${t("hunt.contextLabel")} ${d.sources.join(", ")} · ${t("hunt.modelLabel")} ${d.model}`
      : `${t("hunt.noContext")} ${d.model}`;
    (($("save-name") as HTMLInputElement)).value = focus.slice(0, 80);
    (($("save-tech") as HTMLInputElement)).value = techsFromPlan(d.plan || "").join(", ");
    $("save-box").style.display = "";
  } catch (e) {
    out.textContent = "⚠️ " + String(e);
  } finally { btn.disabled = false; }
}

async function save(): Promise<void> {
  const name = ($("save-name") as HTMLInputElement).value.trim();
  const techniques = ($("save-tech") as HTMLInputElement).value.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
  const msg = $("save-msg"); const btn = $("save-btn") as HTMLButtonElement;
  if (!name) { msg.textContent = t("hunt.nameRequired"); return; }
  btn.disabled = true; msg.textContent = "⏳…";
  try {
    const r = await fetch("/api/hunting/save", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name, techniques, description: `${t("hunt.focusLabel")} ${lastFocus}`,
        findings: ($("plan") as HTMLElement).textContent || "", status: "Proposed", source: "AI hunt assistant",
      }),
    });
    const d = await r.json() as { ok?: boolean; huntId?: number; links?: number; error?: string };
    if (!r.ok || !d.ok) { msg.textContent = "⚠️ " + (d.error || `${t("hunt.errHttp")} ${r.status}`); return; }
    msg.textContent = `✅ ${t("hunt.saved")} (HUNT #${d.huntId}, ${d.links} ${t("hunt.techLinked")})`;
    void loadOverview();
  } catch (e) {
    msg.textContent = "⚠️ " + String(e);
  } finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  const ex = $("examples");
  for (const k of EXAMPLE_KEYS) {
    const label = t(k);
    const b = document.createElement("button");
    b.textContent = label;
    b.onclick = () => { ($("focus") as HTMLTextAreaElement).value = label; void generate(); };
    ex.appendChild(b);
  }
  $("gen-btn").onclick = () => void generate();
  $("save-btn").onclick = () => void save();
  ($("focus") as HTMLTextAreaElement).addEventListener("keydown", (e) => {
    const ke = e as KeyboardEvent;
    if (ke.key === "Enter" && ke.ctrlKey) { e.preventDefault(); void generate(); }
  });
  void refreshStatus();
  void loadOverview();
  void loadTahiti();
});

// ── TaHiTI methodology phase funnel ──────────────────────────────────────────
interface TahitiPhase { key: string; name: string; description: string; steps: string[]; count: number; hunts: { HuntID: number; HuntName: string; status: string; trigger: string | null; techCount: number }[] }
interface TahitiData { phases: TahitiPhase[]; triggers: { name: string; count: number }[]; summary: { totalHunts: number; withTrigger: number; backlog: number } }

async function loadTahiti(): Promise<void> {
  const host = $("tahiti");
  let d: TahitiData;
  try { const r = await fetch("/api/hunting/tahiti"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { host.innerHTML = `<div class="muted">⚠️ ${esc(e)}</div>`; return; }

  const colors: Record<string, string> = { initiate: "#60a5fa", hunt: "#fbbf24", finalize: "#34d399" };
  const phaseCards = d.phases.map((p) => {
    const c = colors[p.key] || "#94a3b8";
    const hunts = p.hunts.length
      ? p.hunts.slice(0, 8).map((h) => `<div style="font-size:11px;padding:3px 0;border-top:1px solid var(--border)"><a href="/?db=XTHREAT&table=HUNT&filterCol=HuntID&filterVal=${h.HuntID}" style="color:var(--text)">${esc(h.HuntName)}</a> <span class="muted">· ${esc(h.status)}${h.trigger ? ` · ${esc(h.trigger)}` : ""}${h.techCount ? ` · ${h.techCount} TTP` : ""}</span></div>`).join("") + (p.hunts.length > 8 ? `<div class="muted" style="font-size:11px;padding-top:3px">+${p.hunts.length - 8} more</div>` : "")
      : `<div class="muted" style="font-size:11px;padding-top:4px">No hunts in this phase.</div>`;
    return `<div style="flex:1;min-width:230px;background:var(--surface-2);border:1px solid var(--border);border-top:3px solid ${c};border-radius:8px;padding:11px 13px">
      <div style="display:flex;align-items:baseline;justify-content:space-between"><b style="color:${c};font-size:13px">${esc(p.name)}</b><span style="font-size:22px;font-weight:700">${p.count}</span></div>
      <div class="muted" style="font-size:11px;line-height:1.45;margin:4px 0 7px">${esc(p.description)}</div>
      <ol style="margin:0 0 7px 16px;padding:0;font-size:10.5px;color:var(--text-dim);line-height:1.5">${p.steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
      ${hunts}
    </div>`;
  }).join("");

  const trig = d.triggers.filter((tg) => tg.count > 0);
  const trigHtml = trig.length
    ? `<div style="margin-top:12px"><div class="muted" style="font-size:11px;margin-bottom:5px">Hunt triggers (where investigation abstracts come from)</div><div style="display:flex;gap:6px;flex-wrap:wrap">${trig.map((tg) => `<span style="font-size:11px;background:var(--surface-2);border:1px solid var(--border);border-radius:6px;padding:2px 8px"><b>${tg.count}</b> ${esc(tg.name)}</span>`).join("")}</div></div>`
    : `<div class="muted" style="font-size:11px;margin-top:12px">Set a hunt's <code>TahitiTrigger</code> (and <code>TahitiPhase</code>) in the HUNT form to drive this funnel — by default hunts are placed by their status.</div>`;

  host.innerHTML = `<div style="display:flex;gap:10px;flex-wrap:wrap">${phaseCards}</div>
    ${trigHtml}
    <div class="muted" style="font-size:11px;margin-top:10px">${d.summary.totalHunts} hunt(s) across the TaHiTI lifecycle · ${d.summary.backlog} in the Initiate backlog · ${d.summary.withTrigger} with a recorded trigger.</div>`;
}
