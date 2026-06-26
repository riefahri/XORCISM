/**
 * purple-team.ts — Detection-coverage view (/purple-team?run=<id>).
 * Shows the ATT&CK detection coverage of an attack-chain run against the Sigma
 * library (gaps first), and generates a Sigma rule for any gap. English-only viewer.
 */
import { initI18n, t } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Tech { id: string; name: string; connectors: string[]; rules: number; sampleRules: string[]; covered: boolean }
interface Coverage { run: { ChainRunID: number; PlaybookName: string; SeedTarget: string } | null; techniques: Tech[]; stats: { total: number; covered: number; gaps: number; coveragePct: number }; }

const params = new URLSearchParams(location.search);
const runId = Number(params.get("run"));
const engagementId = Number(params.get("engagement"));
function attackUrl(id: string): string { return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`; }
function pctColor(p: number): string { return p >= 70 ? "#22c55e" : p >= 40 ? "#f59e0b" : "#ef4444"; }

function row(tech: Tech): string {
  const status = tech.covered
    ? `<span class="ok">${fmt("pt.coveredRules", { n: tech.rules })}</span>${tech.sampleRules.length ? `<div class="rules">${tech.sampleRules.map(esc).join(" · ")}</div>` : ""}`
    : `<span class="gap">${t("pt.gap")}</span> <button class="btn btn-ghost btn-sm genbtn" data-id="${esc(tech.id)}" data-name="${esc(tech.name)}">${t("pt.genSigma")}</button><pre class="sigma" id="sig-${esc(tech.id)}" style="display:none"></pre>`;
  return `<tr>
    <td class="tid"><a href="${attackUrl(tech.id)}" target="_blank" rel="noopener noreferrer">${esc(tech.id)}</a></td>
    <td>${esc(tech.name)}</td>
    <td>${tech.connectors.map((c) => `<span class="tool">${esc(c)}</span>`).join("")}</td>
    <td>${status}</td>
  </tr>`;
}

async function genSigma(btn: HTMLButtonElement): Promise<void> {
  const id = btn.dataset.id!, name = btn.dataset.name!;
  const pre = $(`sig-${id}`); btn.disabled = true; pre.style.display = "block"; pre.textContent = t("pt.generating");
  try {
    const r = await fetch("/api/purple/sigma-suggest", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ techId: id, techName: name }) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    pre.textContent = (d.offline ? t("pt.skeleton") + "\n" : fmt("pt.generatedBy", { model: d.model }) + "\n") + d.yaml;
  } catch (e) { pre.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

async function load(): Promise<void> {
  if (Number.isFinite(engagementId) && engagementId > 0) ($("pt-back") as HTMLAnchorElement).href = `/pentest?id=${engagementId}`;
  let d: Coverage;
  try { const r = await fetch(`/api/purple/chain/${runId}`); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("pt-results").innerHTML = `<div class="pt-empty">⚠️ ${esc(e)}</div>`; return; }
  if (d.run) $("pt-run").innerHTML = fmt("pt.runSummary", { name: esc(d.run.PlaybookName), target: esc(d.run.SeedTarget) });
  if (!d.techniques.length) { $("pt-results").innerHTML = `<div class="pt-empty">${t("pt.noTech")}</div>`; return; }
  const st = d.stats;
  $("pt-gauge").style.display = "flex";
  $("pt-pct").textContent = `${st.coveragePct}%`; ($("pt-pct") as HTMLElement).style.color = pctColor(st.coveragePct);
  ($("pt-bar") as HTMLElement).style.width = `${st.coveragePct}%`; ($("pt-bar") as HTMLElement).style.background = pctColor(st.coveragePct);
  $("pt-gmeta").textContent = fmt("pt.gmeta", { covered: st.covered, total: st.total, gaps: st.gaps });
  $("pt-results").innerHTML = `<table class="pt"><thead><tr><th>${t("pt.thAttack")}</th><th>${t("pt.thTechnique")}</th><th>${t("pt.thExercised")}</th><th>${t("pt.thDetection")}</th></tr></thead><tbody>${d.techniques.map(row).join("")}</tbody></table>`;
  $("pt-results").querySelectorAll("button.genbtn").forEach((b) => b.addEventListener("click", () => void genSigma(b as HTMLButtonElement)));
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); if (!Number.isFinite(runId) || runId <= 0) { $("pt-results").innerHTML = `<div class="pt-empty">${t("pt.noRun")}</div>`; return; } void load(); });
