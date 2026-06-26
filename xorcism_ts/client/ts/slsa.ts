/** slsa.ts — client for the SLSA supply-chain level tracker (/slsa). Level distribution + per-artifact
 *  build-integrity posture + level-up worklist from /api/slsa. */
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface Art { id: number; project: string; repo: string; platform: string; level: number; gap: string; provenance: boolean; signed: boolean; hosted: boolean; isolated: boolean; hermetic: boolean; verified: boolean }
interface Data { summary: { artifacts: number; avgLevel: number; atL2plus: number; atL0: number; unsigned: number }; dist: Record<string, number>; artifacts: Art[]; worklist: Art[] }

function card(lbl: string, val: string | number, foot: string, color?: string): string {
  return `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}
const yn = (b: boolean): string => b ? `<span class="y">✓</span>` : `<span class="n">—</span>`;

function render(d: Data): void {
  const body = $("body"); if (!body) return;
  const s = d.summary;
  const cards = [
    card("Artifacts", s.artifacts, "tracked"),
    card("Avg SLSA level", s.avgLevel, "0 → 3"),
    card("At L2+", s.atL2plus, "signed + hosted", s.atL2plus === s.artifacts && s.artifacts ? "#34d399" : undefined),
    card("At L0", s.atL0, "no provenance", s.atL0 ? "#f87171" : "#34d399"),
    card("Unsigned provenance", s.unsigned, "not L2-ready", s.unsigned ? "#fbbf24" : "#34d399"),
  ].join("");
  const distBar = ["L0", "L1", "L2", "L3"].map((l) => `<span class="lvl lvl-${l[1]}" style="margin-right:6px">${l}: ${d.dist[l] || 0}</span>`).join("");
  const arow = (a: Art): string => `<tr>
    <td><span class="lvl lvl-${a.level}">L${a.level}</span></td>
    <td><span class="nm">${esc(a.project)}</span><div class="muted" style="font-size:11px">${esc(a.repo)} · ${esc(a.platform)}</div></td>
    <td style="text-align:center">${yn(a.provenance)}</td><td style="text-align:center">${yn(a.signed)}</td>
    <td style="text-align:center">${yn(a.hosted)}</td><td style="text-align:center">${yn(a.isolated)}</td><td style="text-align:center">${yn(a.hermetic)}</td>
    <td class="muted" style="font-size:12px">${esc(a.gap)}</td>
  </tr>`;
  const head = `<thead><tr><th>Level</th><th>Artifact</th><th>Prov.</th><th>Signed</th><th>Hosted</th><th>Isolated</th><th>Hermetic</th><th>Next level</th></tr></thead>`;
  body.innerHTML = `<div class="cards">${cards}</div>
    <div class="sec">Level distribution</div><div style="margin-bottom:6px">${distBar}</div>
    <div class="sec">Level-up worklist (lowest first)</div>
    <table class="t">${head}<tbody>${d.worklist.map(arow).join("") || `<tr><td colspan="8" class="muted" style="padding:14px;text-align:center">✓ All artifacts at SLSA Build L3.</td></tr>`}</tbody></table>
    <div class="sec">All artifacts (${d.artifacts.length})</div>
    <table class="t">${head}<tbody>${d.artifacts.map(arow).join("") || `<tr><td colspan="8" class="muted" style="padding:14px;text-align:center">No artifacts. Add them in the <a href="/?table=SLSAARTIFACT">SLSAARTIFACT</a> table.</td></tr>`}</tbody></table>`;
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/slsa"); const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); render(d); }
  catch (e) { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}
document.addEventListener("DOMContentLoaded", () => { void load(); });
