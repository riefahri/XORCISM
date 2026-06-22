/**
 * cyber-risk-hunting.ts — client for /cyber-risk-hunting.
 * A worklist of "where could an adversary succeed?": fused exposures + over-scoped non-human
 * identities, each with a hunt hypothesis, plus an "Escalate into the loop" action that re-enters
 * the CROC Continuous Defense Loop so the pre-authorization policies fire on the finding.
 */
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
const gaugeColor = (n: number): string => n >= 70 ? "#b91c1c" : n >= 40 ? "#ca8a04" : "#3b82f6";

async function getJson(url: string): Promise<any> { const r = await fetch(url); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
function toast(m: string): void { const t = $("toast"); if (!t) return; t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2600); }

let data: any = null;
let hotOnly = false;

function tags(e: any): string {
  const t = (e.kev ? `<span class="tag t-kev">KEV</span>` : "") + (e.itw ? `<span class="tag t-itw">ITW</span>` : "") + (e.exploits ? `<span class="tag t-exp">${e.exploits} exploit${e.exploits === 1 ? "" : "s"}</span>` : "");
  const reach: Record<string, string> = { entry: `<span class="tag t-reach" style="background:#7f1d1d;color:#fecaca">entry point</span>`, jewel: `<span class="tag t-reach" style="background:#78350f;color:#fcd34d">crown jewel</span>`, choke: `<span class="tag t-reach" style="background:#3b2f63;color:#ddd6fe">choke point</span>`, onpath: `<span class="tag t-reach" style="background:#1e3a5f;color:#bfdbfe">on attack path</span>` };
  return t + (e.reach ? reach[e.reach] || "" : "");
}

function render(d: any): string {
  const s = d.summary || {};
  let exposures = (d.exposures || []) as any[];
  const agentic = (d.agentic || []) as any[];
  const attackPaths = (d.attackPaths || []) as any[];
  const chokepoints = (d.chokepoints || []) as any[];
  if (hotOnly) exposures = exposures.filter((e) => e.hot);
  return `
  <div class="cards">
    <div class="card"><div class="lbl">Actively attacked</div><div class="val" style="color:#f87171">${s.activelyAttacked || 0}</div><div class="foot">KEV / exploited / in-the-wild</div></div>
    <div class="card"><div class="lbl">Crown-jewel reachable</div><div class="val" style="color:#fbbf24">${s.crownReachable || 0}</div><div class="foot">touch a financially-valued asset</div></div>
    <div class="card"><div class="lbl">Reachable crown jewels</div><div class="val" style="color:#fb7185">${s.reachableJewels || 0}</div><div class="foot">${s.attackPaths || 0} path(s) from an entry point</div></div>
    <div class="card"><div class="lbl">Exposures on a path</div><div class="val" style="color:#f472b6">${s.onAttackPath || 0}</div><div class="foot">sit on an entry/jewel/choke/path asset</div></div>
    <div class="card"><div class="lbl">Over-scoped identities</div><div class="val" style="color:#c4b5fd">${s.overScopedIdentities || 0}</div><div class="foot">privileged non-human / agents</div></div>
  </div>
  <div class="sec">Exposure hunting worklist <span class="spacer"></span><label class="filters"><input type="checkbox" id="hot" ${hotOnly ? "checked" : ""}> actively-attacked only</label></div>
  <table class="t"><thead><tr><th>Priority</th><th>Exposure</th><th>Hunt hypothesis</th><th>Assets</th><th></th></tr></thead><tbody>
    ${exposures.map((e) => `<tr><td><span class="gauge" style="background:${gaugeColor(e.priority)}">${e.priority}</span></td><td><span class="mono">${esc(e.ref)}</span><div style="margin-top:3px">${tags(e)}</div><div class="why">${esc((e.factors || []).slice(0, 3).join(" · "))}</div></td><td class="hyp">${esc(e.hypothesis)}</td><td>${e.assets || 0}</td><td><button class="btn-sm2 esc" data-kind="exposure" data-ref="${esc(e.ref)}" data-pri="${e.priority}">Escalate ↻</button></td></tr>`).join("") || `<tr><td colspan="5" class="muted">No exposures match. ${hotOnly ? "Clear the filter, or" : ""} run exposure imports + CVE matching to populate the worklist.</td></tr>`}
  </tbody></table>
  <div class="sec">Over-scoped non-human identities — constrain before they are abused</div>
  <table class="t"><thead><tr><th>Identity</th><th>Why it is a risk</th><th>Hunt hypothesis</th><th></th></tr></thead><tbody>
    ${agentic.map((a) => `<tr><td><span class="nm">${esc(a.name)}</span><div class="muted" style="font-size:11px">${esc(a.privilege || a.type || "")}</div></td><td><span class="why">${esc((a.why || []).join(" · "))}</span></td><td class="hyp">${esc(a.hypothesis)}</td><td><button class="btn-sm2 esc" data-kind="identity" data-ref="${esc(a.name)}" data-pri="80">Constrain ↻</button></td></tr>`).join("") || `<tr><td colspan="4" class="muted">No over-scoped non-human identities found.</td></tr>`}
  </tbody></table>
  <div class="sec">Attack paths to crown jewels <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none">internet entry → high-value asset</span></div>
  <table class="t"><thead><tr><th>Entry point</th><th></th><th>Crown jewel</th><th>Hops</th><th>Cost</th></tr></thead><tbody>
    ${attackPaths.map((p) => `<tr><td class="nm">${esc(p.entry)}</td><td class="muted">→</td><td><span class="nm" style="color:#fbbf24">${esc(p.jewel)}</span></td><td>${p.hops}</td><td class="muted">${p.cost}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">No reachable path from an internet entry point to a valued asset (good — or add asset IPs / business values).</td></tr>`}
  </tbody></table>
  <div class="sec">Choke points — break the most paths</div>
  <table class="t"><thead><tr><th>Asset</th><th>On paths</th><th>Hunt hypothesis</th><th></th></tr></thead><tbody>
    ${chokepoints.map((c) => `<tr><td class="nm">${esc(c.label)}</td><td><span class="gauge" style="width:30px;height:30px;font-size:12px;background:#7f1d1d">${c.paths}</span></td><td class="hyp">${esc(c.hypothesis)}</td><td><button class="btn-sm2 esc" data-kind="exposure" data-ref="choke point: ${esc(c.label)}" data-pri="75">Escalate ↻</button></td></tr>`).join("") || `<tr><td colspan="4" class="muted">No choke points identified.</td></tr>`}
  </tbody></table>`;
}

function wire(): void {
  $("hot")?.addEventListener("change", (e) => { hotOnly = (e.target as HTMLInputElement).checked; draw(); });
  document.querySelectorAll<HTMLButtonElement>(".esc").forEach((b) => {
    b.addEventListener("click", async () => {
      const kind = b.dataset.kind, ref = b.dataset.ref, priority = Number(b.dataset.pri) || 0;
      b.disabled = true;
      try {
        const r = await (await fetch("/api/cyber-risk-hunting/escalate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ kind, ref, priority }) })).json();
        toast(r.ok ? `Escalated into the loop → ${kind === "identity" ? "constrain" : "exposure"} policies fire` : "Failed");
        b.textContent = "Escalated ✓";
      } catch { toast("Failed"); b.disabled = false; }
    });
  });
}

function draw(): void { const body = $("body"); if (body && data) { body.innerHTML = render(data); wire(); } }

async function load(): Promise<void> {
  const body = $("body"); if (!body) return;
  try { data = await getJson("/api/cyber-risk-hunting"); draw(); }
  catch (e) { body.innerHTML = `<div class="muted" style="padding:24px;text-align:center">Failed to load: ${esc((e as Error).message)}</div>`; }
}

document.addEventListener("DOMContentLoaded", () => { void load(); });
