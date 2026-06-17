/**
 * ransomware.ts — Ransomware-to-$ scenario simulator (/ransomware).
 * Pick an ATT&CK ransomware group → quantified SLE/ALE, the blast radius, kill-chain
 * coverage, and the controls that break the chain. Data from /api/ransomware/*.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Group { attackId: string; name: string; techniques: number }
interface Scenario {
  group: { attackId: string; name: string } | null; techniques: number; hasEncryption: boolean; hasInhibitRecovery: boolean;
  phases: { name: string; covered: boolean }[]; phasesCovered: number; phasesTotal: number;
  impacted: { assetId: number; name: string; value: number }[]; currency: string;
  primaryLoss: number; ransom: number; recovery: number; sle: number; aro: number; ale: number; residualSle: number;
  controls: { name: string; source: string; effect: string }[]; assumptions: string[];
}

let CUR = "USD";
function money(n: number): string {
  try { return new Intl.NumberFormat(undefined, { style: "currency", currency: CUR, maximumFractionDigits: 0 }).format(n); }
  catch { return "$" + Math.round(n).toLocaleString(); }
}

async function jget(url: string): Promise<any> { const r = await fetch(url); if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }

function render(d: Scenario): void {
  CUR = d.currency || "USD";
  const cut = d.sle > 0 ? Math.round((1 - d.residualSle / d.sle) * 100) : 0;
  $("rw-sub").innerHTML = d.group
    ? `Scenario: <b>${esc(d.group.name)}</b> (${esc(d.group.attackId)}) — ${d.techniques} ATT&CK techniques, ${d.phasesCovered}/${d.phasesTotal} kill-chain phases${d.hasEncryption ? " · <span style='color:#fca5a5'>uses data-encryption impact (T1486)</span>" : ""}.`
    : "No ransomware group resolved.";
  if (!d.impacted.length) {
    $("rw-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">No assets with a business value — set <b>BusinessValue</b> on your assets to quantify the impact.</div>`;
    return;
  }
  $("rw-body").innerHTML = `
    <div class="hero">
      <div class="card hcard sle"><div class="lbl">Single loss expectancy</div><div class="big">${money(d.sle)}</div><div class="note">if this ransomware event lands</div></div>
      <div class="card hcard ale"><div class="lbl">Annualized loss (ALE)</div><div class="big">${money(d.ale)}</div><div class="note">SLE × ARO ${d.aro}</div></div>
      <div class="card hcard res"><div class="lbl">Residual with controls</div><div class="big">${money(d.residualSle)}</div><div class="note">≈ ${cut}% lower with backups + segmentation</div></div>
    </div>

    <div class="hero">
      <div class="card hcard"><div class="lbl">Loss breakdown (SLE)</div>
        <div class="brk" style="margin-top:8px">
          <div class="r"><span>Primary loss (value at risk)</span><b>${money(d.primaryLoss)}</b></div>
          <div class="r"><span>Ransom demand (est.)</span><b>${money(d.ransom)}</b></div>
          <div class="r"><span>Recovery / incident response</span><b>${money(d.recovery)}</b></div>
          <div class="r tot"><span>Single loss expectancy</span><span>${money(d.sle)}</span></div>
        </div>
      </div>
      <div class="card hcard"><div class="lbl">Kill-chain coverage (${d.phasesCovered}/${d.phasesTotal})</div>
        <div class="phases">${d.phases.map((p) => `<span class="ph${p.covered ? " on" : ""}">${esc(p.name)}</span>`).join("")}</div>
        ${d.hasInhibitRecovery ? `<div class="note" style="margin-top:8px;color:#fca5a5">⚠️ Also inhibits recovery (T1490/T1489) — degrades backups/shadow copies.</div>` : ""}
      </div>
    </div>

    <h3>Blast radius — assets encrypted (${d.impacted.length})</h3>
    <table class="rw"><thead><tr><th>Asset</th><th style="text-align:right">Value at risk</th></tr></thead><tbody>${
      d.impacted.slice(0, 50).map((a) => `<tr><td>${esc(a.name)}</td><td class="v">${money(a.value)}</td></tr>`).join("")}</tbody></table>

    <h3>Controls that break the chain</h3>
    <div class="card">${d.controls.map((c) => `<div class="ctl"><b>${esc(c.name)}</b><span class="src">${esc(c.source)}</span><div class="muted" style="font-size:12px">${esc(c.effect)}</div></div>`).join("")}</div>

    <div class="assume"><b>Assumptions</b> (transparent model — tune to your org):<br>${d.assumptions.map(esc).join("<br>")}</div>`;
}

async function loadScenario(group?: string): Promise<void> {
  $("rw-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">Computing impact…</div>`;
  try { render(await jget(`/api/ransomware/scenario${group ? `?group=${encodeURIComponent(group)}` : ""}`)); }
  catch (e) { $("rw-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; }
}

document.addEventListener("DOMContentLoaded", async () => {
  const sel = $("rw-group") as HTMLSelectElement;
  try {
    const groups: Group[] = await jget("/api/ransomware/groups");
    sel.innerHTML = groups.map((g) => `<option value="${esc(g.attackId)}">${esc(g.name)} (${esc(g.attackId)}) · ${g.techniques} TTPs</option>`).join("");
  } catch { sel.innerHTML = `<option value="">(groups unavailable)</option>`; }
  sel.addEventListener("change", () => void loadScenario(sel.value));
  const q = new URLSearchParams(location.search).get("group");
  if (q) sel.value = q;
  void loadScenario(sel.value || undefined);
});
