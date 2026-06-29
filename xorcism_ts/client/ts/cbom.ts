/**
 * cbom.ts — Cryptographic Bill of Materials (/cbom).
 * Crypto-asset inventory + quantum-readiness rollup + CycloneDX 1.6 CBOM import, from /api/cbom.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Row { id: number; name: string; assetType: string; primitive: string; algorithm: string; keySize: number | null; curve: string; nistLevel: number | null; quantumSafe: boolean | null; deprecated: boolean; protocol: string; certSubject: string; certNotAfter: string; asset: string | null; assetId: number | null; source: string; }
interface Inv {
  rows: Row[];
  summary: { total: number; quantumSafe: number; quantumVulnerable: number; unknown: number; deprecated: number; certificates: number; protocols: number; withAsset: number; quantumReadiness: number; byPrimitive: { key: string; n: number }[]; byAlgorithm: { key: string; n: number }[] };
  worklist: { id: number; name: string; algorithm: string; asset: string | null; severity: string; reason: string }[];
}

const scoreColor = (n: number): string => (n >= 80 ? "#10b981" : n >= 50 ? "#fbbf24" : n >= 25 ? "#fb923c" : "#ef4444");
function card(lbl: string, val: string, foot: string, color?: string, cls = "cb-card"): string {
  return `<div class="${cls}"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}
const qsBadge = (q: boolean | null): string => q === true ? `<span class="qs safe">quantum-safe</span>` : q === false ? `<span class="qs vuln">quantum-vulnerable</span>` : `<span class="qs unk">unclassified</span>`;

function bars(items: { key: string; n: number }[]): string {
  const max = items.reduce((m, x) => Math.max(m, x.n), 1);
  return `<div class="bars">${items.map((x) => `<div class="brow"><span class="k">${esc(x.key)}</span><span class="bar"><i style="width:${Math.round((x.n / max) * 100)}%"></i></span><span class="muted">${x.n}</span></div>`).join("")}</div>`;
}

async function doImport(btn: HTMLButtonElement): Promise<void> {
  const ta = document.getElementById("cb-json") as HTMLTextAreaElement;
  const txt = ta.value.trim();
  if (!txt) { return; }
  const stat = $("cb-impstat"); btn.disabled = true; stat.textContent = "Importing…";
  try {
    const r = await fetch("/api/cbom/import", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cbom: txt }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    stat.innerHTML = `✓ imported <b>${d.imported}</b> crypto-asset(s) — ${d.quantumVulnerable} quantum-vulnerable`;
    await load();
  } catch (e) { stat.innerHTML = `⚠️ ${esc(e)}`; btn.disabled = false; }
}

async function seedDemo(btn: HTMLButtonElement): Promise<void> {
  btn.disabled = true; btn.textContent = "Seeding…";
  try { const r = await fetch("/api/cbom/seed", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }); if (r.ok) { await load(); return; } } catch { /* */ }
  btn.disabled = false; btn.textContent = "Seed demo CBOM";
}

async function load(): Promise<void> {
  let d: Inv;
  try { const r = await fetch("/api/cbom"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("cb-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  const cards = [
    card("Quantum readiness", `${s.quantumReadiness}%`, `${s.quantumSafe}/${s.quantumSafe + s.quantumVulnerable} classified safe`, scoreColor(s.quantumReadiness), "cb-card cb-score"),
    card("Crypto-assets", String(s.total), `${s.withAsset} linked to an asset`),
    card("Quantum-vulnerable", String(s.quantumVulnerable), "classical public-key (RSA/ECC/DH)", s.quantumVulnerable ? "#ef4444" : "#34d399"),
    card("Deprecated/broken", String(s.deprecated), "MD5/SHA-1/DES/RC4…", s.deprecated ? "#fb923c" : "#34d399"),
    card("Certificates", String(s.certificates), `${s.protocols} protocol(s)`),
  ].join("");

  const imp = `<div class="imp">
      <div style="font-size:12px;color:#94a3b8;margin-bottom:5px">Paste a CycloneDX 1.6 CBOM (or a <code>{"cryptoAssets":[…]}</code> / array) to import:</div>
      <textarea id="cb-json" placeholder='{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"cryptographic-asset","name":"RSA-2048","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"pke","parameterSetIdentifier":2048}}}]}'></textarea>
      <button class="cb-go" id="cb-import">Import CBOM</button>
      ${s.total === 0 ? `<button class="cb-go alt" id="cb-seed" style="margin-left:8px">Seed demo CBOM</button>` : ""}
      <span id="cb-impstat" class="muted" style="font-size:12px;margin-left:10px"></span>
    </div>`;

  const work = d.worklist.length
    ? `<ul class="worklist">${d.worklist.map((w) => `<li><span class="sev-${esc(w.severity)}">${esc(w.severity)}</span> · <b style="color:#e2e8f0">${esc(w.name)}</b> <span class="scode">${esc(w.algorithm)}</span> — ${esc(w.reason)}${w.asset ? ` <span class="muted">· ${esc(w.asset)}</span>` : ""}</li>`).join("")}</ul>`
    : `<div class="muted" style="padding:8px 0">No quantum-vulnerable or deprecated cryptography — or nothing imported yet.</div>`;

  const table = d.rows.length ? `<table class="cb"><thead><tr><th>Name</th><th>Type</th><th>Algorithm</th><th>Key</th><th>Quantum</th><th>Asset</th></tr></thead><tbody>${d.rows.map((r) => `<tr>
      <td><b style="color:#e2e8f0">${esc(r.name)}</b>${r.certSubject ? `<div class="scode">${esc(r.certSubject)}${r.certNotAfter ? ` · exp ${esc(r.certNotAfter)}` : ""}</div>` : ""}</td>
      <td><span class="muted">${esc(r.assetType)}${r.primitive ? ` · ${esc(r.primitive)}` : ""}</span></td>
      <td>${esc(r.algorithm)}${r.protocol ? ` <span class="muted">${esc(r.protocol)}</span>` : ""}</td>
      <td>${r.keySize != null ? esc(r.keySize) : (r.curve ? esc(r.curve) : "—")}${r.nistLevel ? ` <span class="muted">L${r.nistLevel}</span>` : ""}</td>
      <td>${qsBadge(r.quantumSafe)}${r.deprecated ? `<span class="dep">deprecated</span>` : ""}</td>
      <td><span class="muted">${esc(r.asset || "—")}</span></td>
    </tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:12px 0">No cryptographic assets yet — import a CBOM above.</div>`;

  $("cb-body").innerHTML = `<div class="cb-cards">${cards}</div>${imp}
    ${s.total ? `<div class="cb-section">By primitive</div>${bars(s.byPrimitive)}
    <div class="cb-section">By algorithm</div>${bars(s.byAlgorithm)}` : ""}
    <div class="cb-section">Quantum-readiness worklist (${d.worklist.length})</div>${work}
    <div class="cb-section">Cryptographic assets (${d.rows.length})</div>${table}
    <div class="legend">Quantum classification is deterministic: Shor breaks classical public-key (RSA/ECC/DH/DSA) → vulnerable; NIST PQC (ML-KEM, ML-DSA, SLH-DSA) + hash-based sigs → safe; AES-256 / SHA-384+/SHA-3 → safe; AES-128 / SHA-256 are Grover-weakened.</div>`;

  const ib = document.getElementById("cb-import") as HTMLButtonElement | null; if (ib) ib.onclick = () => void doImport(ib);
  const sb = document.getElementById("cb-seed") as HTMLButtonElement | null; if (sb) sb.onclick = () => void seedDemo(sb);
}

document.addEventListener("DOMContentLoaded", () => { void load(); });
