/** cloud-security.ts — Cloud Security Management cockpit (/cloud-security). Cloud asset inventory,
 * exposure/misconfig worklist, provider breakdown + CSA CCM reference, from /api/cloud-security. */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.replace(`{${k}}`, String(v)), t(key));

interface Row { id: number; name: string; provider: string; criticality: string; publicFacing: boolean; encrypted: boolean; pii: boolean; thirdParty: boolean; owner: boolean; vulns: number; criticalVulns: number; kev: number; tags: string[]; flags: string[]; score: number; hostname: string; ip: string; }
interface Data { rows: Row[]; worklist: { id: number; name: string; provider: string; severity: string; reason: string }[]; summary: any; }

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="cs-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const pcls = (p: string): string => `p-${["AWS", "Azure", "GCP", "OCI", "SaaS", "Cloud"].includes(p) ? p : "Cloud"}`;
const scls = (s: string): string => `sv-${["Critical", "High", "Medium", "Low"].includes(s) ? s : "Low"}`;

function rowHtml(r: Row): string {
  return `<tr>
    <td><a class="nm" href="/?db=XORCISM&table=ASSET&editCol=AssetID&editVal=${r.id}" style="color:var(--accent,#7c83fd);text-decoration:none" title="${t("cs.editAsset")}">${esc(r.name)}</a>${r.hostname || r.ip ? `<div class="muted" style="font-size:11px">${esc(r.hostname || r.ip)}</div>` : ""}</td>
    <td><span class="prov ${pcls(r.provider)}">${esc(r.provider)}</span></td>
    <td>${esc(r.criticality || "—")}</td>
    <td>${r.publicFacing ? `<span class="tag t-pub">${t("cs.public")}</span>` : `<span class='muted'>${t("cs.internal")}</span>`}</td>
    <td>${r.encrypted ? `<span class="tag t-enc">${t("cs.enc")}</span>` : `<span class="tag t-unenc">${t("cs.noEnc")}</span>`}${r.pii ? ` <span class="tag t-pii">PII</span>` : ""}</td>
    <td>${r.vulns ? `${r.vulns}${r.criticalVulns ? ` <span class="muted" style="font-size:11px">(${r.criticalVulns}C)</span>` : ""}${r.kev ? ` <span class="tag t-kev">${r.kev} KEV</span>` : ""}` : "<span class='muted'>0</span>"}</td>
    <td>${r.owner ? "✓" : `<span class='tag t-unenc'>${t("cs.ownerNone")}</span>`}</td>
  </tr>`;
}

function load(): void {
  fetch("/api/cloud-security").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => {
    const s = d.summary;
    if (!d.rows.length) {
      $("cs-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${fmt("cs.emptyA", { n: s.ccmControls, m: s.ccmDomains })}<br>
        ${t("cs.emptyB")}</div>`;
      return;
    }
    const cards = [
      card(t("cs.cAssets"), String(s.cloudAssets), fmt("cs.cAssetsFoot", { n: s.thirdParty })),
      card(t("cs.cPublic"), String(s.publicFacing), t("cs.cPublicFoot"), s.publicFacing ? "#fbbf24" : "#34d399"),
      card(t("cs.cUnenc"), String(s.unencrypted), t("cs.cUnencFoot"), s.unencrypted ? "#f87171" : "#34d399"),
      card(t("cs.cKev"), String(s.kev), t("cs.cKevFoot"), s.kev ? "#f87171" : "#34d399"),
      card(t("cs.cCrit"), String(s.criticalAssets), fmt("cs.cCritFoot", { n: s.withCriticalVulns })),
      card("CSA CCM", String(s.ccmControls), fmt("cs.cCcmFoot", { n: s.ccmDomains }), "#60a5fa"),
    ].join("");
    const byProv = Object.entries(s.byProvider || {}).sort((a: any, b: any) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="prov ${pcls(k)}">${esc(k)}</span> <b>${n}</b></span>`).join("");
    const work = d.worklist.length
      ? `<ul class="worklist">${d.worklist.slice(0, 40).map((w) => `<li><span class="sev ${scls(w.severity)}">${esc(w.severity)}</span> <b style="color:#e2e8f0">${esc(w.name)}</b> <span class="prov ${pcls(w.provider)}">${esc(w.provider)}</span> — ${esc(w.reason)}</li>`).join("")}</ul>`
      : `<div class="muted" style="padding:8px 0">${t("cs.workNone")}</div>`;
    const table = `<table class="cs"><thead><tr><th>${t("cs.thAsset")}</th><th>${t("cs.thProvider")}</th><th>${t("cs.thCriticality")}</th><th>${t("cs.thExposure")}</th><th>${t("cs.thEncryption")}</th><th>${t("cs.thVulns")}</th><th>${t("cs.thOwner")}</th></tr></thead><tbody>${d.rows.slice(0, 200).map(rowHtml).join("")}</tbody></table>`;
    $("cs-body").innerHTML = `<div class="cs-cards">${cards}</div>
      <div class="cs-section">${t("cs.secProvider")}</div><div class="breakdown">${byProv || "<span class='muted'>—</span>"}</div>
      <div class="cs-section">${t("cs.secWorklist")} (${d.worklist.length})</div>${work}
      <div class="cs-section">${t("cs.secAssets")} (${d.rows.length})</div>${table}`;
  }).catch((e) => { $("cs-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}
// ── AWS compliance checker ──────────────────────────────────────────────────────
interface Finding { Provider: string; Account: string; CheckID: string; Title: string; Service: string; Severity: string; Status: string; Resource: string; Detail: string; Remediation: string; Benchmark: string; }
interface Compliance { findings: Finding[]; summary: { pass: number; fail: number; accounts: number; score: number | null; byService: Record<string, { pass: number; fail: number }>; bySeverity: Record<string, number>; scanDate: string | null }; }

const SAMPLE_SNAPSHOT = {
  account: "123456789012",
  password_policy: { MinimumPasswordLength: 8, RequireSymbols: false, RequireNumbers: true, RequireUppercaseCharacters: true, RequireLowercaseCharacters: true, MaxPasswordAge: 0, PasswordReusePrevention: 0 },
  root_account: { mfa_enabled: false, access_keys: 1 },
  users: [
    { user: "alice", console_access: true, mfa: true, access_keys: [{ active: true, last_rotated_days: 40, last_used_days: 3 }], password_last_used_days: 2 },
    { user: "bob", console_access: true, mfa: false, access_keys: [{ active: true, last_rotated_days: 210, last_used_days: 140 }], password_last_used_days: 150 },
    { user: "svc-deploy", console_access: false, mfa: false, access_keys: [{ active: true, last_rotated_days: 365, last_used_days: 1 }] },
  ],
  cloudtrail: { trails: [{ name: "org-trail", is_multi_region: true, is_logging: true, log_file_validation: false, cloudwatch_logs: false, kms_encrypted: false }] },
  config: { recorders: [{ name: "default", recording: true, all_regions: false }] },
};
const SAMPLE_AZURE = {
  tenant: "contoso.onmicrosoft.com",
  security_defaults_enabled: false, legacy_auth_blocked: false,
  password_policy: { min_length: 8, complexity: true, expiry_days: 0 },
  users: [
    { user: "alice@contoso.com", admin: true, mfa: true },
    { user: "bob@contoso.com", admin: true, mfa: false },
    { user: "carol@contoso.com", mfa: false, last_sign_in_days: 140 },
  ],
};
const SAMPLE_GCP = {
  project: "my-gcp-project",
  users: [
    { user: "ops@example.com", admin: true, two_step: false },
    { user: "dev@example.com", two_step: true, last_login_days: 5 },
  ],
  service_accounts: [{ name: "ci-deployer", user_managed_keys: 2, oldest_key_age_days: 400 }],
  primitive_owner_bindings: 3,
};
type Provider = "aws" | "azure" | "gcp";
const SAMPLES: Record<Provider, unknown> = { aws: SAMPLE_SNAPSHOT, azure: SAMPLE_AZURE, gcp: SAMPLE_GCP };
const TITLES: Record<Provider, string> = { aws: "AWS compliance check (CIS AWS Foundations)", azure: "Azure compliance check (CIS Microsoft Azure Foundations)", gcp: "GCP compliance check (CIS Google Cloud Foundations)" };
let checkProvider: Provider = "aws";

function renderCompliance(d: Compliance): void {
  const host = $("cs-compliance");
  if (!d.findings.length) { host.innerHTML = ""; return; }
  const s = d.summary;
  const scoreColor = (s.score ?? 0) >= 80 ? "#34d399" : (s.score ?? 0) >= 50 ? "#fbbf24" : "#f87171";
  const sevOrder = ["Critical", "High", "Medium", "Low", "Info"];
  const sevChips = sevOrder.filter((k) => s.bySeverity[k]).map((k) => `<span class="sev ${scls(k)}">${k}: ${s.bySeverity[k]}</span>`).join(" ");
  const fails = d.findings.filter((f) => f.Status === "fail");
  const rows = [...fails, ...d.findings.filter((f) => f.Status === "pass")].slice(0, 200).map((f) =>
    `<tr>
      <td><span class="pf ${f.Status}">${f.Status === "pass" ? "PASS" : "FAIL"}</span></td>
      <td><span class="chk-cid">${esc(f.CheckID)}</span></td>
      <td>${esc(f.Title)}<div class="muted" style="font-size:11px">${esc(f.Detail)}</div></td>
      <td>${esc(f.Service)}</td>
      <td>${f.Status === "fail" ? `<span class="sev ${scls(f.Severity)}">${esc(f.Severity)}</span>` : "—"}</td>
      <td>${esc(f.Resource)}</td>
    </tr>`).join("");
  host.innerHTML = `
    <div class="cs-section">AWS compliance check ${s.accounts ? `· ${s.accounts} account(s)` : ""} ${s.scanDate ? `· ${esc(String(s.scanDate).slice(0, 16).replace("T", " "))}` : ""}</div>
    <div class="cs-cards">
      <div class="cs-card"><div class="lbl">Compliance score</div><div class="val chk-score"><span class="pct" style="color:${scoreColor}">${s.score ?? "—"}</span><span class="muted" style="font-size:13px">/100</span></div><div class="foot">${s.pass} pass · ${s.fail} fail</div></div>
      <div class="cs-card"><div class="lbl">Failing checks</div><div class="val" style="color:${s.fail ? "#f87171" : "#34d399"}">${s.fail}</div><div class="foot">${sevChips || "none"}</div></div>
    </div>
    <table class="chk"><thead><tr><th>Status</th><th>Check</th><th>Title</th><th>Service</th><th>Severity</th><th>Resource</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function loadCompliance(): void {
  fetch("/api/cloud-security/compliance").then((r) => r.ok ? r.json() : null).then((d: Compliance | null) => { if (d) renderCompliance(d); }).catch(() => { /* none yet */ });
}

function openCheck(provider: Provider): void {
  checkProvider = provider;
  const title = document.getElementById("cs-chk-title"); if (title) title.textContent = TITLES[provider];
  ($("cs-chk-json") as HTMLTextAreaElement).value = "";
  $("cs-chk-err").textContent = "";
  $("cs-chk-modal").classList.add("open");
}
async function runCheck(): Promise<void> {
  const raw = ($("cs-chk-json") as HTMLTextAreaElement).value.trim();
  const err = $("cs-chk-err"); err.textContent = "";
  let snapshot: unknown;
  try { snapshot = JSON.parse(raw); } catch { err.textContent = "Invalid JSON."; return; }
  const btn = $("cs-chk-run") as HTMLButtonElement; btn.disabled = true; err.textContent = "Running…";
  try {
    const r = await fetch(`/api/cloud-security/${checkProvider}-check`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ snapshot }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    $("cs-chk-modal").classList.remove("open");
    loadCompliance();
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n(); load(); loadCompliance();
  $("cs-run-check").addEventListener("click", () => openCheck("aws"));
  const azBtn = document.getElementById("cs-run-check-azure"); if (azBtn) azBtn.addEventListener("click", () => openCheck("azure"));
  const gcpBtn = document.getElementById("cs-run-check-gcp"); if (gcpBtn) gcpBtn.addEventListener("click", () => openCheck("gcp"));
  $("cs-chk-cancel").addEventListener("click", () => $("cs-chk-modal").classList.remove("open"));
  $("cs-chk-modal").addEventListener("click", (e) => { if (e.target === $("cs-chk-modal")) $("cs-chk-modal").classList.remove("open"); });
  $("cs-chk-sample").addEventListener("click", (e) => { e.preventDefault(); ($("cs-chk-json") as HTMLTextAreaElement).value = JSON.stringify(SAMPLES[checkProvider], null, 2); });
  $("cs-chk-run").addEventListener("click", () => void runCheck());
});
