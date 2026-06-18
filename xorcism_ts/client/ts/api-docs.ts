/**
 * api-docs.ts — self-contained renderer for the XORCISM OpenAPI spec (/api-docs).
 * Fetches /api/v1/openapi.json and renders endpoints grouped by tag, with a curl example.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Param { name: string; in: string; required?: boolean; description?: string; schema?: { type?: string; default?: unknown } }
interface SchemaObj { type?: string; required?: string[]; properties?: Record<string, { type?: string }> }
interface Op { tags?: string[]; summary?: string; parameters?: Param[]; security?: unknown[]; requestBody?: { content?: Record<string, { schema?: { $ref?: string } }> } }
interface Spec {
  info: { title: string; version: string; description?: string };
  servers?: { url: string }[];
  tags?: { name: string; description?: string }[];
  paths: Record<string, Record<string, Op>>;
  components?: { schemas?: Record<string, SchemaObj> };
}

const refName = (ref?: string): string => (ref ? ref.split("/").pop() || "" : "");
const exampleVal = (t?: string): unknown => (t === "number" || t === "integer" ? 0 : t === "boolean" ? false : "string");
// Required API-key scope per operation (mirrors the gate() checks in routes/v1.ts).
const SCOPE_MAP: Record<string, string> = {
  "GET /assets": "assets:read", "GET /assets/{id}": "assets:read", "PATCH /assets/{id}": "assets:write",
  "GET /incidents": "incidents:read", "POST /incidents": "incidents:write", "PATCH /incidents/{id}": "incidents:write",
  "GET /incident-sla": "incidents:read", "GET /exposures": "exposure:read", "GET /risk": "risk:read",
};

function opHtml(base: string, path: string, method: string, op: Op, schemas: Record<string, SchemaObj>): string {
  const m = method.toLowerCase();
  const params = op.parameters || [];
  const paramRows = params.length
    ? `<table><thead><tr><th>Param</th><th>In</th><th>Type</th><th>Req</th><th>Description</th></tr></thead><tbody>${
        params.map((p) => `<tr><td class="path">${esc(p.name)}</td><td>${esc(p.in)}</td><td>${esc(p.schema?.type || "")}</td><td>${p.required ? "yes" : "no"}</td><td class="muted">${esc(p.description || "")}</td></tr>`).join("")
      }</tbody></table>`
    : (op.requestBody ? "" : `<div class="muted" style="font-size:12px;margin:6px 0">No parameters.</div>`);

  // Request body (POST/PATCH)
  let bodyRows = ""; let dataArg = "";
  const bref = op.requestBody?.content?.["application/json"]?.schema?.$ref;
  if (bref) {
    const sc = schemas[refName(bref)];
    const props = sc?.properties || {};
    const reqd = new Set(sc?.required || []);
    bodyRows = `<div class="muted" style="font-size:12px;margin:8px 0 2px">Body — application/json:</div>
      <table><thead><tr><th>Field</th><th>Type</th><th>Req</th></tr></thead><tbody>${
        Object.entries(props).map(([k, v]) => `<tr><td class="path">${esc(k)}</td><td>${esc(v.type || "")}</td><td>${reqd.has(k) ? "yes" : "no"}</td></tr>`).join("")
      }</tbody></table>`;
    const ex: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(props)) ex[k] = exampleVal(v.type);
    dataArg = ` \\\n  -H "Content-Type: application/json" \\\n  -d '${JSON.stringify(ex)}'`;
  }

  const isPublic = Array.isArray(op.security) && op.security.length === 0;
  const qs = params.filter((p) => p.in === "query").map((p) => `${p.name}=${p.schema?.default ?? ""}`).join("&");
  const url = `${location.origin}${base}${path.replace("{id}", "1")}${qs ? "?" + qs : ""}`;
  const authH = isPublic ? "" : ` \\\n  -H "Authorization: Bearer $XORCISM_API_KEY"`;
  const curl = `curl -s${m !== "get" ? ` -X ${method.toUpperCase()}` : ""} "${url}"${authH}${dataArg}`;
  const scope = SCOPE_MAP[`${method.toUpperCase()} ${path}`];
  const tag = isPublic ? "" : (scope ? ` <span class="scope">${esc(scope)}</span>` : ' <span class="lock">🔒</span>');
  return `<details class="op">
    <summary><span class="m m-${m}">${method.toUpperCase()}</span>
      <span class="path">${esc(base)}${esc(path)}</span>
      <span class="sum">${esc(op.summary || "")}${tag}</span></summary>
    <div class="body">${paramRows}${bodyRows}<pre class="curl">${esc(curl)}</pre></div>
  </details>`;
}

async function load(): Promise<void> {
  let spec: Spec;
  try { const r = await fetch("/api/v1/openapi.json"); if (!r.ok) throw new Error(`HTTP ${r.status}`); spec = await r.json(); }
  catch (e) { $("ad-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const base = spec.servers?.[0]?.url || "/api/v1";

  $("ad-head").innerHTML = `<h1>${esc(spec.info.title)} <span class="muted" style="font-size:14px">v${esc(spec.info.version)}</span></h1>
    <div class="ad-sub">${esc(spec.info.description || "")}</div>
    <div class="ad-auth"><b>Authentication.</b> Create a key on the <a href="/api-keys">API keys</a> page, then send it as
      <code>Authorization: Bearer xor_…</code> or <code>X-API-Key: xor_…</code>. Base URL: <code>${esc(base)}</code>.
      <div style="margin-top:6px" class="muted">Example: <code>export XORCISM_API_KEY=xor_…</code> then use the curl snippets below.</div>
    </div>`;

  // group by tag, preserving spec.tags order
  const schemas = spec.components?.schemas || {};
  const order = (spec.tags || []).map((t) => t.name);
  const groups = new Map<string, string[]>();
  for (const [path, ops] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(ops)) {
      const tag = op.tags?.[0] || "Other";
      if (!groups.has(tag)) groups.set(tag, []);
      groups.get(tag)!.push(opHtml(base, path, method, op, schemas));
    }
  }
  const tagNames = [...groups.keys()].sort((a, b) => (order.indexOf(a) + 1 || 99) - (order.indexOf(b) + 1 || 99));
  $("ad-body").innerHTML = tagNames.map((tag) => {
    const desc = spec.tags?.find((t) => t.name === tag)?.description;
    return `<div class="ad-grp">${esc(tag)}${desc ? ` <span class="muted" style="text-transform:none;font-weight:400">— ${esc(desc)}</span>` : ""}</div>${groups.get(tag)!.join("")}`;
  }).join("");
}

document.addEventListener("DOMContentLoaded", () => void load());
