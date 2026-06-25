# GCVE CPE Editor connector

Pulls curated **CPE** (Common Platform Enumeration) records from a
[GCVE-EU **CPE Editor**](https://github.com/gcve-eu/cpe-editor) instance
([v1.1.0](https://github.com/gcve-eu/cpe-editor/releases/tag/v1.1.0)+) and normalizes each to a
CPE dictionary entry that maps to **`XORCISM.CPE`** — the software/platform identifiers used across
XORCISM for CVE↔asset matching, SCA and OVAL / vulnerable-configuration tests.

CPE Editor curates CPE data (vendors, products, CPEs, change proposals) with alias / duplicate
detection and NVD CPE-Match + PURL mappings, and exposes a **read-only OpenAPI** plus JSON / NDJSON
dataset export. This connector consumes that API (or an exported dataset).

## Modes

| Mode | Trigger | Source |
|------|---------|--------|
| **live** | `base_url` or `CPE_EDITOR_URL` | `GET <base_url>/api/v1/cpes?limit=&search=` (optional `Authorization: Bearer $CPE_EDITOR_TOKEN`) |
| **file** | `file=<path>` | An exported dataset — JSON array, `{"cpes":[...]}` object, or NDJSON (one record per line) |
| **demo** | neither | A small built-in sample (3 CPEs) |

## Config

- `CPE_EDITOR_URL` — the CPE Editor instance base URL (or pass `base_url`). The connector appends `/api/v1/cpes`.
- `CPE_EDITOR_TOKEN` — optional bearer token (secrets via env only, never the UI).

## Parameters

- `base_url` — instance base URL (overrides `CPE_EDITOR_URL`).
- `search` — vendor / product / CPE substring filter (live).
- `limit` — max records to pull (live, default 200).
- `file` — path to an exported dataset.

## Output

```json
{ "source": "GCVE CPE Editor", "count": N, "valid": M,
  "cpes": [ { "cpe23": "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*",
              "cpe22": null, "part": "a", "vendor": "apache", "product": "http_server",
              "version": "2.4.58", "title": "Apache HTTP Server 2.4.58",
              "deprecated": false, "reference": "https://httpd.apache.org/",
              "external_id": "...", "valid": true } ] }
```

`valid` flags whether each `cpe23` / `cpe22` matches the CPE 2.3 / 2.2 binding grammar (the same
check XORCISM enforces on CPE form fields). Records map to `XORCISM.CPE` (mapping `cpe-editor`).

Run standalone for a dry-run (prints the normalized JSON):

```bash
python run.py
```

Read-only · stdlib only · ASCII output.
