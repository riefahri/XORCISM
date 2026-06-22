# ServiceNow

`servicenow` · **import** connector · category **ITSM**

Imports incidents / **security incidents** from [ServiceNow](https://www.servicenow.com) — the market-leading enterprise ITSM and Security Incident Response (SecOps) platform — via the **Table API** into XORCISM as **security alerts** (`XINCIDENT.ALERT`). Each ServiceNow record becomes one `ALERT` (idempotent by its `number`); ServiceNow **priority 1–5 maps to severity** (1=Critical) and the impacted CI (`cmdb_ci`) is linked to its `ASSET`.

> This is the SOC/ITSM *ticketing* companion to the existing `servicenow-grc` connector (which imports GRC documents). Set `SERVICENOW_TABLE=sn_si_incident` to pull from Security Incident Response instead of the default `incident` table.

**Upstream:** https://www.servicenow.com

## Configuration (worker environment variables)

| Variable | Required | Description |
|----------|----------|-------------|
| `SERVICENOW_INSTANCE` | live | e.g. `dev12345.service-now.com` |
| `SERVICENOW_USER` | live | Integration user |
| `SERVICENOW_PASSWORD` | live | Password (Basic auth) |
| `SERVICENOW_TABLE` | optional | Table name — default `incident`; use `sn_si_incident` for SecOps |

## Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `limit` | int | 200 | Max records to import |
| `query` | string | `active=true` | ServiceNow encoded query (`sysparm_query`), e.g. `active=true^priority<=2` |
| `file` | file | — | Offline: a saved Table-API export JSON |

## Modes

1. **Live** — instance + user + password set → `GET /api/now/table/<table>` (display values).
2. **Offline** — `file` = a Table-API export (`{ "result": [...] }` or a list).
3. **Demo** — neither set → imports the bundled [`sample.json`](sample.json).

Returns `{ "source": "ServiceNow", "alerts": [...] }` → `runner.import_incidents` → `XINCIDENT.ALERT`. No DB access in the connector (worker-safe). Permission: `connector:servicenow`.
