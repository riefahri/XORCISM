# Opsgenie

`opsgenie` · **import** connector · category **Incident Response**

Imports alerts from [Atlassian Opsgenie](https://www.atlassian.com/software/opsgenie) — a widely used on-call alerting / incident-management platform — via the REST API into XORCISM as **security alerts** (`XINCIDENT.ALERT`). Each Opsgenie alert becomes one `ALERT` (idempotent by its id); **priority P1–P5 maps to severity** and tags/owner/source are carried over.

**Upstream:** https://docs.opsgenie.com/docs/alert-api

## Configuration (worker environment variables)

| Variable | Required | Description |
|----------|----------|-------------|
| `OPSGENIE_API_KEY` | live | API integration key (sent as `Authorization: GenieKey …`) |
| `OPSGENIE_EU` | optional | Set to `1` to use the EU endpoint `https://api.eu.opsgenie.com` |

## Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `limit` | int | 200 | Max alerts to import |
| `query` | string | `status: open` | Opsgenie search query, e.g. `status: open AND priority < P3` |
| `file` | file | — | Offline: a saved `/v2/alerts` export JSON |

## Modes

1. **Live** — `OPSGENIE_API_KEY` set → `GET /v2/alerts`.
2. **Offline** — `file` = an export (`{ "data": [...] }` or a list).
3. **Demo** — neither set → imports the bundled [`sample.json`](sample.json).

Returns `{ "source": "Opsgenie", "alerts": [...] }` → `runner.import_incidents` → `XINCIDENT.ALERT`. No DB access in the connector (worker-safe). Permission: `connector:opsgenie`.
