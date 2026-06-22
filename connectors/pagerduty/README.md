# PagerDuty

`pagerduty` · **import** connector · category **Incident Response**

Imports incidents from [PagerDuty](https://www.pagerduty.com) — the leading on-call / incident-response alerting platform — via the REST API into XORCISM as **security alerts** (`XINCIDENT.ALERT`). Each PagerDuty incident becomes one `ALERT` (idempotent by its id); **priority (P1–P5) / urgency maps to severity** and the affected service is recorded as a tag and as the impacted asset name.

**Upstream:** https://developer.pagerduty.com/api-reference/

## Configuration (worker environment variables)

| Variable | Required | Description |
|----------|----------|-------------|
| `PAGERDUTY_API_TOKEN` | live | REST API key (sent as `Authorization: Token token=…`) |
| `PAGERDUTY_STATUSES` | optional | Comma list of statuses (default `triggered,acknowledged`) |

## Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `limit` | int | 200 | Max incidents to import |
| `since_hours` | int | 168 | Incidents created in the last N hours |
| `file` | file | — | Offline: a saved `/incidents` export JSON |

## Modes

1. **Live** — `PAGERDUTY_API_TOKEN` set → `GET https://api.pagerduty.com/incidents`.
2. **Offline** — `file` = an export (`{ "incidents": [...] }` or a list).
3. **Demo** — neither set → imports the bundled [`sample.json`](sample.json).

Returns `{ "source": "PagerDuty", "alerts": [...] }` → `runner.import_incidents` → `XINCIDENT.ALERT`. No DB access in the connector (worker-safe). Permission: `connector:pagerduty`.
