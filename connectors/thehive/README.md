# TheHive

`thehive` · **import** connector · category **DFIR**

Imports **alerts** (and optionally **cases**) from [TheHive](https://thehive.dev), the open-source SOAR / case-management platform, into XORCISM as **security alerts** — rows in `XINCIDENT.ALERT`, the Defender-XDR-aligned alert layer that feeds incidents. Each TheHive alert/case becomes one `ALERT` (idempotent by its TheHive id), and any impacted host observable is linked to its `ASSET`.

**Upstream:** https://thehive.dev

## Configuration (worker environment variables)

| Variable | Required | Description |
|----------|----------|-------------|
| `THEHIVE_URL` | live | Base URL, e.g. `https://thehive.lab` |
| `THEHIVE_API_KEY` | live | API key (sent as `Authorization: Bearer …`) |

## Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `limit` | int | 200 | Maximum number of alerts to import |
| `kind` | string | `alert` | `alert` or `case` |
| `file` | file | — | Offline: a saved TheHive export JSON to parse instead of the live API |

## Modes

1. **Live** — `THEHIVE_URL` + `THEHIVE_API_KEY` set → queries the TheHive 5 query API (`POST /api/v1/query`, `listAlert`/`listCase`).
2. **Offline** — pass `file` = a TheHive alert-export JSON (a list, or `{ "data": [...] }`).
3. **Demo** — neither set → imports the bundled [`sample.json`](sample.json) so the connector is immediately demoable.

## How it works

`run.py` exposes `run(params, workdir)` and returns `{ "source": "TheHive", "alerts": [...] }`. The XORCISM runner routes the `alerts` list through `runner.import_incidents` into `XINCIDENT.ALERT` (idempotent by `(DetectionSource, ExternalID)`). The connector performs **no database access** itself, so it is safe to run on a remote worker. Required permission: `connector:thehive`.

---
<sub>Hand-written. Severity maps TheHive 1–4 → low/medium/high/critical.</sub>
