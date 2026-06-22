# Zammad

`zammad` · **import** connector · category **Ticketing**

Imports tickets from [Zammad](https://zammad.org) — a popular **open-source** help-desk / ticketing system — via the REST API into XORCISM as **security alerts** (`XINCIDENT.ALERT`). Each Zammad ticket becomes one `ALERT` (idempotent by its `number`); **priority maps to severity**, state to status, and the owner/group are carried over. Use the `group` parameter to import only your `Security` queue.

**Upstream:** https://docs.zammad.org/en/latest/api/intro.html

## Configuration (worker environment variables)

| Variable | Required | Description |
|----------|----------|-------------|
| `ZAMMAD_URL` | live | Base URL, e.g. `https://support.acme.io` |
| `ZAMMAD_TOKEN` | live | HTTP token access (sent as `Authorization: Token token=…`) |

## Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `limit` | int | 200 | Max tickets to import |
| `group` | string | — | Optional Zammad group name to filter on (e.g. `Security`) |
| `file` | file | — | Offline: a saved `/api/v1/tickets` export JSON |

## Modes

1. **Live** — `ZAMMAD_URL` + `ZAMMAD_TOKEN` set → `GET /api/v1/tickets?expand=true`.
2. **Offline** — `file` = a tickets export (a list, or `{ "tickets": [...] }`).
3. **Demo** — neither set → imports the bundled [`sample.json`](sample.json).

Returns `{ "source": "Zammad", "alerts": [...] }` → `runner.import_incidents` → `XINCIDENT.ALERT`. No DB access in the connector (worker-safe). Permission: `connector:zammad`.
