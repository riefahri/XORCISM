# Cyera

`cyera` · **import** connector · category **Cloud Security**

Imports data stores and data-security risks from [Cyera](https://www.cyera.com) — a **DSPM** (Data Security Posture Management) platform that discovers, classifies and protects sensitive data across cloud, SaaS and on-prem — into XORCISM:

- each **data store** → an `ASSET` (name + engine/type + cloud provider; sensitivity & data classes carried as tags / a finding),
- each **data risk / issue** → a finding (`VULNERABILITY`) attached to its data store,

so sensitive-data exposure (public PII stores, unencrypted sensitive data, over-permissive access) shows up alongside the rest of your attack surface and Enterprise Risk Score.

**Upstream:** https://www.cyera.com · API docs: https://docs.cyera.io

## Configuration (worker environment variables)

| Variable | Required | Description |
|----------|----------|-------------|
| `CYERA_API_URL` | optional | API base — default `https://api.cyera.io` |
| `CYERA_CLIENT_ID` | live | OAuth2 client id |
| `CYERA_CLIENT_SECRET` | live | OAuth2 client secret |

The connector logs in (`POST /v1/login` → JWT) then reads `/v3/datastores` and `/v1/issues` (defensive: falls back across API versions).

## Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `limit` | int | 500 | Max data stores / issues to import |
| `file` | file | — | Offline: a saved Cyera export JSON |

## Modes

1. **Live** — `CYERA_CLIENT_ID` + `CYERA_CLIENT_SECRET` set → authenticate + pull data stores + issues.
2. **Offline** — `file` = a Cyera export (`{ "datastores": [...], "issues": [...] }`, or a list).
3. **Demo** — neither → imports the bundled [`sample.json`](sample.json).

Returns `{ "project": "Cyera DSPM", "assets": [...], "vulns": [...] }` → `runner.import_findings` (ASSET / VULNERABILITY / ASSETVULNERABILITY). No DB access in the connector (worker-safe). Permission: `connector:cyera`. The data-security companion to the cloud CNAPP connectors (`wiz`, `upwind`, `lacework`).
