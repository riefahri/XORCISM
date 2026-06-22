# MITRE Caldera — adversary-emulation automation

`caldera` · **import** connector · category **Adversary Emulation** · ⚠️ **intrusive** (the `launch` action runs an operation)

Automates adversary emulation against a **remote** [MITRE Caldera](https://github.com/mitre/caldera) server (v2 API). It both **reads** existing operations and can **launch** new ones, and feeds the results into XORCISM's BAS layer — agents → `ASSET`, executed abilities → findings **and** → `EMULATIONRUN` / `EMULATIONRESULT` (the **ATT&CK validation-coverage heatmap**, `/attack`).

## Actions

| `action` | Behaviour |
|----------|-----------|
| `import` (**default**) | **Read-only** — list operations + map their executed links (abilities) to coverage results. Safe. |
| `launch` | **Create + start** an operation (adversary vs. an agent group) on the remote Caldera host — automated offensive emulation (admin only; blast radius = the Caldera **agent group** you deployed). Optionally `wait` then import its results. |

## Remote hosts & automation

- **Target any remote Caldera host** with `caldera_url` (overrides `CALDERA_URL`) — one XORCISM can drive several remote Caldera servers.
- **Schedule it** (Connectors → recurrence / `XSCHEDULE` cron) for recurring automated emulation, or chain it.
- The API **key stays in the worker environment** (`CALDERA_API_KEY`, sent as the `KEY` header) — never in the UI.

## Configuration (worker environment variables)

| Variable | Description |
|----------|-------------|
| `CALDERA_URL` | e.g. `https://caldera.lab:8888` (or the `caldera_url` param) |
| `CALDERA_API_KEY` | Caldera API key (`conf/local.yml`) |

## Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `action` | enum | `import` | `import` (read-only) / `launch` (create + start an operation) |
| `caldera_url` | string | — | Remote Caldera base URL (overrides `CALDERA_URL`) |
| `operation` | string | — | Import filter: operation name or ID (empty = all) |
| `adversary` | string | — | `launch`: adversary id or name to emulate |
| `group` | string | `red` | `launch`: Caldera agent group to run against |
| `planner` | string | `atomic` | `launch`: planner id or name |
| `name` | string | — | `launch`: operation name |
| `wait` | int | `0` | `launch`: seconds to wait for the op to finish before importing |
| `agents_only` | bool | `false` | Import only the agent inventory |
| `file` | file | — | Offline: a saved Caldera operation export JSON |

## How it works

`run.py` returns `{ assets, vulns, cpes, emulation_results, scenario }`. The runner routes `emulation_results` through `import_emulation` → one `EMULATIONRUN` (Score = % executed) + one `EMULATIONRESULT` per link (Caldera link status → Executed / Failed / No result / Pending; technique resolved to `AttackTechniqueID`), and `assets`/`vulns` through `import_findings`. **No DB access** in the connector (worker-safe). Required permission: `connector:caldera`. The agent-based complement to the [`atomic-red-team`](../atomic-red-team/README.md) connector.
