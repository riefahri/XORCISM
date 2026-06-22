# Microsoft Teams

`teams` · **outbound / action** connector · category **ChatOps**

Posts a XORCISM alert / incident / message to a **Microsoft Teams** channel through an **incoming webhook**. Supports both Teams payloads, auto-detected from the webhook host:

- **Adaptive Card** — modern **Power Automate / Workflows** webhooks (default).
- **MessageCard** — legacy **Office 365 "Incoming Webhook"** connector (`*.webhook.office.com`).

This is the *connector* (manual / attack-chain) counterpart to the **in-app distribution** ([`xorcism_ts/server/teams.ts`](../../xorcism_ts/server/teams.ts)) which fans alerts & notifications out to Teams **automatically** via the notification engine. Configure the channels under **Settings → Microsoft Teams** in the app, or use this connector for one-off / playbook posts.

**Upstream:** [Teams incoming webhooks](https://learn.microsoft.com/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)

## Configuration (worker environment variables)

| Variable | Required | Description |
|----------|----------|-------------|
| `TEAMS_WEBHOOK_URL` | live | Teams incoming-webhook URL |

(or pass the URL via the `webhook` parameter)

## Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `text` | string | — | Message body. Required unless `title` is given |
| `title` | string | — | Card title / alert name |
| `severity` | string | — | `critical`/`high`/`medium`/`low`/`info` — colours the card |
| `link` | string | — | Optional absolute URL (deep-link to the alert in XORCISM) |
| `format` | string | `auto` | `auto` / `adaptivecard` / `messagecard` |
| `webhook` | string | — | Webhook URL (overrides `TEAMS_WEBHOOK_URL`) |
| `dry_run` | bool | `false` | Build the card but **do not send** (returns the payload) |

## Modes

1. **Live** — a webhook is configured and `dry_run` is off → POSTs the card and returns `{ "notify": 1 }`.
2. **Dry-run** — no webhook, or `dry_run=true` → builds and **returns** the payload without sending.

Severity colours: critical/high `#b91c1c`/`#ea580c` (Adaptive `Attention`), medium `#ca8a04` (`Warning`), low `#16a34a` (`Good`), info `#2563eb` (`Accent`).

## How it works

`run.py` returns `{ "source": "Microsoft Teams", "notify": <0|1>, … }`. The runner recognises the `notify` key as an **outbound action** and short-circuits to a no-op import — the connector **never reads or writes the database**, so it is safe to run on a remote worker. Permission: `connector:teams`. Drivable from attack-chains / n8n playbooks; pairs with the in-app notification rules and the [`chatops`](../chatops/README.md) (Slack / Mattermost) connector.
