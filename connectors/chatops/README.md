# Slack / Mattermost (ChatOps)

`chatops` · **outbound / action** connector · category **ChatOps**

The **outbound** counterpart to the inbound SOC-tool connectors (TheHive, ServiceNow, PagerDuty, Opsgenie, Zammad). It posts a XORCISM alert / incident / message to a **Slack** or **Mattermost** channel through an **incoming webhook**. Mattermost's incoming webhook deliberately mirrors Slack's payload, so one connector serves both.

**Upstream:** [Slack incoming webhooks](https://api.slack.com/messaging/webhooks) · [Mattermost incoming webhooks](https://developers.mattermost.com/integrate/webhooks/incoming/)

## Configuration (worker environment variables)

| Variable | Required | Description |
|----------|----------|-------------|
| `SLACK_WEBHOOK_URL` | live (Slack) | Slack incoming-webhook URL |
| `MATTERMOST_WEBHOOK_URL` | live (Mattermost) | Mattermost incoming-webhook URL |

(or pass the URL directly via the `webhook` parameter)

## Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `text` | string | — | Message body (Markdown). Required unless `title` is given |
| `title` | string | — | Optional bold header / alert name |
| `severity` | string | — | `critical`/`high`/`medium`/`low`/`info` — colours the message |
| `link` | string | — | Optional URL (e.g. deep-link to the alert in XORCISM) |
| `channel` | string | — | Optional channel override |
| `username` | string | `XORCISM` | Display name for the bot message |
| `webhook` | string | — | Incoming-webhook URL (overrides the env var) |
| `dry_run` | bool | `false` | Build the payload but **do not send** (returns the payload) |

## Modes

1. **Live** — a webhook is configured and `dry_run` is off → `POST`s a Slack/Mattermost-compatible message (`{text, attachments:[{color, title, title_link, text, fields, footer}]}`) and returns `{ "notify": 1 }`.
2. **Dry-run** — no webhook, or `dry_run=true` → builds and **returns** the payload without sending it (safe to test).

Severity colours: critical `#b91c1c`, high `#ea580c`, medium `#ca8a04`, low `#16a34a`, info `#2563eb`.

## How it works

`run.py` returns `{ "source": "Slack"|"Mattermost", "notify": <0|1>, … }`. The runner recognises the `notify` key as an **outbound action** and short-circuits to a no-op import — the connector **never reads or writes the database**, so it is safe to run on a remote worker. Required permission: `connector:chatops`. Pairs naturally with the in-app event→notification rules and can be driven from attack-chains / n8n playbooks to fan SOC alerts out to your team channel.
