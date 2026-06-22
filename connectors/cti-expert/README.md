# CTI-Expert

`cti-expert` · **import** connector · category **Cyberthreat Intelligence OSINT**

Imports the output of [CTI-Expert](https://github.com/7onez/cti-expert) — a Claude-Code OSINT/CTI-analyst skill (67+ commands / 36+ techniques, A–F source-reliability grading, 0–100 exposure scoring, STIX 2.1 IOC export) — into XORCISM's threat-intel exchange (`XTHREAT.INTELEXCHANGE`).

It parses either form of cti-expert export:

- a **STIX 2.1 bundle** (`{ "type": "bundle", "objects": [ indicator / observed-data / domain-name / ipv4-addr / email-addr / url / user-account / file ] }`), or
- a **cti-expert case JSON** (`{ "target", "kind", "exposureScore", "severity", "observables": [{type,value}], "findings": [{technique,finding,reliability,severity}] }`).

Each IOC / finding becomes an `INTELEXCHANGE` intel item (the IOC value as `IntelReference`, with A–F reliability / severity carried in tags). CVEs mentioned in descriptions are extracted into `CveTags`.

**Upstream:** https://github.com/7onez/cti-expert

## Relationship to the native cockpit

XORCISM ships a **native** CTI-Expert experience at **`/cti-expert`** ([ctiexpert.ts](../../xorcism_ts/server/ctiexpert.ts)) that re-runs the same investigation methodology with your **local AI** (Ollama) — no API keys, nothing leaves your infrastructure. This connector is for ingesting cases produced by the *upstream* Claude-Code skill so they land in the same threat-intel exchange.

## Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `limit` | int | 500 | Max intel items to import |
| `file` | file | — | A cti-expert STIX bundle or case JSON export |

## Modes

1. **Offline** — pass `file` = a saved cti-expert export.
2. **Demo** — no `file` → imports the bundled [`sample.json`](sample.json) (a domain investigation case).

Returns `{ "source": "CTI-Expert", "intel": [...] }` → `runner.import_threat_intel` → `XTHREAT.INTELEXCHANGE`. No DB access in the connector (worker-safe). Permission: `connector:cti-expert`.
