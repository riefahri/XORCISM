# RedRoom connector

[RedRoom](https://github.com/Owlinkai/redroom) (by [Owlink.ai](https://owlink.ai)) is an open-source
**real-time news OSINT platform** — a command-and-control-style intelligence dashboard for geopolitical
analysis: a live feed with **sentiment + threat classification**, a 3D threat globe, an RSS crawler with
scheduled missions, satellite/SIGINT dashboards, **AI-assisted narrative detection** for information
operations, and multi-source reference verification. TypeScript, MIT.

This `import` connector pulls RedRoom's **classified intelligence feed** into XORCISM's CTI store.

## What it imports

| RedRoom feed item | XORCISM (`XTHREAT.INTELEXCHANGE`) |
|---|---|
| Headline / title | `IntelName` |
| Summary + classification block | `IntelDescription` |
| Source link / permalink | `IntelReference` (idempotency key) |
| Sentiment · threat-level · region · narrative | `IntelTags` |
| Narrative / campaign | `ActorTags` |
| Any `CVE-…` referenced in the text | `CveTags` |
| Published date, item id | `IntelDate`, `IntelExternalID` |

`IntelSource` is set to **RedRoom**. Idempotent by reference URL (existing rows are updated).
Normalized result: `{assets:[], services:[], cpes:[], vulns:[], intel:[…]}` → feeds **CTI**.

## Configuration

Worker-safe: it only reads an exported file or a **read-only** feed API — no DB access, no offensive action.

| Source | How |
|---|---|
| `file` parameter | Upload a RedRoom feed export (JSON array, or `{items|feed|data|articles|results:[…]}`). |
| `REDROOM_URL` env (worker) | RedRoom feed API URL (a base URL gets `/api/feed` appended). |
| `REDROOM_API_KEY` env | Optional bearer token for that API. |
| `limit` parameter | Max items (default 500). |
| `min_threat` parameter | `low` \| `medium` \| `high` \| `critical` — minimum threat level (default `low`). |

Field names vary between RedRoom versions, so extraction is defensive (title/headline, summary/content,
url/link/permalink, threatLevel/classification/severity, sentiment, region/country, narrative…).

## Offline dry run

```bash
python connectors/redroom/run.py                       # uses a built-in sample
python connectors/redroom/run.py --file feed.json --min-threat high
```

Imported items surface in **CTI** (the threat-intel exchange) and the STIX graph.
