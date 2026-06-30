# IRONSIGHT connector

[IRONSIGHT](https://github.com/NoblerWorks-HQ/IRONSIGHT) (by [Nobler Works](https://noblerworks.com/))
is an open-source **real-time OSINT command center** monitoring the Middle East conflict. It aggregates
**50+ free, no-API-key public sources** into a single dashboard: 20+ RSS news feeds (with keyword
relevance filtering), 27 Telegram channels (auto-translated Hebrew/Arabic/Farsi), an interactive
theater map (military aircraft via adsb.lol, naval vessels, strike markers, missile-trajectory arcs),
live Pikud HaOref / Tzeva Adom missile alerts, a categorized conflict/strike monitor, per-country
regional threat levels, NASA FIRMS satellite thermal detection, plus defense/energy/crypto/prediction
markets. Next.js + TypeScript, MIT.

This `import` connector pulls IRONSIGHT's **intelligence feeds** into XORCISM's CTI store.

## What it imports

The CTI-relevant feeds (news · Telegram · conflicts · strikes · regional alerts) → `XTHREAT.INTELEXCHANGE`:

| IRONSIGHT feed item | XORCISM (`XTHREAT.INTELEXCHANGE`) |
|---|---|
| Headline / Telegram post / event title | `IntelName` |
| Summary + classification metadata (feed/severity/category/region/coords) | `IntelDescription` |
| Source link / permalink | `IntelReference` (idempotency key) |
| `feed:<kind>` · source · region · category · severity | `IntelTags` |
| Conflict actors (IDF / IRGC / Hezbollah / Hamas / Houthi …) detected in the text | `ActorTags` |
| Any `CVE-…` referenced (e.g. in defense/cyber feeds) | `CveTags` |
| Published date, item id | `IntelDate`, `IntelExternalID` |

`IntelSource` is the underlying outlet/channel (e.g. *BBC*, *@warfareanalysis*); the global feed source is
**IRONSIGHT** (also added as an `ironsight` tag). Idempotent by reference URL (existing rows are updated).
Normalized result: `{assets:[], services:[], cpes:[], vulns:[], intel:[…], source:"IRONSIGHT"}` → feeds **CTI**.

Markets / crypto / oil / flights / ships / fires are situational-awareness only and are not imported as CTI.

## Configuration

Worker-safe: it only reads an exported file or **read-only** GET API routes — no DB access, no offensive action.

| Source | How |
|---|---|
| `file` parameter | An IRONSIGHT export (a JSON array → treated as news, or `{news\|telegram\|conflicts\|strikes\|regionalAlerts:[…]}`). |
| `IRONSIGHT_URL` env (worker) | Base URL of a running IRONSIGHT instance; its read-only routes are GET-fetched: `/api/news`, `/api/telegram`, `/api/conflicts`, `/api/strikes`, `/api/regional-alerts`. |
| `kinds` parameter | Comma-separated feeds to import (default: `news,telegram,conflicts,strikes,regional-alerts`). |
| `limit` parameter | Max items across all feeds (default 500). |
| `min_severity` parameter | `low` \| `guarded` \| `elevated` \| `high` \| `critical` — minimum severity for *event* feeds that carry one (conflicts/strikes/regional alerts). News & Telegram have no severity and are always included. Default: import all. |

Field names vary between IRONSIGHT versions, so extraction is defensive (title/headline/text, link/url/permalink,
source/channel, category/type, severity/threatLevel/level, country/region/location, lat/lng …).

> IRONSIGHT relies on some unofficial/undocumented public endpoints and is provided by its authors for
> educational/research use; respect each upstream provider's terms. This connector ingests only headlines,
> links and public metadata (no full-content reproduction).

## Offline dry run

```bash
python connectors/ironsight/run.py                                  # built-in sample (all feeds)
python connectors/ironsight/run.py --file feed.json --kinds news,strikes --min-severity high
```

Imported items surface in **CTI** (the threat-intel exchange) and the STIX graph.
