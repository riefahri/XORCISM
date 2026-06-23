# EMAIL-CRAWL — OSINT email harvesting

`email-crawl` · **import** connector · category **OSINT** · ⚠️ **intrusive** (engagement scope enforced)

Imports the email addresses harvested from a target website by EMAIL-CRAWL (an OSINT web crawler that extracts emails from contact/team pages, mailtos, etc.). For an attack-surface view those exposed addresses are phishing / social-engineering targets, so the crawled domain becomes an ASSET and each email becomes an informational finding on it (noting the source page and whether it is an on-domain corporate address). Offline (non-intrusive): pass `file` = an EmailCrawl JSON export. Live (ACTIVE OSINT RECON — only with authorization): set EMAILCRAWL_BIN (path to EmailCrawl.py on the worker) and pass `target` (the site to crawl) + optional `maxPages`. No config / no file → the bundled sample.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | string | no | — | URL/domain to crawl (live mode; requires EMAILCRAWL_BIN on the worker). Active recon — authorized targets only. |
| `maxPages` | string | no | — | Max pages to crawl in live mode (EmailCrawl --max-pages; default 200). |
| `file` | file | no | — | Offline EmailCrawl JSON export ({emails:[...]} / {results:[{email, source_url}]} / a flat list). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *EMAIL-CRAWL — OSINT email harvesting*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:email-crawl`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/email-crawl/sample.json --connector email-crawl
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
