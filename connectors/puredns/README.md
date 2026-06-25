# puredns connector

[puredns](https://github.com/d3mondev/puredns) — a fast domain resolver and
subdomain brute-forcing tool built on [massdns](https://github.com/blechschmidt/massdns).
It brute-forces a wordlist against a domain (or resolves a candidate list),
filters DNS **wildcards**, and **validates** answers against trusted resolvers, so
the output is the set of *live, resolvable* subdomains rather than raw guesses.

In XORCISM it feeds the **attack-surface / recon** stage: each resolved subdomain
becomes an **ASSET (host)** on the target domain, which the attack-chain engine
then probes (`httpx`) and fingerprints/scans (WhatWeb, Nikto, WPScan…).

## Modes

### Offline (recommended on the worker)
Parse a results file you already produced:

```bash
puredns bruteforce subdomains.txt example.com -r resolvers.txt -w resolved.txt
# or resolve a candidate list:
puredns resolve candidates.txt -r resolvers.txt -w resolved.txt
```

Then import `resolved.txt` via the `file` parameter. The parser accepts either:

- **plain** — one resolved domain per line (`api.example.com`), or
- **massdns `-o S`** — `api.example.com. A 1.2.3.4` (A / AAAA give the asset its IP).

### Live
Set `target` to the apex domain and provide a `wordlist` (and ideally a
`resolvers` file) on the worker; if the `puredns` binary is on `PATH` the
connector runs it and parses the output.

| Parameter | Type | Notes |
|---|---|---|
| `file` | file | Offline results export to parse. |
| `target` | target | Live: apex domain (scope-enforced). |
| `mode` | string | `bruteforce` (default) or `resolve`. |
| `wordlist` | string | Live: subdomain wordlist / candidate-domains file. |
| `resolvers` | string | Live: trusted-resolvers file (`-r`). |

## Output (normalized findings model)

```json
{ "assets": [{ "hostname": "api.example.com", "ip": "1.2.3.4" }], "hosts": ["api.example.com"],
  "services": [], "cpes": [], "vulns": [] }
```

Routed through `runner.import_findings` → `XORCISM.ASSET`. Resolved hosts are
scoped to the `target` domain when one is supplied.

## Attack chains

`puredns` is wired into the **"Web recon (subdomains)"** playbook (alongside
`subfinder`, adding active brute-force coverage to passive discovery) and is the
seed of the dedicated **"DNS brute-force recon (puredns)"** playbook. Discovered
hosts fan out into `httpx` → WhatWeb / Nikto / WPScan.

> ⚠️ Active DNS enumeration (`intrusive: true`). Brute-force only domains inside
> the engagement scope / rules of engagement.
