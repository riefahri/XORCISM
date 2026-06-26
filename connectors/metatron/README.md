# Metatron connector (offensive security / penetration testing)

Imports a **Metatron** penetration-test / engagement export into XORCISM.

> ⚠️ **INTRUSIVE — authorized targets only.** Run only against systems in scope under a signed
> Rules of Engagement.

## Mapping
- discovered **host** → `ASSET`
- open **service** → a service on its host (port / proto / product)
- enumerated **vulnerability** → `VULNERABILITY` / `ASSETVULNERABILITY` (CVE-linked where present)
- **confirmed exploit** → a vulnerability flagged exploitable (name prefixed `Exploited:`, severity critical)

The `host → service → exploit → impact` steps feed **pentest attack chains** (`XCHAIN`, `/pentest/chain`,
simulate/live under ROE), and exploited findings raise exploitability in the exposure-fusion score.

## Config (worker environment variables)
- `METATRON_API_URL` + `METATRON_API_TOKEN` — live pull (`/findings`), **or**
- `file` param — a saved Metatron engagement export JSON.

## Modes
1. **live** — both env vars set.
2. **offline** — `file` param.
3. **demo** — no config → bundled `sample.json`.

Worker-safe: stdlib only, secrets via env, ASCII-only output, no DB access. Normalized result
(`{project, assets, services, vulns, exploitable}`) is consumed by `runner.import_findings`.

```bash
python run.py            # demo (bundled sample)
```
