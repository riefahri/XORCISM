# Brakeman connector (Ruby on Rails SAST)

Imports a [Brakeman](https://brakemanscanner.org) static-analysis report into XORCISM. Brakeman finds
**SQLi, XSS, mass-assignment, command injection, unsafe redirects** and more in Rails source.

## Mapping
- the scanned application → an `ASSET` (project context)
- each warning → a `VULNERABILITY` / `ASSETVULNERABILITY` on the app, severity from Brakeman's
  **confidence** (High→high, Medium→medium, Weak→low)

## Usage
```bash
brakeman -f json -o report.json     # in your Rails app
# then import report.json via the connector (file param), or:
python run.py                        # demo (bundled sample)
```

Worker-safe: stdlib only, ASCII-only output, no DB access. Normalized result (`{project, assets, vulns}`)
is consumed by `runner.import_findings`. From the **awesome-web-hacking** toolkit.
