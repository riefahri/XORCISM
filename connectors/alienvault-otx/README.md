# AlienVault OTX — threat pulses (CTI)

Pulls threat **pulses** from AlienVault / LevelBlue **Open Threat Exchange** and maps each to a
normalized XORCISM intel item → `XTHREAT.INTELEXCHANGE` (the threat graph + the `/attack` ATT&CK
coverage heatmap). This is the named CTI source XORCISM was missing alongside MISP, OpenCTI,
abuse.ch, VirusTotal, GreyNoise and Shodan — the AEGIS "OTX BROWSER" equivalent.

A pulse → one intel item with its name, description, **MITRE ATT&CK technique ids**, adversary,
malware families, CVEs, indicator tally (IPs / domains / hostnames / URLs / file hashes) and tags.

```bash
# demo (no key) — proves the import chain
python connectors/runner.py --connector alienvault-otx

# from an exported pulses file ({"results":[...]} or an array)
python connectors/runner.py --connector alienvault-otx --param file=pulses.json

# live — your subscribed pulses
OTX_API_KEY=… python connectors/runner.py --connector alienvault-otx --param limit=100
# only pulses modified since a date:
OTX_API_KEY=… python connectors/runner.py --connector alienvault-otx --param modified_since=2026-06-01T00:00:00
```

Idempotent by the pulse URL (`IntelReference`); ATT&CK ids are cross-linked into the coverage
heatmap; stdlib only; key via env `OTX_API_KEY`. Get a free key at otx.alienvault.com (account →
API). Read-only.
