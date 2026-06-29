# Malwoverview connector

Imports [malwoverview](https://github.com/alexandreborges/malwoverview) (by Alexandre Borges) output into
XORCISM's malware store (**XMALWARE**). Malwoverview is a Python CLI for initial **malware triage & threat
hunting** that aggregates ~18 TI/sandbox services (VirusTotal, Hybrid Analysis, Triage, Polyswarm,
MalwareBazaar, URLhaus, ThreatFox, Malshare, Malpedia, AlienVault OTX, …) and can emit JSON.

## Produce the input
Run malwoverview with JSON output (it uses *your own* per-service API keys), e.g.:
```
malwoverview.py -v 1 -V <sha256> -o json > sample.json     # VirusTotal report
malwoverview.py -b 1 -B <sha256> -o json > sample.json     # MalwareBazaar
```
or feed it a **normalized bundle** you assemble from several services:
```json
{ "samples": [ {
    "sha256": "…", "md5": "…", "verdict": "malicious", "positives": 58, "total": 72,
    "family": "Emotet", "tags": ["trojan","banker"], "attck": ["T1059","T1071"],
    "summary": "VT 58/72 · MalwareBazaar: Emotet",
    "services": [ {"service":"VirusTotal","verdict":"malicious","detection":"Trojan.Emotet","link":"…"},
                  {"service":"MalwareBazaar","verdict":"malicious","detection":"Emotet"} ],
    "iocs": [ {"type":"url","value":"http://…"} ] } ] }
```
A raw **VirusTotal v3 file report** or a raw **MalwareBazaar hash query** are also auto-detected.

## Mapping (→ XMALWARE)
- each sample → **MALWARESCAN** (Md5/Sha1/Sha256, aggregate Verdict, Positives/Total, Summary, family in tags) — the same store as the `/malware-scan` page
- each aggregated service → **MALWARESCANENGINE** (per-service Verdict / Detection / Category / Link)
- the family + tags + **MITRE ATT&CK** techniques → an **INTELEXCHANGE** item, cross-linked into the ATT&CK matrix
- idempotent by `Sha256 + Source` (re-import updates the scan and its engine rows)

## Run
```
python connectors/runner.py --connector malwoverview --file sample.json
```
Results then appear in **/malware-scan** (inventory + per-engine verdicts) and in **CTI** (INTELEXCHANGE → ATT&CK).

`run.py` makes no live API calls and no DB writes (worker-safe) — malwoverview does the querying with your keys;
this connector only normalizes its JSON. Only triage samples you are authorized to analyze.
