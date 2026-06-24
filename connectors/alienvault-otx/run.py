"""run.py - XORCISM connector for AlienVault OTX (Open Threat Exchange) pulses -> INTELEXCHANGE.

A "pulse" is an OTX threat report: a named bundle of indicators (IPs, domains, hostnames, URLs,
file hashes, CVEs) plus MITRE ATT&CK technique ids, adversary, malware families, targeted
industries/countries and tags. Each pulse is mapped to a normalized XORCISM intel item ->
runner.import_threat_intel -> XTHREAT.INTELEXCHANGE (threat graph + ATT&CK coverage).

Modes:
    live : `api_key` or env OTX_API_KEY -> GET https://otx.alienvault.com/api/v1/pulses/subscribed.
    file : `file` = an exported pulses JSON ({"results":[...]} or an array of pulses).
    demo : neither -> a small built-in sample.

Read-only. Worker-safe: stdlib only, secrets via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any, Dict, List

OTX = "https://otx.alienvault.com/api/v1/pulses/subscribed"
PULSE_URL = "https://otx.alienvault.com/pulse/"
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_ATTACK = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

_DEMO = {"results": [
    {"id": "demo1", "name": "Emotet malspam campaign - June 2026", "author_name": "AlienVault",
     "description": "Renewed Emotet distribution via malicious XLS attachments dropping a loader.",
     "created": "2026-06-20T10:00:00", "modified": "2026-06-22T08:00:00",
     "tags": ["emotet", "malspam", "loader"], "adversary": "TA542", "industries": ["Finance"],
     "targeted_countries": ["United States", "Germany"], "malware_families": ["Emotet"],
     "attack_ids": [{"id": "T1566.001", "name": "Spearphishing Attachment"}, {"id": "T1059.001", "name": "PowerShell"}],
     "indicators": [{"type": "FileHash-SHA256", "indicator": "ab" * 32}, {"type": "domain", "indicator": "evil-emotet.example"},
                    {"type": "IPv4", "indicator": "203.0.113.66"}, {"type": "URL", "indicator": "http://evil-emotet.example/x"}]},
    {"id": "demo2", "name": "Exploitation of CVE-2026-12345 in Acme VPN", "author_name": "AlienVault",
     "description": "Active exploitation of an Acme VPN pre-auth RCE.",
     "created": "2026-06-21T12:00:00", "modified": "2026-06-21T12:00:00",
     "tags": ["vpn", "rce", "exploitation"], "adversary": "", "industries": ["Government"],
     "targeted_countries": [], "malware_families": [],
     "attack_ids": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
     "indicators": [{"type": "CVE", "indicator": "CVE-2026-12345"}, {"type": "IPv4", "indicator": "198.51.100.7"}]},
]}


def _csv(s) -> str:
    return ", ".join(sorted({str(x).strip() for x in s if str(x).strip()}))[:1000]


def _names(lst) -> List[str]:
    out = []
    for x in lst or []:
        if isinstance(x, dict):
            out.append(x.get("display_name") or x.get("name") or x.get("id") or "")
        elif x:
            out.append(str(x))
    return [x for x in out if x]


def _map_pulse(p: Dict[str, Any]) -> Dict[str, Any]:
    pid = p.get("id")
    indicators = p.get("indicators") or []
    # indicator type tally for the description
    tally: Dict[str, int] = {}
    cves = set()
    for ind in indicators:
        t = str(ind.get("type") or "").strip()
        if t:
            tally[t] = tally.get(t, 0) + 1
        if t.upper() == "CVE":
            cves.add(str(ind.get("indicator") or "").upper())
    ioc_summary = ", ".join(f"{v} {k}" for k, v in sorted(tally.items()))
    # ATT&CK ids: from attack_ids and any T#### in tags/description
    attack = set()
    for a in p.get("attack_ids") or []:
        aid = a.get("id") if isinstance(a, dict) else a
        if aid:
            attack.add(str(aid).upper())
    blob = f"{p.get('name','')} {p.get('description','')} " + " ".join(_names(p.get("tags")))
    attack |= {m.upper() for m in _ATTACK.findall(blob)}
    cves |= {m.upper() for m in _CVE.findall(blob)}
    tags = _names(p.get("tags")) + _names(p.get("industries")) + _names(p.get("targeted_countries"))
    desc = (p.get("description") or p.get("name") or "")[:7000]
    if ioc_summary:
        desc += f" Indicators: {ioc_summary}."
    return {
        "name": (p.get("name") or f"OTX pulse {pid}")[:500],
        "description": desc[:8000],
        "reference": f"{PULSE_URL}{pid}" if pid else f"otx:pulse:{p.get('name','')}",
        "external_id": str(pid) if pid else None,
        "author": p.get("author_name") or "AlienVault OTX",
        "date": str(p.get("modified") or p.get("created") or "")[:10],
        "attack_tags": _csv(attack),
        "actor_tags": _csv([p.get("adversary")] if p.get("adversary") else []),
        "malware_tags": _csv(_names(p.get("malware_families"))),
        "cve_tags": _csv(cves),
        "tags": _csv(["OTX"] + tags),
        "views": len(indicators),
    }


def _load(params: Dict[str, Any]) -> List[Dict[str, Any]]:
    path = str(params.get("file") or "").strip()
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("results", data) if isinstance(data, dict) else data
    key = (str(params.get("api_key") or "").strip() or os.environ.get("OTX_API_KEY", "").strip())
    if key:
        q = {"limit": int(params.get("limit") or 50)}
        if str(params.get("modified_since") or "").strip():
            q["modified_since"] = str(params["modified_since"]).strip()
        req = urllib.request.Request(f"{OTX}?{urllib.parse.urlencode(q)}",
                                     headers={"X-OTX-API-KEY": key, "Accept": "application/json", "User-Agent": "XORCISM-OTX/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            return (json.loads(resp.read().decode("utf-8")) or {}).get("results", [])
    return _DEMO["results"]


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    pulses = _load(params)
    intel = [_map_pulse(p) for p in pulses if isinstance(p, dict) and (p.get("id") or p.get("name"))]
    return {"intel": intel, "source": "AlienVault OTX", "count": len(intel)}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()), indent=2))
