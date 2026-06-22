"""run.py — XORCISM connector for CTI-Expert (github.com/7onez/cti-expert).

CTI-Expert is a Claude-Code OSINT/CTI-analyst skill (67+ commands, STIX 2.1 IOC export). This
connector ingests its output into XORCISM's threat-intel exchange (XTHREAT.INTELEXCHANGE via
runner.import_threat_intel). It parses either:
  * a STIX 2.1 bundle  ({"type":"bundle","objects":[ indicator / observed-data / ... ]}), or
  * a cti-expert case JSON ({"target","kind","exposureScore","severity","observables":[{type,value}],
    "findings":[{technique,finding,reliability,severity}]}).
Each IOC / finding becomes an intel item {name, reference, external_id, description, tags, cve_tags}.

The native XORCISM cockpit (/cti-expert, ctiexpert.ts) re-runs the same investigation with the
LOCAL AI (Ollama); this connector imports cases produced by the upstream skill.

Modes: offline `file` (a saved export), else the bundled sample.json. Worker-safe: stdlib only,
ASCII-only output, no DB access.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

SOURCE = "CTI-Expert"
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _intel_from_stix(objs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for o in objs or []:
        if not isinstance(o, dict):
            continue
        t = o.get("type")
        if t in ("indicator", "observed-data", "domain-name", "ipv4-addr", "ipv6-addr",
                 "email-addr", "url", "user-account", "file"):
            sid = o.get("id") or ""
            name = o.get("name") or o.get("pattern") or o.get("value") or (o.get("number_observed") and "observed-data") or sid
            value = o.get("value") or o.get("pattern") or name
            desc = str(o.get("description") or "")
            labels = o.get("labels") or o.get("indicator_types") or []
            tags = ",".join(["cti-expert", "osint"] + [str(x) for x in labels])
            out.append({
                "name": str(name)[:200], "reference": f"cti-expert:{sid or value}",
                "external_id": str(sid or value)[:200], "description": desc[:1000],
                "tags": tags, "cve_tags": ",".join(sorted(set(_CVE.findall(desc + " " + str(name))))) or None,
            })
    return out


def _intel_from_case(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    target = str(case.get("target") or "").strip()
    kind = str(case.get("kind") or case.get("targetKind") or "target")
    sev = str(case.get("severity") or "")
    score = case.get("exposureScore")
    base_tags = ",".join(filter(None, ["cti-expert", "osint", kind, (f"exposure:{score}" if score is not None else ""), (sev.lower() if sev else "")]))
    # the INTSUM itself
    if target:
        out.append({
            "name": f"OSINT INTSUM - {target} ({sev or '?'})"[:200],
            "reference": f"cti-expert:case:{kind}:{target}", "external_id": f"{kind}:{target}"[:200],
            "description": str(case.get("brief") or case.get("summary") or "")[:1000], "tags": base_tags,
        })
    # each observable (IOC)
    for ob in case.get("observables") or []:
        if not isinstance(ob, dict):
            continue
        val = str(ob.get("value") or "").strip()
        if not val:
            continue
        out.append({
            "name": f"{ob.get('type', 'ioc')}: {val}"[:200], "reference": f"cti-expert:{val}",
            "external_id": val[:200], "description": f"OSINT observable from cti-expert case on {target}"[:1000],
            "tags": ",".join(["cti-expert", "osint", str(ob.get("type") or "ioc")]),
        })
    # each finding (as intel context)
    for f in case.get("findings") or []:
        if not isinstance(f, dict):
            continue
        tech = str(f.get("technique") or "finding")
        out.append({
            "name": f"{tech} - {target}"[:200], "reference": f"cti-expert:finding:{target}:{tech}"[:200],
            "external_id": f"{target}:{tech}"[:200], "description": str(f.get("finding") or "")[:1000],
            "tags": ",".join(filter(None, ["cti-expert", "finding", f"rel:{f.get('reliability')}", str(f.get('severity') or '').lower()])),
        })
    return out


def _normalize(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict) and data.get("type") == "bundle":
        return _intel_from_stix(data.get("objects") or [])
    if isinstance(data, list):
        return _intel_from_stix(data)
    if isinstance(data, dict) and (data.get("target") or data.get("observables") or data.get("findings")):
        return _intel_from_case(data)
    if isinstance(data, dict) and data.get("objects"):
        return _intel_from_stix(data["objects"])
    return []


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 500) or 500)
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    intel = _normalize(data)
    return {"source": SOURCE, "intel": intel[:limit]}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
