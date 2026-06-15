"""parse_osv.py — Parses the JSON output of OSV-Scanner.

OSV-Scanner (https://google.github.io/osv-scanner/) analyzes lockfiles, SBOMs and
code directories for known vulnerabilities via OSV.dev.

Input format: results[].packages[].{package, vulnerabilities[], groups[]}.
Normalized result (imported by runner.import_findings):
    {project, components:[{name,version,purl,cpe}],
     vulns:[{asset,ref,name,severity}], assets:[], cpes:[]}
"""
from __future__ import annotations
import json
from typing import Any, Dict, List, Optional


def _band(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _severity(vuln: Dict[str, Any], pkg: Dict[str, Any]) -> str:
    # GHSA and the like place a textual severity in database_specific.
    ds = (vuln.get("database_specific") or {}).get("severity")
    if ds:
        return str(ds).lower()
    # OSV-Scanner aggregates a max CVSS score per vulnerability group.
    for g in pkg.get("groups", []) or []:
        ms = g.get("max_severity")
        if ms not in (None, "", "0"):
            try:
                return _band(float(ms))
            except (TypeError, ValueError):
                pass
    return "unknown"


def _ref(vuln: Dict[str, Any]) -> Optional[str]:
    # Prefers the CVE alias (dedup with the NVD import), otherwise the OSV/GHSA id.
    for a in vuln.get("aliases", []) or []:
        if isinstance(a, str) and a.upper().startswith("CVE-"):
            return a
    return vuln.get("id")


def parse(output: str, params: Dict[str, Any]) -> Dict[str, Any]:
    with open(output, "r", encoding="utf-8") as f:
        data = json.load(f)

    project = (params or {}).get("project") or "OSV-Scanner scan"
    components: List[Dict[str, Any]] = []
    vulns: List[Dict[str, Any]] = []

    for res in data.get("results", []) or []:
        for pkg in res.get("packages", []) or []:
            p = pkg.get("package") or {}
            if p.get("name"):
                components.append({
                    "name": p.get("name"),
                    "version": p.get("version"),
                    "purl": p.get("purl"),
                    "cpe": None,
                })
            for v in pkg.get("vulnerabilities", []) or []:
                ref = _ref(v)
                if not ref:
                    continue
                vulns.append({
                    "asset": project,
                    "ref": ref,
                    "name": v.get("summary") or v.get("id"),
                    "severity": _severity(v, pkg),
                })

    return {
        "project": project,
        "components": components,
        "vulns": vulns,
        "assets": [],
        "cpes": [],
    }
