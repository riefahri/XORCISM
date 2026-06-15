"""parse_depx.py — Parse the JSON output of ProjectDiscovery depx `audit`.

depx (https://github.com/projectdiscovery/depx) flags KNOWN MALICIOUS packages in
local lockfiles/SBOMs by cross-referencing the OpenSSF Malicious Packages dataset
and a live intelligence feed (supply-chain compromise: hijacked publishes,
credential stealers, install-script backdoors, typosquats).

Input format (versioned envelope, best-effort/defensive — exact field names vary
across depx versions): `{schema_version, command, version, total, results:[...]}`,
each result carrying a verdict ("malicious"/"clean"), a PURL, advisory id(s) and
advisory details. A bare list of results is also accepted.

Normalized result (consumed by runner.import_findings):
    {project, components:[{name,version,purl,cpe}],
     vulns:[{asset,ref,name,severity}], assets:[], cpes:[]}
Only MALICIOUS packages become findings; clean packages are ignored.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple


def _results(data: Any) -> List[Dict[str, Any]]:
    """Extract the results array from depx's versioned envelope (or a bare list)."""
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for key in ("results", "data", "findings", "packages", "items"):
            v = data.get(key)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
    return []


def _is_malicious(r: Dict[str, Any]) -> bool:
    v = str(r.get("verdict") or r.get("status") or r.get("classification") or "").lower()
    if v:
        return v in ("malicious", "compromised", "flagged", "suspicious", "vulnerable")
    # No verdict field present → `audit` typically only emits findings, so keep it.
    return True


def _purl(r: Dict[str, Any]) -> Optional[str]:
    for k in ("purl", "PURL", "package_url", "packageUrl"):
        x = r.get(k)
        if isinstance(x, str) and x.strip():
            return x.strip()
    return None


def _parse_purl(purl: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """`pkg:npm/@scope/name@1.2.3` → (name, version). Best-effort."""
    if not purl or not isinstance(purl, str):
        return None, None
    body = purl[4:] if purl.lower().startswith("pkg:") else purl
    body = body.split("?", 1)[0].split("#", 1)[0]  # drop qualifiers/subpath
    name, ver = (body.rsplit("@", 1) + [""])[:2] if "@" in body.rsplit("/", 1)[-1] else (body, "")
    if "/" in name:                       # strip the ecosystem prefix (npm/, pypi/…)
        name = name.split("/", 1)[1]
    name = name.replace("%40", "@")
    return (name or None), (ver or None)


def _ref(r: Dict[str, Any], purl: Optional[str]) -> Optional[str]:
    """Stable identifier → VULGUID. Prefer the published advisory id (MAL-…/GHSA-…/CVE-…)."""
    for k in ("ref", "id", "advisory_id", "advisoryId"):
        x = r.get(k)
        if isinstance(x, str) and x.strip():
            return x.strip()
    for k in ("advisory_ids", "advisories", "advisoryIds", "ids", "aliases"):
        xs = r.get(k)
        if isinstance(xs, list):
            for x in xs:
                if isinstance(x, str) and x.strip():
                    return x.strip()
                if isinstance(x, dict):
                    for kk in ("id", "ghsa_id", "cve", "cve_id"):
                        if x.get(kk):
                            return str(x[kk])
    adv = r.get("advisory")
    if isinstance(adv, dict):
        for kk in ("id", "ghsa_id", "cve"):
            if adv.get(kk):
                return str(adv[kk])
    # Fallback: synthesize a deterministic id from the package.
    base = purl or r.get("package") or r.get("name")
    return f"DEPX-{re.sub(r'[^A-Za-z0-9._@/:-]+', '_', str(base))}" if base else None


def _name(r: Dict[str, Any], purl: Optional[str]) -> str:
    adv = r.get("advisory") if isinstance(r.get("advisory"), dict) else {}
    for src in (r, adv):
        for k in ("title", "summary", "description", "details", "message"):
            x = src.get(k)
            if isinstance(x, str) and x.strip():
                return x.strip()[:300]
    return f"Malicious package: {purl or r.get('package') or r.get('name') or '?'}"


def _severity(r: Dict[str, Any]) -> str:
    adv = r.get("advisory") if isinstance(r.get("advisory"), dict) else {}
    sev = r.get("severity") or adv.get("severity")
    if isinstance(sev, str) and sev.strip():
        s = sev.strip().lower()
        if s in ("critical", "high", "medium", "moderate", "low", "info"):
            return "medium" if s == "moderate" else s
    # A confirmed malicious package is critical by nature.
    return "critical"


def parse(output: str, params: Dict[str, Any]) -> Dict[str, Any]:
    with open(output, "r", encoding="utf-8") as f:
        data = json.load(f)

    project = (params or {}).get("project") or "depx audit"
    components: List[Dict[str, Any]] = []
    vulns: List[Dict[str, Any]] = []
    seen_refs: set = set()

    for r in _results(data):
        if not _is_malicious(r):
            continue
        purl = _purl(r)
        name, version = _parse_purl(purl)
        if name:
            components.append({"name": name, "version": version, "purl": purl, "cpe": None})
        ref = _ref(r, purl)
        if not ref or ref in seen_refs:
            continue
        seen_refs.add(ref)
        vulns.append({
            "asset": project,
            "ref": ref,
            "name": _name(r, purl),
            "severity": _severity(r),
        })

    return {
        "project": project,
        "components": components,
        "vulns": vulns,
        "assets": [],
        "cpes": [],
    }
