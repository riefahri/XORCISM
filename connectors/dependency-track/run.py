"""run.py — SBOM management (OWASP Dependency-Track).

Two modes:
  • local (default): reads a CycloneDX JSON SBOM → components (CPE/PURL linked to
    the application) + vulnerabilities declared in the SBOM ("vulnerabilities" section).
  • api (api=true): pushes the SBOM to Dependency-Track and retrieves the findings.
    Configuration ONLY by environment variables (never entered here):
        DTRACK_URL      e.g. http://dtrack.lab:8081
        DTRACK_API_KEY  Dependency-Track API key

Result: {project, components:[{name,version,purl,cpe}], vulns:[{asset,ref,name,severity}], assets:[], cpes:[]}
"""
from __future__ import annotations
import base64
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

CDX_SEV = {"critical": "critical", "high": "high", "medium": "medium",
           "low": "low", "info": "info", "unassigned": "info", "none": "info"}


def _load_sbom(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _parse_local(bom: Dict[str, Any], project: Optional[str]) -> Dict[str, Any]:
    meta_comp = (bom.get("metadata") or {}).get("component") or {}
    project = project or meta_comp.get("name") or "SBOM application"

    components: List[Dict[str, Any]] = []
    for c in bom.get("components", []) or []:
        components.append({
            "name": c.get("name"), "version": c.get("version"),
            "purl": c.get("purl"), "cpe": c.get("cpe"),
        })

    vulns: List[Dict[str, Any]] = []
    for v in bom.get("vulnerabilities", []) or []:
        ref = v.get("id")
        if not ref:
            continue
        ratings = v.get("ratings") or []
        sev = "info"
        for r in ratings:
            sev = CDX_SEV.get(str(r.get("severity", "")).lower(), sev)
            if sev != "info":
                break
        vulns.append({"asset": None, "ref": ref, "name": ref, "severity": sev})

    return {"project": project, "components": components, "vulns": vulns, "assets": [], "cpes": []}


def _api(bom_path: str, project: str, version: str) -> Dict[str, Any]:
    import requests  # lazy
    url = os.environ.get("DTRACK_URL")
    key = os.environ.get("DTRACK_API_KEY")
    if not url or not key:
        raise RuntimeError("mode API : définissez DTRACK_URL et DTRACK_API_KEY (variables d'environnement)")
    url = url.rstrip("/")
    hdr = {"X-Api-Key": key}

    with open(bom_path, "rb") as f:
        bom_b64 = base64.b64encode(f.read()).decode("ascii")
    requests.put(f"{url}/api/v1/bom", headers=hdr, json={
        "projectName": project, "projectVersion": version,
        "autoCreate": True, "bom": bom_b64,
    }, timeout=60).raise_for_status()

    # Project resolution + waiting for the analysis
    proj = requests.get(f"{url}/api/v1/project/lookup",
                        headers=hdr, params={"name": project, "version": version}, timeout=30)
    proj.raise_for_status()
    uuid = proj.json().get("uuid")
    findings: List[Dict[str, Any]] = []
    for _ in range(30):
        r = requests.get(f"{url}/api/v1/finding/project/{uuid}", headers=hdr, timeout=30)
        if r.status_code == 200:
            findings = r.json()
            if findings:
                break
        time.sleep(5)

    vulns: List[Dict[str, Any]] = []
    for fnd in findings:
        vuln = fnd.get("vulnerability") or {}
        ref = vuln.get("vulnId") or vuln.get("uuid")
        if not ref:
            continue
        vulns.append({"asset": None, "ref": ref, "name": ref,
                      "severity": CDX_SEV.get(str(vuln.get("severity", "")).lower(), "info")})
    return {"project": project, "components": [], "vulns": vulns, "assets": [], "cpes": []}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    path = params.get("file")
    if not path:
        raise ValueError("paramètre 'file' requis (SBOM CycloneDX)")
    bom = _load_sbom(path)
    local = _parse_local(bom, params.get("project"))
    if str(params.get("api", "")).lower() in ("1", "true", "yes"):
        api_res = _api(path, local["project"], str(params.get("version", "1.0")))
        # components from the local SBOM + findings from Dependency-Track
        local["vulns"] = api_res["vulns"] or local["vulns"]
    return local


if __name__ == "__main__":
    print(json.dumps(run({"file": sys.argv[1]}, "."), indent=2, ensure_ascii=False))
