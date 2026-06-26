"""run.py — XORCISM connector for Xygeni (Software Supply Chain Security / ASPM).

Xygeni (https://xygeni.io) secures the SDLC: SAST, SCA/SBOM, secrets, IaC, container, malicious-
package (malware) detection, CI/CD-misconfiguration and build/pipeline SLSA provenance. This
connector imports its findings + supply-chain posture into XORCISM:
  * each project           -> the project context (asset)
  * each SCA vulnerability  -> a vulnerability (CVE-linked where present) on the project asset
  * secrets / IaC / SAST / malicious-package issues -> findings on the project asset

Modes (in order):
    live    : XYGENI_API_TOKEN -> GET findings from XYGENI_API_URL (default https://api.xygeni.io).
    offline : params["file"]   -> parse a saved Xygeni export.
    demo    : neither          -> import the bundled sample.json.

Normalized result: {project, assets:[...], vulns:[...]} -> runner.import_findings. Worker-safe:
stdlib only, secrets via env, ASCII-only output, no DB access.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any, Dict, List

_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
        "info": "info", "informational": "info", "blocker": "critical", "major": "high", "minor": "low"}
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _sev(s: Any) -> str:
    return _SEV.get(str(s or "").strip().lower(), "medium")


def _http(url: str, headers: Dict[str, str], timeout: int = 90) -> Any:
    req = urllib.request.Request(url, method="GET", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8", "replace") or "null")


def _rows(data: Any, *keys: str) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for k in keys + ("findings", "results", "data", "items", "issues", "content"):
            v = data.get(k)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
    return []


def _normalize(findings: List[Dict[str, Any]], project: str) -> Dict[str, Any]:
    asset = project or "Xygeni project"
    assets = [{"hostname": asset, "key": asset, "tags": "xygeni,sscs,aspm,supply-chain"}]
    vulns: List[Dict[str, Any]] = []
    for f in findings:
        cat = str(f.get("category") or f.get("type") or f.get("kind") or f.get("subcategory") or "finding").lower()
        title = str(f.get("title") or f.get("name") or f.get("message") or f.get("ruleName") or cat)
        sev = _sev(f.get("severity") or f.get("priority") or f.get("risk"))
        # CVE either explicit or scraped from the title/refs
        cve = f.get("cve") or f.get("cveId") or f.get("vulnId")
        if not cve:
            m = _CVE.search(json.dumps(f)[:600])
            cve = m.group(0).upper() if m else None
        comp = f.get("component") or f.get("package") or f.get("dependency") or {}
        comp_name = comp.get("name") if isinstance(comp, dict) else (str(comp) if comp else None)
        loc = f.get("file") or f.get("path") or f.get("location") or comp_name or ""
        fid = str(f.get("id") or f.get("uid") or f.get("fingerprint") or title)[:60]
        if "sca" in cat or "depend" in cat or "component" in cat or cve:
            ref = cve or f"XYGENI-SCA-{fid}"
            name = f"{title}" + (f" ({comp_name})" if comp_name else "")
        elif "secret" in cat:
            ref = f"XYGENI-SECRET-{fid}"; name = f"Exposed secret: {title}" + (f" @ {loc}" if loc else "")
        elif "malware" in cat or "malicious" in cat:
            ref = f"XYGENI-MALPKG-{fid}"; name = f"Malicious package: {title}" + (f" ({comp_name})" if comp_name else ""); sev = "critical"
        elif "iac" in cat or "terraform" in cat or "k8s" in cat:
            ref = f"XYGENI-IAC-{fid}"; name = f"IaC misconfiguration: {title}" + (f" @ {loc}" if loc else "")
        elif "ci" in cat or "pipeline" in cat or "build" in cat or "slsa" in cat:
            ref = f"XYGENI-CICD-{fid}"; name = f"CI/CD / build-integrity: {title}"
        else:  # SAST / other
            ref = f"XYGENI-SAST-{fid}"; name = f"{title}" + (f" @ {loc}" if loc else "")
        vulns.append({"asset": asset, "ref": ref, "name": name[:280], "severity": sev})
    return {"project": f"Xygeni: {project}" if project else "Xygeni", "assets": assets, "services": [], "cpes": [], "vulns": vulns}


def _live(base: str, token: str, limit: int) -> Dict[str, Any]:
    base = base.rstrip("/")
    h = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    project = ""
    try:
        projs = _rows(_http(f"{base}/v1/projects?limit=1", h), "projects")
        project = str((projs[0].get("name") if projs else "") or "")
    except Exception:  # noqa: BLE001
        pass
    findings: List[Dict[str, Any]] = []
    for path in (f"/v1/findings?limit={limit}", f"/v1/issues?limit={limit}", "/v1/findings"):
        try:
            findings = _rows(_http(f"{base}{path}", h), "findings", "issues")
            if findings:
                break
        except Exception:  # noqa: BLE001
            continue
    return _normalize(findings[:limit], project)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 1000) or 1000)
    base = (os.environ.get("XYGENI_API_URL") or "https://api.xygeni.io").strip()
    token = (os.environ.get("XYGENI_API_TOKEN") or "").strip()
    if token:
        return _live(base, token, limit)
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    project = str((data.get("project") or data.get("projectName") or "") if isinstance(data, dict) else "")
    findings = _rows(data, "findings", "issues") or (_rows(data) if isinstance(data, list) else [])
    return _normalize(findings[:limit], project)


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
