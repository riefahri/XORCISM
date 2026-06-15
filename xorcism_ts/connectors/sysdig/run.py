"""run.py — Import of Sysdig Secure runtime vulnerabilities via the REST API.

GET of the runtime results; each result (workload/image) with its
vulnerabilities → ASSET + linked findings (CVE).

Config (worker environment variables, never entered in the UI):
    SYSDIG_URL         base, e.g. https://app.us4.sysdig.com               (REQUIRED)
    SYSDIG_API_TOKEN   Bearer token                                       (REQUIRED)
    SYSDIG_PATH        endpoint (default /secure/vulnerability/v1/runtime-results)
    SYSDIG_VERIFY_TLS  true/false (default true)

Normalized result: {assets, services:[], cpes:[], vulns}.
"""
from __future__ import annotations
import os
from typing import Any, Dict, List


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes")


def _asset_name(item: Dict[str, Any]) -> str:
    for k in ("workloadName", "mainAssetName", "assetName", "image", "imageName", "hostName", "host"):
        v = item.get(k)
        if v:
            return str(v)
    res = item.get("resource") or item.get("scope") or {}
    if isinstance(res, dict):
        return str(res.get("name") or res.get("hostName") or "")
    return ""


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    import requests

    base = (os.getenv("SYSDIG_URL") or "").rstrip("/")
    token = os.getenv("SYSDIG_API_TOKEN")
    if not base or not token:
        raise RuntimeError("SYSDIG_URL et SYSDIG_API_TOKEN requis (env worker)")
    path = os.getenv("SYSDIG_PATH", "/secure/vulnerability/v1/runtime-results")
    verify = _env_bool("SYSDIG_VERIFY_TLS", True)
    limit = int(params.get("limit", 200) or 200)

    r = requests.get(
        f"{base}{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        params={"limit": limit}, verify=verify, timeout=120,
    )
    r.raise_for_status()
    payload = r.json() or {}
    items = payload.get("data") or payload.get("results") or (payload if isinstance(payload, list) else [])

    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict):
            continue
        host = _asset_name(it)
        if not host:
            continue
        assets.setdefault(host, {"hostname": host, "key": host})
        vlist = it.get("vulnerabilities") or it.get("vulns") or []
        if isinstance(vlist, dict):  # sometimes a per-severity counter, not a list
            vlist = []
        for v in vlist:
            if not isinstance(v, dict):
                continue
            cve = str(v.get("name") or v.get("cve") or v.get("vulnId") or "").strip()
            if not cve:
                continue
            ref = cve if cve.upper().startswith("CVE-") else f"SYSDIG-{cve}"
            sev = str(v.get("severity") or "medium").lower()
            vulns.append({"asset": host, "ref": ref, "name": cve[:200], "severity": sev})

    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}
