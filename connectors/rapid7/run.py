"""run.py — Rapid7 InsightVM connector (API v3, Nexpose console).

Config by environment variables ONLY:
    R7_API_URL    e.g. https://console:3780
    R7_API_USER, R7_API_PASSWORD
    R7_INSECURE   "1" to ignore TLS validation (lab only)

Result: {assets, vulns:[{asset,ref,name,severity}], services:[], cpes:[]}.
"""
from __future__ import annotations
import json
import os
import re
import sys
from typing import Any, Dict, List

CVE_RE = re.compile(r"cve-\d{4}-\d{4,7}", re.I)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    import requests  # lazy
    url = os.environ.get("R7_API_URL")
    user = os.environ.get("R7_API_USER")
    pwd = os.environ.get("R7_API_PASSWORD")
    if not (url and user and pwd):
        raise RuntimeError("définissez R7_API_URL, R7_API_USER, R7_API_PASSWORD (variables d'environnement)")
    url = url.rstrip("/")
    auth = (user, pwd)
    verify = os.environ.get("R7_INSECURE", "") not in ("1", "true", "yes")
    max_assets = int(params.get("max_assets", 200) or 200)

    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    page, size = 0, min(max_assets, 500)
    fetched = 0
    while fetched < max_assets:
        r = requests.get(f"{url}/api/3/assets", params={"page": page, "size": size},
                         auth=auth, verify=verify, timeout=60)
        r.raise_for_status()
        resources = r.json().get("resources", [])
        if not resources:
            break
        for a in resources:
            fetched += 1
            aid = a.get("id")
            host = (a.get("hostName") or (a.get("hostNames") or [{}])[0].get("name")
                    or a.get("ip") or str(aid))
            key = str(host)
            assets.setdefault(key, {"hostname": host, "ip": a.get("ip"), "key": key,
                                    "os": a.get("os")})
            vr = requests.get(f"{url}/api/3/assets/{aid}/vulnerabilities",
                              params={"size": 500}, auth=auth, verify=verify, timeout=60)
            if vr.status_code != 200:
                continue
            for v in vr.json().get("resources", []):
                vid = v.get("id") or ""
                cves = sorted(set(m.upper() for m in CVE_RE.findall(vid)))
                refs = cves or [f"R7:{vid}"]
                for ref in refs:
                    vulns.append({"asset": key, "ref": ref, "name": vid or ref,
                                  "severity": "medium"})
            if fetched >= max_assets:
                break
        page += 1

    return {"assets": list(assets.values()), "vulns": vulns, "services": [], "cpes": []}


if __name__ == "__main__":
    print(json.dumps(run({}, "."), indent=2, ensure_ascii=False))
