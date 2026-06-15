"""run.py — Qualys VMDR connector (Host List Detection API).

Config by environment variables ONLY:
    QUALYS_API_URL   e.g. https://qualysapi.qg3.apps.qualys.com
    QUALYS_USER, QUALYS_PASSWORD

Result: {assets, vulns:[{asset,ref,name,severity}], services:[], cpes:[]}.
"""
from __future__ import annotations
import json
import os
import sys
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

SEV = {"1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical"}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    import requests  # lazy
    url = os.environ.get("QUALYS_API_URL")
    user = os.environ.get("QUALYS_USER")
    pwd = os.environ.get("QUALYS_PASSWORD")
    if not (url and user and pwd):
        raise RuntimeError("définissez QUALYS_API_URL, QUALYS_USER, QUALYS_PASSWORD (variables d'environnement)")

    q = {"action": "list", "show_results": "1",
         "severities": ",".join(str(i) for i in range(int(params.get("min_severity", 2) or 1), 6))}
    if params.get("ips"):
        q["ips"] = str(params["ips"])
    r = requests.get(f"{url.rstrip('/')}/api/2.0/fo/asset/host/vm/detection/",
                     params=q, auth=(user, pwd),
                     headers={"X-Requested-With": "XORCISM"}, timeout=120)
    r.raise_for_status()
    root = ET.fromstring(r.content)

    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    for host in root.iter("HOST"):
        ip = (host.findtext("IP") or "").strip()
        dns = (host.findtext("DNS") or "").strip()
        key = dns or ip
        if not key:
            continue
        assets.setdefault(key, {"hostname": dns or ip, "ip": ip, "key": key})
        for det in host.findall("./DETECTION_LIST/DETECTION"):
            qid = (det.findtext("QID") or "").strip()
            sev = (det.findtext("SEVERITY") or "1").strip()
            if not qid:
                continue
            vulns.append({"asset": key, "ref": f"QID:{qid}",
                          "name": f"Qualys QID {qid}", "severity": SEV.get(sev, "info")})

    return {"assets": list(assets.values()), "vulns": vulns, "services": [], "cpes": []}


if __name__ == "__main__":
    print(json.dumps(run({}, "."), indent=2, ensure_ascii=False))
