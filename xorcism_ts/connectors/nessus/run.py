"""run.py — Import of a Nessus file (.nessus / NessusClientData_v2).
ReportHost → ASSET; ReportItem (severity >= min) → VULNERABILITY (CVE if present,
otherwise Nessus:pluginID) + ASSETVULNERABILITY link.
Result: {assets, vulns, services, cpes:[]}."""
from __future__ import annotations
import json
import sys
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

SEV = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}


def _host_name(rh: ET.Element) -> str:
    props = {t.get("name"): (t.text or "") for t in rh.findall("./HostProperties/tag")}
    return props.get("host-fqdn") or props.get("host-ip") or rh.get("name") or "unknown-host"


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    path = params.get("file")
    if not path:
        raise ValueError("paramètre 'file' requis (.nessus)")
    min_sev = int(params.get("min_severity", 1) or 0)
    root = ET.parse(path).getroot()

    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    for rh in root.iter("ReportHost"):
        host = _host_name(rh)
        ip = next((t.text for t in rh.findall("./HostProperties/tag") if t.get("name") == "host-ip"), None)
        assets.setdefault(host, {"hostname": host, "ip": ip, "key": host})
        for item in rh.findall("ReportItem"):
            sev = int(item.get("severity") or "0")
            if sev < min_sev:
                continue
            cves = [c.text.strip() for c in item.findall("cve") if c.text]
            pid = item.get("pluginID") or "0"
            name = item.get("pluginName") or f"Nessus plugin {pid}"
            refs = cves or [f"NESSUS:{pid}"]
            for ref in refs:
                vulns.append({"asset": host, "ref": ref, "name": name, "severity": SEV.get(str(sev), "info")})
            svc = item.get("svc_name")
            if svc:
                services.append({"asset": host, "name": svc, "port": item.get("port")})

    return {"assets": list(assets.values()), "vulns": vulns, "services": services, "cpes": []}


if __name__ == "__main__":
    print(json.dumps(run({"file": sys.argv[1]}, "."), indent=2, ensure_ascii=False))
