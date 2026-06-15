"""run.py — Import of a Greenbone/OpenVAS report (GMP XML).
<report> ... <results><result><host>IP</host><name>..</name><severity>7.5</severity>
<threat>High</threat><nvt oid=".."><refs><ref type="cve" id="CVE-.."/></refs></nvt></result>
Result: {assets, vulns, services:[], cpes:[]}."""
from __future__ import annotations
import json
import sys
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


def _sev_label(cvss: float, threat: str) -> str:
    if threat:
        t = threat.lower()
        if t in ("critical", "high", "medium", "low"):
            return t
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    path = params.get("file")
    if not path:
        raise ValueError("paramètre 'file' requis (rapport GMP)")
    min_cvss = float(params.get("min_cvss", 0.1) or 0.0)
    root = ET.parse(path).getroot()

    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    for result in root.iter("result"):
        host_el = result.find("host")
        host = (host_el.text or "").strip() if host_el is not None else ""
        if not host:
            continue
        try:
            cvss = float((result.findtext("severity") or "0").strip() or 0)
        except ValueError:
            cvss = 0.0
        if cvss < min_cvss:
            continue
        assets.setdefault(host, {"hostname": host, "ip": host, "key": host})
        name = (result.findtext("name") or "OpenVAS finding").strip()
        threat = (result.findtext("threat") or "").strip()
        nvt = result.find("nvt")
        cves: List[str] = []
        oid = ""
        if nvt is not None:
            oid = nvt.get("oid") or ""
            for ref in nvt.findall("./refs/ref"):
                if (ref.get("type") or "").lower() == "cve" and ref.get("id"):
                    cves.append(ref.get("id"))
        refs = cves or ([f"NVT:{oid}"] if oid else [f"OPENVAS:{name}"])
        for ref in refs:
            vulns.append({"asset": host, "ref": ref, "name": name, "severity": _sev_label(cvss, threat)})

    return {"assets": list(assets.values()), "vulns": vulns, "services": [], "cpes": []}


if __name__ == "__main__":
    print(json.dumps(run({"file": sys.argv[1]}, "."), indent=2, ensure_ascii=False))
