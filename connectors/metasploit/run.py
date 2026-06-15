"""run.py — Import of a Metasploit export (db_export -f xml, root <MetasploitV5>/<MetasploitV4>).
hosts/host → ASSET; services → services; vulns/vuln (CVE refs) → VULNERABILITY + links.
Result: {assets, services, vulns, cpes:[]}."""
from __future__ import annotations
import json
import re
import sys
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _txt(el, tag: str) -> str:
    c = el.find(tag)
    return (c.text or "").strip() if c is not None and c.text else ""


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    path = params.get("file")
    if not path:
        raise ValueError("paramètre 'file' requis (export Metasploit XML)")
    root = ET.parse(path).getroot()

    assets: Dict[str, Dict[str, Any]] = {}
    services: List[Dict[str, Any]] = []
    vulns: List[Dict[str, Any]] = []
    for host in root.iter("host"):
        addr = _txt(host, "address")
        name = _txt(host, "name") or addr
        key = name or addr
        if not key:
            continue
        assets.setdefault(key, {"hostname": name or addr, "ip": addr, "key": key, "os": _txt(host, "os_name")})
        for svc in host.findall("./services/service"):
            services.append({"asset": key, "name": _txt(svc, "name"), "port": _txt(svc, "port")})
        for vuln in host.findall("./vulns/vuln"):
            vname = _txt(vuln, "name") or "Metasploit vuln"
            refs_raw = " ".join(r.text or "" for r in vuln.findall("./refs/ref"))
            cves = sorted(set(m.upper() for m in CVE_RE.findall(refs_raw)))
            refs = cves or [("MSF:%s:%s" % (key, vname)).replace(" ", "_")]
            for ref in refs:
                vulns.append({"asset": key, "ref": ref, "name": vname, "severity": "high"})

    return {"assets": list(assets.values()), "services": services, "vulns": vulns, "cpes": []}


if __name__ == "__main__":
    print(json.dumps(run({"file": sys.argv[1]}, "."), indent=2, ensure_ascii=False))
