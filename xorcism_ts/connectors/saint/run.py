"""run.py — Import of a SAINT report (XML), best-effort.

SAINT has no universal XML schema depending on the version; this parser looks for
"vulnerability"/"vuln" nodes and extracts host / severity / CVE in a
flexible way. Adapt _field() if your export differs.

Result: {assets, vulns, services:[], cpes:[]}.
"""
from __future__ import annotations
import json
import re
import sys
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
       "area of concern": "medium", "potential problem": "low", "informational": "info"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _field(el: ET.Element, names: List[str]) -> str:
    for n in names:
        if el.get(n):
            return el.get(n).strip()
        child = el.find(n)
        if child is not None and (child.text or "").strip():
            return child.text.strip()
    return ""


def _sev(raw: str) -> str:
    r = raw.lower().strip()
    if r in SEV:
        return SEV[r]
    try:
        c = float(r)
        return "critical" if c >= 9 else "high" if c >= 7 else "medium" if c >= 4 else "low" if c > 0 else "info"
    except ValueError:
        return "medium"


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    path = params.get("file")
    if not path:
        raise ValueError("paramètre 'file' requis (rapport SAINT XML)")
    root = ET.parse(path).getroot()

    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    for el in root.iter():
        if el.tag.lower() not in ("vulnerability", "vuln", "finding"):
            continue
        host = _field(el, ["host", "ip", "target", "hostname", "address"])
        if not host:
            continue
        assets.setdefault(host, {"hostname": host, "ip": host, "key": host})
        name = _field(el, ["name", "title", "tutorial", "description", "class"]) or "SAINT finding"
        sev = _sev(_field(el, ["severity", "class", "cvss", "risk"]))
        text_blob = " ".join(el.itertext())
        cves = sorted(set(m.upper() for m in CVE_RE.findall(text_blob)))
        refs = cves or [("SAINT:%s:%s" % (host, name)).replace(" ", "_")]
        for ref in refs:
            vulns.append({"asset": host, "ref": ref, "name": name, "severity": sev})

    return {"assets": list(assets.values()), "vulns": vulns, "services": [], "cpes": []}


if __name__ == "__main__":
    print(json.dumps(run({"file": sys.argv[1]}, "."), indent=2, ensure_ascii=False))
