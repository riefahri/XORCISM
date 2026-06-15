"""run.py — Import of a w3af XML report (plugin output xml_file).
Structure: <w3af-run> ... <vulnerability id=[..] name=".." severity="High" url="http://.." var=".." plugin="..">
Result: {assets, vulns, services:[], cpes:[]}."""
from __future__ import annotations
import json
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

SEV = {"information": "info", "low": "low", "medium": "medium", "high": "high"}


def _host(url: str) -> Optional[str]:
    try:
        return urllib.parse.urlparse(url).hostname
    except Exception:
        return None


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    path = params.get("file")
    if not path:
        raise ValueError("paramètre 'file' requis (rapport XML w3af)")
    root = ET.parse(path).getroot()

    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    for v in root.iter("vulnerability"):
        url = v.get("url") or ""
        host = _host(url) or url or "w3af-target"
        assets.setdefault(host, {"hostname": host, "key": host})
        name = v.get("name") or "w3af finding"
        var = v.get("var") or ""
        sev = SEV.get((v.get("severity") or "").lower(), "medium")
        ref = ("W3AF:%s:%s:%s" % (host, name, var)).replace(" ", "_")
        vulns.append({"asset": host, "ref": ref, "name": name + (f" ({var})" if var else ""), "severity": sev})

    return {"assets": list(assets.values()), "vulns": vulns, "services": [], "cpes": []}


if __name__ == "__main__":
    print(json.dumps(run({"file": sys.argv[1]}, "."), indent=2, ensure_ascii=False))
