"""parse_wpscan.py — Parses the JSON output of WPScan (--format json).

WPScan exposes the vulnerabilities under version (core), plugins, main_theme and
themes; each vulnerability has a "title" and "references" (including cve).
We prefer the CVE reference (dedup with the NVD import), otherwise a stable
synthetic reference (WPSCAN-<hash>).

Normalized result: {assets:[{hostname,key}], services:[], cpes:[],
                      vulns:[{asset,ref,name,severity}]}.
"""
from __future__ import annotations
import hashlib
import json
import os
import urllib.parse
from typing import Any, Dict, List, Optional


def _hostname(t: str) -> Optional[str]:
    if not t:
        return None
    u = urllib.parse.urlparse(t if "://" in t else "//" + t)
    return u.hostname or t


def parse(path_or_text: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    raw = open(path_or_text, "r", encoding="utf-8", errors="replace").read() \
        if os.path.exists(path_or_text) else path_or_text
    data = json.loads(raw)
    if not isinstance(data, dict):
        return {"assets": [], "services": [], "cpes": [], "vulns": []}

    host = _hostname(data.get("target_url") or (params or {}).get("target", ""))
    assets = {host: {"hostname": host, "key": host}} if host else {}
    vulns: List[Dict[str, Any]] = []

    def add(vlist: Any, source: str) -> None:
        for v in vlist or []:
            if not isinstance(v, dict):
                continue
            cves = ((v.get("references") or {}).get("cve")) or []
            if cves:
                ref = "CVE-" + str(cves[0])
            else:
                ref = "WPSCAN-" + hashlib.sha1(f"{source}|{v.get('title','')}".encode("utf-8")).hexdigest()[:12]
            title = str(v.get("title") or source)
            vulns.append({"asset": host, "ref": ref, "name": f"{source}: {title}"[:200], "severity": "high"})

    # WordPress core
    add(((data.get("version") or {}).get("vulnerabilities")), "WordPress core")
    # Plugins (dict name → info)
    for name, info in (data.get("plugins") or {}).items():
        add((info or {}).get("vulnerabilities"), f"plugin {name}")
    # Main theme + themes
    mt = data.get("main_theme") or {}
    if isinstance(mt, dict):
        add(mt.get("vulnerabilities"), f"theme {mt.get('slug') or 'main'}")
    for name, info in (data.get("themes") or {}).items():
        add((info or {}).get("vulnerabilities"), f"theme {name}")

    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}


if __name__ == "__main__":
    import sys
    print(json.dumps(parse(sys.argv[1]), indent=2, ensure_ascii=False))
