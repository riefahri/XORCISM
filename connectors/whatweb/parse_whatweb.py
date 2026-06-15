"""parse_whatweb.py — Parses the WhatWeb output (--log-json) → technologies as CPE.
Normalized result: {assets:[{hostname,key}], services:[{asset,cpe,name}], cpes:[...], vulns:[]}."""
from __future__ import annotations
import json
import os
import sys
import urllib.parse
from typing import Any, Dict, List, Optional


def _hostname(t: str) -> Optional[str]:
    if not t:
        return None
    u = urllib.parse.urlparse(t if "://" in t else "//" + t)
    return u.hostname or t


def parse(path_or_text: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    raw = open(path_or_text, "r", encoding="utf-8", errors="replace").read() if os.path.exists(path_or_text) else path_or_text
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = [json.loads(l) for l in raw.splitlines() if l.strip()]
    entries = data if isinstance(data, list) else [data]

    assets: Dict[str, Dict[str, Any]] = {}
    services: List[Dict[str, Any]] = []
    cpes: set = set()
    for e in entries:
        if not isinstance(e, dict):
            continue
        host = _hostname(e.get("target", ""))
        if not host:
            continue
        assets.setdefault(host, {"hostname": host, "key": host})
        for plugin, info in (e.get("plugins") or {}).items():
            versions = (info or {}).get("version") or []
            if versions:
                for v in versions:
                    label = f"cpe:/a:*:{str(plugin).lower()}:{v}"
                    cpes.add(label)
                    services.append({"asset": host, "cpe": label, "name": plugin})
            else:
                label = f"tech:{plugin}"
                cpes.add(label)
                services.append({"asset": host, "cpe": label, "name": plugin})
    return {"assets": list(assets.values()), "services": services, "cpes": sorted(cpes), "vulns": []}


if __name__ == "__main__":
    print(json.dumps(parse(sys.argv[1]), indent=2, ensure_ascii=False))
