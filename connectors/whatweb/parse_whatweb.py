"""parse_whatweb.py — Parses the WhatWeb output (--log-json) → technologies as CPE.
Skips metadata plugins (country, headers, …) and captures the resolved IP.
Normalized result: {assets:[{hostname,ip,key}], services:[{asset,cpe,name}], cpes:[...], vulns:[]}."""
from __future__ import annotations
import json
import os
import sys
import urllib.parse
from typing import Any, Dict, List, Optional

# WhatWeb plugins that are metadata / response headers, not technologies — kept
# out of the tech & CPE component list to avoid polluting the asset inventory.
_META = {
    "ip", "country", "title", "uncommonheaders", "cookies", "email", "html5",
    "redirectlocation", "object", "frame", "script", "meta-author", "meta-refresh",
    "via-proxy", "x-frame-options", "strict-transport-security", "x-xss-protection",
    "content-security-policy", "access-control-allow-origin", "httponly",
    "x-content-type-options", "allow", "ipaddress",
}


def _hostname(t: str) -> Optional[str]:
    if not t:
        return None
    u = urllib.parse.urlparse(t if "://" in t else "//" + t)
    return u.hostname or t


def _first(info: Any, key: str) -> str:
    v = (info or {}).get(key) or []
    return str(v[0]) if v else ""


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
        plugins = e.get("plugins") or {}
        asset = assets.setdefault(host, {"hostname": host, "key": host})
        ip = _first(plugins.get("IP"), "string")  # WhatWeb resolves the target IP
        if ip and not asset.get("ip"):
            asset["ip"] = ip
        for plugin, info in plugins.items():
            if str(plugin).lower() in _META:
                continue
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
