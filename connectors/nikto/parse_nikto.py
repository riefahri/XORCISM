"""parse_nikto.py — Parses the JSON output of Nikto (-Format json).

Nikto produces an object (or a list of scans) containing the target and a list of
"vulnerabilities": {id/OSVDB, method, url, msg}. These findings don't
always have a CVE → we synthesize a stable reference (NIKTO-<id|hash>).

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
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Nikto sometimes emits several concatenated JSON objects (one per host).
        data = [json.loads(l) for l in raw.splitlines() if l.strip().startswith("{")]

    scans = data if isinstance(data, list) else [data]
    fallback_host = _hostname((params or {}).get("target", ""))

    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    for scan in scans:
        if not isinstance(scan, dict):
            continue
        host = scan.get("host") or _hostname(scan.get("targetname") or "") or fallback_host
        if not host:
            continue
        assets.setdefault(host, {"hostname": host, "key": host})
        for v in scan.get("vulnerabilities", []) or []:
            if not isinstance(v, dict):
                continue
            msg = str(v.get("msg") or v.get("message") or "").strip()
            url = str(v.get("url") or "")
            vid = v.get("id") or v.get("OSVDB")
            if vid and str(vid) not in ("0", ""):
                ref = f"NIKTO-{vid}"
            else:
                ref = "NIKTO-" + hashlib.sha1(f"{host}|{url}|{msg}".encode("utf-8")).hexdigest()[:12]
            name = (f"{url} — {msg}" if url else msg)[:200] or ref
            vulns.append({"asset": host, "ref": ref, "name": name, "severity": "info"})

    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}
