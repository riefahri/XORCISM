"""run.py — Burp Suite Professional connector (REST API).

Config by environment variables ONLY (never entered in the UI):
    BURP_API_URL   e.g. http://127.0.0.1:1337
    BURP_API_KEY   Burp API key (path component) — optional depending on the config

Either `target` (starts a scan and waits), or `scan_id` (re-reads an existing scan).
Result: {assets, vulns:[{asset,ref,name,severity}], services:[], cpes:[]}.
"""
from __future__ import annotations
import json
import os
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional

SEV = {"high": "high", "medium": "medium", "low": "low",
       "info": "info", "information": "info"}


def _base() -> str:
    url = os.environ.get("BURP_API_URL")
    if not url:
        raise RuntimeError("BURP_API_URL non défini (variable d'environnement)")
    key = os.environ.get("BURP_API_KEY")
    url = url.rstrip("/")
    return f"{url}/{key}/v0.1" if key else f"{url}/v0.1"


def _host(url: str) -> Optional[str]:
    try:
        return urllib.parse.urlparse(url).hostname
    except Exception:
        return None


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    import requests  # lazy
    base = _base()
    scan_id = params.get("scan_id")
    target = params.get("target")

    if not scan_id:
        if not target:
            raise ValueError("fournir 'target' (nouveau scan) ou 'scan_id' (relecture)")
        r = requests.post(f"{base}/scan", json={"urls": [str(target)]}, timeout=30)
        r.raise_for_status()
        loc = r.headers.get("Location", "")
        scan_id = loc.rstrip("/").split("/")[-1] or r.json().get("scan_id")
        deadline = time.time() + int(params.get("max_wait", 1800) or 0)
        while time.time() < deadline:
            st = requests.get(f"{base}/scan/{scan_id}", timeout=30).json()
            if st.get("scan_status") in ("succeeded", "failed", "paused"):
                break
            time.sleep(10)

    data = requests.get(f"{base}/scan/{scan_id}", timeout=30).json()
    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    for ev in data.get("issue_events", []):
        issue = ev.get("issue") or {}
        origin = issue.get("origin") or ""
        path = issue.get("path") or ""
        host = _host(origin) or _host(str(target or "")) or origin or "burp-target"
        assets.setdefault(host, {"hostname": host, "key": host})
        name = issue.get("name") or "Burp issue"
        sev = SEV.get(str(issue.get("severity", "")).lower(), "info")
        ref = ("BURP:%s:%s" % (name, path)).replace(" ", "_")
        vulns.append({"asset": host, "ref": ref, "name": name, "severity": sev})

    return {"assets": list(assets.values()), "vulns": vulns, "services": [], "cpes": []}


if __name__ == "__main__":
    print(json.dumps(run({"scan_id": sys.argv[1] if len(sys.argv) > 1 else None}, "."), indent=2, ensure_ascii=False))
