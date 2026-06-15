"""parse_sqlmap.py — Parses the text output of sqlmap → SQL injection points.
Result: {assets, vulns:[{asset,ref,name,severity}], services:[], cpes:[]}."""
from __future__ import annotations
import json
import os
import re
import sys
import urllib.parse
from typing import Any, Dict, List, Optional


def parse(path_or_text: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    raw = open(path_or_text, "r", encoding="utf-8", errors="replace").read() if os.path.exists(path_or_text) else path_or_text
    host: Optional[str] = None
    if params and params.get("target"):
        host = urllib.parse.urlparse(str(params["target"])).hostname
    if not host:
        m = re.search(r"target URL.*?https?://([^/\s:]+)", raw, re.I)
        host = m.group(1) if m else None

    vulns: List[Dict[str, Any]] = []
    cur_param: Optional[str] = None
    for line in raw.splitlines():
        mp = re.match(r"\s*Parameter:\s*(.+)", line)
        if mp:
            cur_param = mp.group(1).strip()
            continue
        mt = re.match(r"\s*Type:\s*(.+)", line)
        if mt and cur_param:
            typ = mt.group(1).strip()
            ref = ("SQLI:%s:%s:%s" % (host or "target", cur_param, typ)).replace(" ", "_")
            vulns.append({"asset": host, "ref": ref,
                          "name": f"SQL Injection — {cur_param} ({typ})", "severity": "high"})

    assets = [{"hostname": host, "key": host}] if host else []
    return {"assets": assets, "vulns": vulns, "services": [], "cpes": []}


if __name__ == "__main__":
    print(json.dumps(parse(sys.argv[1]), indent=2, ensure_ascii=False))
