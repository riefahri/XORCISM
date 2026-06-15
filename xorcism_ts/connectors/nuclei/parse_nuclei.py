"""
parse_nuclei.py — Nuclei output parser (-jsonl) for the XORCISM connector.

One JSON line per finding. Produces the normalized result:
  { "assets": [{ip, hostname, key}], "vulns": [{asset, ref, severity, name, template, ...}],
    "services": [], "cpes": [] }

`ref` = CVE (info.classification.cve-id) if present, otherwise template-id.

    python parse_nuclei.py findings.jsonl
"""

from __future__ import annotations

import json
import os
import sys
import urllib.parse
from typing import Any, Dict, List, Optional


def _lines(path_or_text: str) -> List[str]:
    if os.path.exists(path_or_text):
        with open(path_or_text, "r", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    return path_or_text.splitlines()


def _hostname(host: str) -> Optional[str]:
    if not host:
        return None
    u = urllib.parse.urlparse(host if "://" in host else "//" + host)
    return u.hostname or host


def parse(path_or_text: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []

    for line in _lines(path_or_text):
        line = line.strip()
        if not line:
            continue
        try:
            f = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = f.get("info") or {}
        host = f.get("host") or f.get("matched-at") or ""
        ip = f.get("ip")
        hostname = _hostname(host)
        key = ip or hostname
        if not key:
            continue
        assets.setdefault(key, {"ip": ip, "hostname": hostname, "key": key})

        cves = (info.get("classification") or {}).get("cve-id") or []
        ref = (cves[0] if cves else None) or f.get("template-id") or info.get("name")
        if not ref:
            continue
        vulns.append({
            "asset": key,
            "ref": str(ref).upper() if str(ref).lower().startswith("cve-") else str(ref),
            "severity": info.get("severity"),
            "name": info.get("name"),
            "template": f.get("template-id"),
            "matched_at": f.get("matched-at"),
            "source": "nuclei",
        })

    return {
        "assets": list(assets.values()),
        "services": [],
        "cpes": [],
        "vulns": vulns,
    }


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: python parse_nuclei.py findings.jsonl", file=sys.stderr)
        sys.exit(2)
    r = parse(sys.argv[1])
    print(json.dumps(r, indent=2, ensure_ascii=False))
    print(f"\n# {len(r['assets'])} hôtes, {len(r['vulns'])} findings", file=sys.stderr)


if __name__ == "__main__":
    main()
