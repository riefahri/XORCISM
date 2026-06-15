"""parse_sn1per.py — Sn1per output parser for the XORCISM connector.

Sn1per wraps many tools; this parser is defensive and reads the aggregated stdout:
  • the scanned target           → ASSET
  • open ports/services (nmap-style lines) → CPEs linked to the asset
  • CVE ids found anywhere        → findings (VULNERABILITY / ASSETVULNERABILITY)

Normalized result: { assets:[{hostname,key}], services:[{asset,cpe}], cpes:[],
                     vulns:[{asset, ref, name, severity, source}] }

    python parse_sn1per.py output.txt
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

PORT_RE = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+open\s+([A-Za-z0-9._/-]+)", re.M)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
TARGET_RE = re.compile(r"(?:Nmap scan report for|target:|TARGET:)\s*([A-Za-z0-9._-]+)", re.I)


def _read(path_or_text: str) -> str:
    if os.path.exists(path_or_text):
        with open(path_or_text, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return path_or_text


def parse(path_or_text: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    text = _read(path_or_text)
    target = (params or {}).get("target")
    if not target:
        m = TARGET_RE.search(text)
        target = m.group(1) if m else None

    assets: Dict[str, Dict[str, Any]] = {}
    services: List[Dict[str, Any]] = []
    vulns: List[Dict[str, Any]] = []

    key = str(target) if target else None
    if key:
        assets[key] = {"hostname": key, "key": key}
        for port, proto, svc in PORT_RE.findall(text):
            services.append({"asset": key, "cpe": f"{svc} {port}/{proto}"})
        for cve in sorted({c.upper() for c in CVE_RE.findall(text)}):
            vulns.append({"asset": key, "ref": cve, "name": cve, "severity": "high", "source": "sn1per"})

    return {"assets": list(assets.values()), "services": services, "cpes": [], "vulns": vulns}


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: python parse_sn1per.py output.txt [target]", file=sys.stderr)
        sys.exit(2)
    p = {"target": sys.argv[2]} if len(sys.argv) > 2 else {}
    r = parse(sys.argv[1], p)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    print(f"\n# {len(r['assets'])} asset(s), {len(r['services'])} service(s), {len(r['vulns'])} finding(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
