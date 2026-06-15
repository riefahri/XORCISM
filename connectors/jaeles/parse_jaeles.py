"""parse_jaeles.py — Jaeles output parser for the XORCISM connector.

Jaeles prints matched signatures to stdout. This parser is defensive: for each
line that looks like a finding (has a severity tag and/or 'vulnerable'/'[Found]'
and a URL) it extracts the target host, severity, signature and any CVE.

Normalized result: { assets:[{hostname,key}], services:[], cpes:[],
                     vulns:[{asset, ref, name, severity, matched_at, source}] }
`ref` = CVE if the line references one, else JAELES-<signature>.

    python parse_jaeles.py output.txt
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.parse
from typing import Any, Dict, List, Optional

URL_RE = re.compile(r"https?://[^\s'\"<>\]]+")
SEV_RE = re.compile(r"\[(info|low|medium|high|critical)\]", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
FINDING_RE = re.compile(r"vulnerab|\[found\]|\[vuln|\[match", re.I)


def _lines(path_or_text: str) -> List[str]:
    if os.path.exists(path_or_text):
        with open(path_or_text, "r", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    return path_or_text.splitlines()


def _hostname(url: str) -> Optional[str]:
    try:
        return urllib.parse.urlparse(url).hostname
    except ValueError:
        return None


def parse(path_or_text: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # noqa: ARG001
    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []

    for line in _lines(path_or_text):
        line = line.strip()
        if "http" not in line:
            continue
        sev_m = SEV_RE.search(line)
        if not sev_m and not FINDING_RE.search(line):
            continue
        url_m = URL_RE.search(line)
        if not url_m:
            continue
        url = url_m.group(0).rstrip(".,);]")
        host = _hostname(url)
        if not host:
            continue
        assets.setdefault(host, {"hostname": host, "key": host})

        cve = CVE_RE.search(line)
        tail = line[url_m.end():].strip(" -|\t")
        sig = tail.split()[0].strip("[]") if tail else None
        ref = cve.group(0).upper() if cve else (f"JAELES-{sig}" if sig else f"JAELES-{host}")
        vulns.append({
            "asset": host,
            "ref": ref[:120],
            "name": (sig or "Jaeles signature match")[:200],
            "severity": (sev_m.group(1).lower() if sev_m else "medium"),
            "matched_at": url,
            "source": "jaeles",
        })

    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: python parse_jaeles.py output.txt", file=sys.stderr)
        sys.exit(2)
    r = parse(sys.argv[1])
    print(json.dumps(r, indent=2, ensure_ascii=False))
    print(f"\n# {len(r['assets'])} host(s), {len(r['vulns'])} finding(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
