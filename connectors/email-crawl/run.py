"""run.py — XORCISM connector for EMAIL-CRAWL (OSINT email harvesting).

EMAIL-CRAWL (https://github.com/techenthusiast167/EMAIL-CRAWL) crawls a target website and
extracts the email addresses exposed on it (contact pages, team pages, mailtos, ...). For an
attack-surface view those harvestable emails are phishing / social-engineering targets, so this
connector maps them into XORCISM as findings on the crawled site:
  * the crawled domain      -> ASSET (the website / OSINT target)
  * each exposed email       -> a finding (VULNERABILITY, severity info) on that asset, noting the
                                source page and whether it is an on-domain (corporate) address.

Modes (in order):
    offline : params["file"] -> an EmailCrawl JSON export (auto-detects {emails:[...]} /
              {results:[{email, source_url}]} / a flat list / nested — emails extracted by regex
              as a fallback). NON-intrusive (parse only).
    live    : params["target"] + EMAILCRAWL_BIN (path to EmailCrawl.py) -> runs the crawler
              (python3 EmailCrawl.py <target> --output <tmp> [--max-pages N]) and parses it.
              ACTIVE OSINT RECON against the target — only with authorization.
    demo    : neither -> the bundled sample.json.

Normalized result: {project?, assets, vulns, source} -> runner.import_findings. Worker-safe:
stdlib only, ASCII-only output, no DB access.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

TOOL_NAME = "EMAIL-CRAWL"
TOOL_URL = "https://github.com/techenthusiast167/EMAIL-CRAWL"
SOURCE = "EMAIL-CRAWL"
_EMAIL_RX = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _host(u: Optional[str]) -> Optional[str]:
    if not u:
        return None
    s = str(u).strip()
    if "@" in s and "://" not in s:        # an email — take its domain
        return s.rsplit("@", 1)[-1].lower() or None
    if "://" not in s:
        s = "http://" + s
    try:
        h = urllib.parse.urlparse(s).hostname
        return h.lower() if h else None
    except ValueError:
        return None


def _collect(data: Any, out: Dict[str, Optional[str]]) -> None:
    """Recursively collect {email: source_url} pairs from an arbitrary JSON structure."""
    if isinstance(data, dict):
        email = None
        for k in ("email", "address", "email_address", "value"):
            v = data.get(k)
            if isinstance(v, str) and _EMAIL_RX.fullmatch(v.strip()):
                email = v.strip().lower(); break
        src = None
        for k in ("source_url", "source", "url", "page", "found_on"):
            v = data.get(k)
            if isinstance(v, str) and v.strip():
                src = v.strip(); break
        if email:
            out.setdefault(email, src)
        for v in data.values():
            _collect(v, out)
    elif isinstance(data, list):
        for v in data:
            _collect(v, out)
    elif isinstance(data, str):
        for m in _EMAIL_RX.findall(data):
            out.setdefault(m.lower(), None)


def _target_of(data: Any, params: Dict[str, Any]) -> Optional[str]:
    if params.get("target"):
        return _host(params["target"])
    if isinstance(data, dict):
        for k in ("target", "domain", "url", "site", "base_url"):
            h = _host(data.get(k))
            if h:
                return h
    return None


def _run_tool(params: Dict[str, Any]) -> Any:
    binary = (os.environ.get("EMAILCRAWL_BIN") or "").strip()
    target = str(params.get("target") or "").strip()
    if not binary or not target:
        raise RuntimeError("live mode needs EMAILCRAWL_BIN (path to EmailCrawl.py) + target")
    out_path = os.path.join(tempfile.gettempdir(), "emailcrawl_%d.json" % os.getpid())
    cmd = [sys.executable, binary, target, "--output", out_path]
    mp = str(params.get("maxPages") or "").strip()
    if mp.isdigit():
        cmd += ["--max-pages", mp]
    subprocess.run(cmd, check=True, timeout=900, capture_output=True)
    with open(out_path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    try:
        os.unlink(out_path)
    except OSError:
        pass
    return data


def _normalize(data: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    pairs: Dict[str, Optional[str]] = {}
    _collect(data, pairs)
    target = _target_of(data, params) or "EMAIL-CRAWL harvest"
    assets = [{"hostname": target, "key": target}]
    vulns: List[Dict[str, Any]] = []
    tdom = target if "." in target else None
    for email, src in sorted(pairs.items()):
        dom = email.rsplit("@", 1)[-1]
        onsite = bool(tdom) and (dom == tdom or dom.endswith("." + tdom))
        name = "Exposed email: %s%s" % (email, " [corporate]" if onsite else "")
        if src:
            name += " (source: %s)" % src[:120]
        vulns.append({"asset": target, "ref": "EMAILCRAWL-" + email, "name": name[:300], "severity": "info"})
    return {"project": "EMAIL-CRAWL: " + target, "assets": assets, "services": [], "cpes": [], "vulns": vulns, "source": SOURCE}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    elif params.get("target") and os.environ.get("EMAILCRAWL_BIN"):
        data = _run_tool(params)
    else:
        sample = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.json")
        with open(sample, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    out = _normalize(data, params)
    print("[email-crawl] %d email(s) harvested from %s" % (len(out["vulns"]), out["assets"][0]["hostname"]))
    return out


if __name__ == "__main__":
    p = {"file": sys.argv[1]} if len(sys.argv) > 1 else {}
    print(json.dumps(run(p, "."), indent=2)[:2000])
