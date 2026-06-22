"""run.py — XORCISM connector: ENISA EU Vulnerability Database (EUVD) → VULNERABILITY.

The EUVD (https://euvd.enisa.europa.eu) is the official EU vulnerability repository
established under NIS2. Each entry has its own id (EUVD-YYYY-NNNNN) and usually aliases
one or more CVE ids. This connector pulls EUVD entries and the runner upserts them into
XVULNERABILITY.VULNERABILITY (import_euvd): existing CVEs get their EUVDId/EUVDUrl (and
CVSS/EPSS/description when missing), EUVD-only entries are added.

Offline: parse a saved EUVD JSON export (--file).
Live:    query the public EUVD API (no key required):
           mode=recent   -> /api/lastvulnerabilities
           mode=critical -> /api/criticalvulnerabilities
           mode=exploited-> /api/exploitedvulnerabilities   (marks Exploited)
           mode=search   -> /api/search?text=&vendor=&product=&size=&page=
           cve=CVE-…     -> /api/vulnerability?id=CVE-…
           id=EUVD-…     -> /api/enisaid?id=EUVD-…
Override the base with env EUVD_API_BASE. No DB access (worker-safe).

Returns {"euvd": [ {euvd_id, cve, name, cvss, epss, published, exploited, url} ], "source": "euvd"}.
The EUVD JSON is parsed defensively ({items:[…]} / list / single object), tolerating drift.
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any, Dict, List

_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
_API_BASE = (os.environ.get("EUVD_API_BASE") or "https://euvd.enisa.europa.eu/api").rstrip("/")
_UA = "XORCISM-EUVD-connector/1.0 (+https://xorcism.ai)"


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    else:
        data = _fetch_live(params)
    return {"euvd": _parse(data, params), "source": "euvd"}


def _get(url: str) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (fixed ENISA host / EUVD_API_BASE)
        body = resp.read().decode("utf-8", "replace")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        raise RuntimeError(
            "EUVD API did not return JSON (the service may be unavailable, or the endpoint changed). "
            "Export the entries to JSON from https://euvd.enisa.europa.eu and import via the 'file' parameter."
        )


def _fetch_live(params: Dict[str, Any]) -> Any:
    cve = str(params.get("cve") or "").strip()
    eid = str(params.get("id") or "").strip()
    if cve:
        return _get(f"{_API_BASE}/vulnerability?id={urllib.parse.quote(cve)}")
    if eid:
        return _get(f"{_API_BASE}/enisaid?id={urllib.parse.quote(eid)}")
    mode = str(params.get("mode") or "recent").strip().lower()
    if mode == "critical":
        return _get(f"{_API_BASE}/criticalvulnerabilities")
    if mode == "exploited":
        return _get(f"{_API_BASE}/exploitedvulnerabilities")
    if mode == "search":
        want = max(1, min(int(params.get("max") or 100), 2000))
        q = {"size": min(100, want), "page": 0}
        for k, p in (("text", "query"), ("vendor", "vendor"), ("product", "product")):
            v = str(params.get(p) or "").strip()
            if v:
                q[k] = v
        items: List[Any] = []
        page = 0
        while len(items) < want:
            q["page"] = page
            data = _get(f"{_API_BASE}/search?{urllib.parse.urlencode(q)}")
            batch = data.get("items") if isinstance(data, dict) else (data if isinstance(data, list) else [])
            if not batch:
                break
            items.extend(batch)
            total = int(data.get("total") or 0) if isinstance(data, dict) else len(items)
            page += 1
            if len(items) >= total or page > 60:
                break
        return {"items": items}
    return _get(f"{_API_BASE}/lastvulnerabilities")


def _first(d: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = d.get(k)
        if isinstance(v, (str, int, float)) and str(v).strip() not in ("", "None"):
            return str(v).strip()
    return ""


def _num(v: Any):
    try:
        return float(v) if v is not None and str(v).strip() != "" else None
    except (TypeError, ValueError):
        return None


def _names(v: Any) -> str:
    """Flatten EUVD vendor/product structures ([{vendor:{name}}] / [{product:{name}}] / list / str)."""
    out: List[str] = []

    def walk(x: Any) -> None:
        if isinstance(x, str):
            out.append(x)
        elif isinstance(x, dict):
            nm = x.get("name")
            if isinstance(nm, str):
                out.append(nm)
            else:
                for vv in x.values():
                    walk(vv)
        elif isinstance(x, list):
            for it in x:
                walk(it)

    walk(v)
    return ", ".join(dict.fromkeys(n for n in out if n))


def _parse(data: Any, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        rows = data.get("items") or data.get("results") or data.get("vulnerabilities") or data.get("data")
        if not isinstance(rows, list):
            rows = [data]  # single vulnerability object
    elif isinstance(data, list):
        rows = data
    else:
        rows = []

    force_exploited = str(params.get("mode") or "").strip().lower() == "exploited"
    out: List[Dict[str, Any]] = []
    seen = set()
    for it in rows:
        if not isinstance(it, dict):
            continue
        euvd_id = _first(it, "id", "euvd_id", "enisaId", "enisa_id")
        aliases = _first(it, "aliases", "alias")
        cve = ""
        m = _CVE.search(f"{aliases} {_first(it, 'cve', 'cveId', 'cve_id')}")
        if m:
            cve = m.group(0).upper()
        if not (euvd_id or cve):
            continue
        key = (euvd_id, cve)
        if key in seen:
            continue
        seen.add(key)
        vendor = _names(it.get("enisaIdVendor") or it.get("vendor") or it.get("vendors"))
        product = _names(it.get("enisaIdProduct") or it.get("product") or it.get("products"))
        desc = _first(it, "description", "summary", "title")
        if vendor or product:
            tail = " / ".join(p for p in (vendor, product) if p)
            desc = (desc + f"  [{tail}]") if desc else tail
        exploited = force_exploited or bool(it.get("exploited") or it.get("exploitedSince") or it.get("knownExploited"))
        out.append({
            "euvd_id": euvd_id,
            "cve": cve,
            "name": desc[:1000],
            "cvss": _num(it.get("baseScore") or it.get("cvssBaseScore") or it.get("cvss")),
            "cvss_version": _first(it, "baseScoreVersion", "cvssVersion"),
            "epss": _num(it.get("epss")),
            "published": _first(it, "datePublished", "publishedDate", "published", "dateUpdated"),
            "exploited": exploited,
            "url": (f"https://euvd.enisa.europa.eu/vulnerability/{euvd_id}" if euvd_id else ""),
            "references": _first(it, "references", "reference"),
        })
    return out


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="EUVD import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--mode", default="recent")
    ap.add_argument("--cve", default="")
    ap.add_argument("--id", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "mode": a.mode, "cve": a.cve, "id": a.id}, ".")
    print(json.dumps(res, indent=2)[:4000])
