"""run.py - XORCISM connector for the GCVE-EU CPE Editor -> CPE dictionary (XORCISM.CPE).

CPE Editor (https://github.com/gcve-eu/cpe-editor, v1.1.0+) is a web app that curates CPE
(Common Platform Enumeration) data and exposes a read-only OpenAPI (vendors / products / cpes /
changes) plus JSON / NDJSON dataset export. Each curated CPE is a software/platform identifier
(cpe:2.3:part:vendor:product:version:...) used across XORCISM for CVE<->asset matching, SCA and
OVAL / vulnerable-configuration tests. This connector fetches those records and normalizes each to
a dictionary entry that maps to XORCISM.CPE.

Modes:
    live : `base_url` or env CPE_EDITOR_URL -> GET <base_url>/api/v1/cpes (optional bearer
           CPE_EDITOR_TOKEN). The response may be a JSON array, a paged {"results"/"data"/"cpes": [...]}
           object, or NDJSON.
    file : `file` = a path to an exported dataset (JSON array, {"cpes": [...]} object, or NDJSON).
    demo : neither -> a small built-in sample.

Read-only. Worker-safe: stdlib only, secrets via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any, Dict, List

API_PATH = "/api/v1/cpes"
# A CPE 2.3 formatted-string binding: cpe:2.3:<part a|o|h>:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
_CPE23 = re.compile(r"^cpe:2\.3:[aoh](:[^:]*){10}$", re.I)
# Legacy CPE 2.2 URI binding: cpe:/<part>:vendor:product:version...
_CPE22 = re.compile(r"^cpe:/[aoh]?:.+", re.I)

_DEMO = {"cpes": [
    {"cpe23": "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*", "title": "Apache HTTP Server 2.4.58",
     "vendor": "apache", "product": "http_server", "version": "2.4.58", "deprecated": False,
     "references": ["https://httpd.apache.org/"]},
    {"cpe23": "cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:x64:*", "title": "Microsoft Windows 11 23H2",
     "vendor": "microsoft", "product": "windows_11", "version": "23h2", "deprecated": False},
    {"cpe23": "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*", "title": "OpenSSL 3.0.13",
     "vendor": "openssl", "product": "openssl", "version": "3.0.13", "deprecated": False,
     "references": ["https://www.openssl.org/"]},
]}


def _first(d: Dict[str, Any], *names: str) -> Any:
    for n in names:
        if n in d and d[n] not in (None, ""):
            return d[n]
    return None


def _part_of(cpe23: str) -> str:
    m = re.match(r"^cpe:2\.3:([aoh]):", cpe23 or "", re.I)
    return m.group(1).lower() if m else ""


def _split23(cpe23: str) -> List[str]:
    # split keeping escaped ':' (\:) intact; good enough for vendor/product/version recovery
    parts = re.split(r"(?<!\\):", cpe23 or "")
    return parts


def _map_cpe(rec: Dict[str, Any]) -> Dict[str, Any] | None:
    cpe23 = str(_first(rec, "cpe23", "cpe_2_3", "cpe23Uri", "cpeName", "name", "cpe") or "").strip()
    cpe22 = str(_first(rec, "cpe22", "cpe22Uri", "cpe_2_2", "cpeUri") or "").strip()
    if cpe23 and not _CPE23.match(cpe23) and _CPE22.match(cpe23):
        # the field labelled "cpe" was actually a 2.2 URI
        cpe22, cpe23 = cpe23, ""
    if not cpe23 and not cpe22:
        return None
    seg = _split23(cpe23) if cpe23 else []
    vendor = str(_first(rec, "vendor", "vendor_name") or (seg[3] if len(seg) > 4 else "")).strip()
    product = str(_first(rec, "product", "product_name") or (seg[4] if len(seg) > 5 else "")).strip()
    version = str(_first(rec, "version") or (seg[5] if len(seg) > 6 else "")).strip()
    if version in ("*", "-"):
        version = ""
    title = str(_first(rec, "title", "label", "human_readable") or
                (" ".join(p for p in [vendor, product, version] if p) or cpe23 or cpe22)).strip()
    refs = _first(rec, "references", "refs", "links") or []
    if isinstance(refs, str):
        refs = [refs]
    ref = ""
    for r in refs if isinstance(refs, list) else []:
        rr = r.get("href") if isinstance(r, dict) else r
        if rr:
            ref = str(rr)
            break
    return {
        "cpe23": cpe23 or None,
        "cpe22": cpe22 or None,
        "part": _part_of(cpe23) or str(_first(rec, "part") or "").strip(),
        "vendor": vendor or None,
        "product": product or None,
        "version": version or None,
        "title": title[:300],
        "deprecated": bool(_first(rec, "deprecated", "is_deprecated") or False),
        "reference": ref or None,
        "external_id": str(_first(rec, "id", "uuid", "cpe_name_id") or "") or None,
        "valid": bool(_CPE23.match(cpe23) or _CPE22.match(cpe22)),
    }


def _records(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        for k in ("cpes", "results", "data", "items"):
            v = payload.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return []


def _load_ndjson(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                out.append(obj)
        except (ValueError, TypeError):
            continue
    return out


def _load(params: Dict[str, Any]) -> List[Dict[str, Any]]:
    path = str(params.get("file") or "").strip()
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        try:
            return _records(json.loads(text))
        except ValueError:
            return _load_ndjson(text)
    base = (str(params.get("base_url") or "").strip() or os.environ.get("CPE_EDITOR_URL", "").strip())
    if base:
        base = base.rstrip("/")
        q: Dict[str, Any] = {"limit": int(params.get("limit") or 200)}
        if str(params.get("search") or "").strip():
            q["search"] = str(params["search"]).strip()
        url = f"{base}{API_PATH}?{urllib.parse.urlencode(q)}"
        headers = {"Accept": "application/json", "User-Agent": "XORCISM-CPE-Editor/1.0"}
        tok = os.environ.get("CPE_EDITOR_TOKEN", "").strip()
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8", "replace")
        try:
            return _records(json.loads(raw))
        except ValueError:
            return _load_ndjson(raw)
    return _DEMO["cpes"]


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    records = _load(params)
    cpes = [m for m in (_map_cpe(r) for r in records) if m]
    valid = sum(1 for c in cpes if c.get("valid"))
    return {"cpes": cpes, "source": "GCVE CPE Editor", "count": len(cpes), "valid": valid}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()), indent=2))
