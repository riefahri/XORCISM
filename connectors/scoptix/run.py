"""run.py — XORCISM connector: SCOPTIX passive-recon export → assets + services + exposures.

SCOPTIX (https://github.com/Omnitarium/scoptix) is a web dashboard (no CLI). Export a
scan from its UI/API and pass the file here. The export endpoint emits CSV per type
(`findings`, `subdomains`, `urls`, `ips`) and a ZIP of CSVs for `all` — this connector
accepts any one CSV or the ZIP. Columns are pinned to lib/scan-export.ts:
  subdomains.csv : hostname, first_seen_at, last_seen_at
  urls.csv       : url, hostname, category, extension, observed_at
  ips.csv        : ip_address, reported_by_hostname, last_resolved_at
  findings.csv   : finding_type, source, engines, url, snippet, ...

Mapping into the normalized runner contract:
  subdomains / IPs  -> ASSET (+ host facts for the chaining engine)
  URLs              -> SERVICE (one per host:port)
  findings          -> VULN  (the secret VALUE/snippet is REDACTED; type + location kept)
No DB access here (worker-safe).
"""
from __future__ import annotations

import csv
import hashlib
import io
import os
import re
import zipfile
from typing import Any, Dict, List
from urllib.parse import urlparse

_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    path = params.get("file")
    if not path:
        raise RuntimeError("scoptix: provide a 'file' (a SCOPTIX CSV export, or the 'all' ZIP) — SCOPTIX has no CLI to run live")
    acc = _new()
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for nm in z.namelist():
                if nm.lower().endswith(".csv"):
                    _consume(z.read(nm).decode("utf-8", "replace"), acc)
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            _consume(fh.read(), acc)
    return _finish(acc)


def _new() -> Dict[str, Any]:
    return {"assets": {}, "hosts": set(), "services": {}, "cpes": set(), "vulns": []}


def _host_of(s: str) -> str:
    s = str(s or "").strip()
    if not s:
        return ""
    if "://" in s:
        return (urlparse(s).hostname or "").lower() or s.lower()
    return s.split("/")[0].strip().lower()


def _add_asset(acc: Dict[str, Any], name: str, ip: str = "") -> str:
    key = (name or ip or "").strip().lower()
    if not key:
        return ""
    a = acc["assets"].setdefault(key, {"hostname": name or key, "key": key})
    if ip and not a.get("ip"):
        a["ip"] = ip
    if name and not _IPV4.match(name):
        acc["hosts"].add(name.lower())
    return key


def _redact(value: str) -> str:
    v = str(value or "").strip().replace("\n", " ")
    if not v:
        return ""
    if len(v) <= 10:
        return "***"
    return v[:6] + "…" + v[-2:]   # keep only a recognizable prefix — never the full secret


def _sev(finding_type: str) -> str:
    t = (finding_type or "").lower()
    if any(k in t for k in ("key", "secret", "credential", "token", "password", "private", "aws", "gcp", "azure")):
        return "Critical"
    return "High"


def _service_from_url(acc: Dict[str, Any], url: str, host_hint: str = "") -> None:
    host = host_hint.strip().lower() or _host_of(url)
    if not host:
        return
    akey = _add_asset(acc, host)
    u = urlparse(url if "://" in url else "http://" + url)
    scheme = (u.scheme or "http").lower()
    port = u.port or (443 if scheme == "https" else 80)
    acc["services"].setdefault(f"{host}:{port}", {"asset": akey, "port": port, "protocol": "tcp", "name": "https" if port == 443 else "http"})
    if url:
        acc["cpes"].add(f"url:{url}")


def _consume(text: str, acc: Dict[str, Any]) -> None:
    text = (text or "").lstrip("﻿")
    if not text.strip():
        return
    reader = csv.DictReader(io.StringIO(text))
    cols = {(c or "").strip().lower() for c in (reader.fieldnames or [])}
    g = lambda row, *ks: next((str(row.get(k) or "").strip() for k in ks if row.get(k)), "")  # noqa: E731

    if "finding_type" in cols or "snippet" in cols:                 # findings.csv
        for row in reader:
            ftype = g(row, "finding_type", "type") or "secret"
            url = g(row, "url")
            host = _host_of(url)
            akey = _add_asset(acc, host) if host else (next(iter(acc["assets"]), ""))
            snippet = g(row, "snippet", "value", "match")
            label = f"Exposed {ftype}" + (f" at {url}" if url else "")
            if snippet:
                label += f" ({_redact(snippet)})"
            ref = "SCOPTIX-" + hashlib.sha1(f"{ftype}|{url}|{snippet}".encode("utf-8")).hexdigest()[:12]
            acc["vulns"].append({"asset": akey, "ref": ref, "severity": _sev(ftype), "name": label[:200]})
    elif "ip_address" in cols:                                       # ips.csv
        for row in reader:
            ip = g(row, "ip_address", "ip")
            if ip and _IPV4.match(ip):
                _add_asset(acc, ip, ip)
            rep = g(row, "reported_by_hostname", "hostname")
            if rep:
                _add_asset(acc, _host_of(rep))
    elif "url" in cols:                                              # urls.csv
        for row in reader:
            _service_from_url(acc, g(row, "url"), g(row, "hostname"))
    elif "hostname" in cols:                                         # subdomains.csv
        for row in reader:
            h = _host_of(g(row, "hostname", "host", "subdomain", "name"))
            if h:
                _add_asset(acc, h)


def _finish(acc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "assets": list(acc["assets"].values()),
        "hosts": sorted(acc["hosts"]),
        "services": list(acc["services"].values()),
        "cpes": sorted(acc["cpes"]),
        "vulns": acc["vulns"],
    }


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="SCOPTIX import (dry run)")
    ap.add_argument("file", help="a SCOPTIX CSV export or the 'all' ZIP")
    a = ap.parse_args()
    res = run({"file": a.file}, tempfile.mkdtemp())
    import json
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[scoptix] {len(res['assets'])} asset(s), {len(res['services'])} service(s), {len(res['vulns'])} exposure(s)", flush=True)
