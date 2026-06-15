"""
import_iocs.py — Feeds XAGENT.XIOC (indicators of compromise) served to the
XOR agents for threat hunting.

Sources:
  • STIX 2.1 files (stix/ folder or --stix-dir): "indicator" objects.
  • AlienVault OTX (CTI connector): recent pulses — key via OTX_API_KEY or --otx-key.

The IOCs are stored normalized: ioc_type ∈ {md5,sha1,sha256,ip,domain,url,filename}.

Usage:
  python import_iocs.py --stix-dir ../stix
  python import_iocs.py --otx-key XXXX           # AlienVault OTX
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sqlite3
import sys
import urllib.request
from datetime import datetime, timezone

DB_DIR = os.getenv("XORCISM_DB_DIR", os.getenv("DB_DIR", r"C:\Users\jerom\XORCISM_databases"))
XAGENT_DB = os.path.join(DB_DIR, "XAGENT.db")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _conn():
    con = sqlite3.connect(XAGENT_DB)
    con.execute("""CREATE TABLE IF NOT EXISTS XIOC(
        IOCID INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc_type TEXT NOT NULL, value TEXT NOT NULL, source TEXT, threat TEXT,
        created_at TEXT, UNIQUE(ioc_type, value))""")
    return con


def insert_iocs(iocs):
    con = _conn()
    ins = con.execute  # shorthand
    n = 0
    for it in iocs:
        t, v = it.get("ioc_type"), it.get("value")
        if not t or not v:
            continue
        try:
            cur = con.execute(
                "INSERT OR IGNORE INTO XIOC(ioc_type,value,source,threat,created_at) VALUES (?,?,?,?,?)",
                (t.lower(), str(v).strip(), it.get("source"), it.get("threat"), _now()))
            n += cur.rowcount
        except sqlite3.Error:
            pass
    con.commit()
    con.close()
    return n


# ── STIX ──────────────────────────────────────────────────────────────────────────
_PAT = [
    (re.compile(r"file:hashes\.'?SHA-?256'?\s*=\s*'([0-9a-fA-F]{64})'"), "sha256"),
    (re.compile(r"file:hashes\.'?SHA-?1'?\s*=\s*'([0-9a-fA-F]{40})'"), "sha1"),
    (re.compile(r"file:hashes\.'?MD5'?\s*=\s*'([0-9a-fA-F]{32})'"), "md5"),
    (re.compile(r"ipv4-addr:value\s*=\s*'([0-9.]+)'"), "ip"),
    (re.compile(r"ipv6-addr:value\s*=\s*'([0-9a-fA-F:]+)'"), "ip"),
    (re.compile(r"domain-name:value\s*=\s*'([^']+)'"), "domain"),
    (re.compile(r"url:value\s*=\s*'([^']+)'"), "url"),
    (re.compile(r"file:name\s*=\s*'([^']+)'"), "filename"),
]


def parse_stix_indicator(pattern):
    out = []
    for rx, typ in _PAT:
        for m in rx.findall(pattern or ""):
            out.append((typ, m))
    return out


def from_stix_dir(stix_dir):
    iocs = []
    for path in glob.glob(os.path.join(stix_dir, "*.json")):
        try:
            data = json.load(open(path, "r", encoding="utf-8"))
        except Exception:
            continue
        objects = data.get("objects", data if isinstance(data, list) else [data])
        for o in objects if isinstance(objects, list) else []:
            if isinstance(o, dict) and o.get("type") == "indicator":
                name = o.get("name") or o.get("id", "")
                for typ, val in parse_stix_indicator(o.get("pattern", "")):
                    iocs.append({"ioc_type": typ, "value": val, "source": "stix", "threat": name})
    return iocs


# ── AlienVault OTX ─────────────────────────────────────────────────────────────────
_OTX_MAP = {
    "FileHash-SHA256": "sha256", "FileHash-SHA1": "sha1", "FileHash-MD5": "md5",
    "IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain", "URL": "url",
}


def from_otx(api_key, max_pulses=20):
    iocs = []
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=%d" % max_pulses
    req = urllib.request.Request(url, headers={"X-OTX-API-KEY": api_key})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.load(r)
    except Exception as e:  # noqa: BLE001
        print(f"[otx] erreur : {e}", file=sys.stderr)
        return iocs
    for pulse in data.get("results", []):
        name = pulse.get("name", "OTX pulse")
        for ind in pulse.get("indicators", []):
            typ = _OTX_MAP.get(ind.get("type"))
            if typ and ind.get("indicator"):
                iocs.append({"ioc_type": typ, "value": ind["indicator"], "source": "otx", "threat": name})
    return iocs


def main():
    ap = argparse.ArgumentParser(description="Import IOC (STIX / AlienVault OTX) → XAGENT.XIOC")
    ap.add_argument("--stix-dir", default=os.path.join(os.path.dirname(__file__), "..", "stix"))
    ap.add_argument("--otx-key", default=os.environ.get("OTX_API_KEY"))
    ap.add_argument("--no-stix", action="store_true")
    args = ap.parse_args()

    iocs = []
    if not args.no_stix and os.path.isdir(args.stix_dir):
        s = from_stix_dir(args.stix_dir)
        print(f"[stix] {len(s)} IOC depuis {args.stix_dir}")
        iocs += s
    if args.otx_key:
        o = from_otx(args.otx_key)
        print(f"[otx] {len(o)} IOC depuis AlienVault OTX")
        iocs += o

    n = insert_iocs(iocs)
    total = _conn().execute("SELECT COUNT(*) FROM XIOC").fetchone()[0]
    print(f"[iocs] {n} nouveaux insérés ; {total} IOC au total dans XAGENT.XIOC")


if __name__ == "__main__":
    main()
