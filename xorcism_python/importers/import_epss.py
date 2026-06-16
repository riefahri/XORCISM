"""
import_epss.py — Populate VULNERABILITY.EPSS from FIRST.org's EPSS dataset.

EPSS (Exploit Prediction Scoring System) gives every CVE a probability (0–1) of
being exploited in the wild in the next 30 days. This importer fills
XVULNERABILITY.VULNERABILITY.EPSS for the CVE-referenced rows.

Two methods:
  • bulk (default) — downloads the full EPSS scores CSV once and joins locally.
    Right for the whole table (hundreds of thousands of CVEs) in one pass.
  • --api          — queries https://api.first.org/data/v1/epss?cve=… in batches.
    Use for a small/targeted set (no full download).

Idempotent. By default only fills rows where EPSS IS NULL; --refresh updates all.

Usage:
    python import_epss.py                 # bulk: fill missing EPSS for all CVE rows
    python import_epss.py --refresh       # bulk: refresh every CVE row
    python import_epss.py --limit 100     # cap the number of rows updated (testing)
    python import_epss.py --api --limit 50
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import os
import sys
import time
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

DB_PATH = os.path.join(config.DB_DIR, "XVULNERABILITY.db")
API = "https://api.first.org/data/v1/epss"
# FIRST.org full dataset (host moved to Empirical Security; UMD kept as a fallback).
CSV_URLS = [
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "https://epss.cyber.umd.edu/data/current/epss_scores-current.csv.gz",
]
UA = {"User-Agent": "XORCISM-epss-importer"}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportEPSS] {msg}", flush=True)


def download_epss_map() -> dict:
    """Download + parse the full EPSS CSV → {CVE: epss(float)}."""
    last = None
    for url in CSV_URLS:
        try:
            log(f"Downloading EPSS dataset: {url}")
            r = requests.get(url, headers=UA, timeout=120)
            r.raise_for_status()
            raw = gzip.decompress(r.content) if url.endswith(".gz") else r.content
            text = raw.decode("utf-8", "replace")
            epss: dict = {}
            for row in csv.reader(io.StringIO(text)):
                if not row or row[0].startswith("#") or row[0].lower() == "cve":
                    continue  # comment line (#model_version…) or header
                if len(row) >= 2:
                    try:
                        epss[row[0].strip().upper()] = float(row[1])
                    except ValueError:
                        continue
            log(f"EPSS dataset: {len(epss)} CVE scores")
            return epss
        except Exception as e:  # noqa: BLE001
            last = e
            log(f"  failed: {e}")
    raise RuntimeError(f"could not download the EPSS dataset ({last})")


def fetch_api(cves: list, batch: int) -> dict:
    """Per-CVE EPSS via the FIRST.org API (comma-separated, batched)."""
    out: dict = {}
    for i in range(0, len(cves), batch):
        chunk = cves[i:i + batch]
        try:
            r = requests.get(API, params={"cve": ",".join(chunk), "limit": len(chunk)},
                             headers=UA, timeout=60)
            r.raise_for_status()
            for d in (r.json().get("data") or []):
                cve, epss = (d.get("cve") or "").upper(), d.get("epss")
                if cve and epss is not None:
                    try:
                        out[cve] = float(epss)
                    except (TypeError, ValueError):
                        pass
        except Exception as e:  # noqa: BLE001
            log(f"  API batch {i // batch + 1} error: {e}")
            time.sleep(2)
        time.sleep(0.3)  # be polite to the API
    return out


def main() -> None:
    import sqlite3

    ap = argparse.ArgumentParser(description="Populate VULNERABILITY.EPSS from FIRST.org EPSS")
    ap.add_argument("--api", action="store_true", help="use the per-CVE API instead of the bulk CSV")
    ap.add_argument("--refresh", action="store_true", help="update all CVE rows (not only EPSS IS NULL)")
    ap.add_argument("--limit", type=int, default=0, help="max rows to update (0 = no limit)")
    ap.add_argument("--batch", type=int, default=100, help="API batch size (--api)")
    args = ap.parse_args()

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA busy_timeout=15000")
    cur = conn.cursor()
    cols = {r[1] for r in cur.execute("PRAGMA table_info(VULNERABILITY)").fetchall()}
    if "EPSS" not in cols:
        cur.execute("ALTER TABLE VULNERABILITY ADD COLUMN EPSS REAL")
        conn.commit()
        log("Added column VULNERABILITY.EPSS")

    where = "VULReferentialID LIKE 'CVE-%'"
    if not args.refresh:
        where += " AND EPSS IS NULL"
    # Keep the stored (raw) referential so the UPDATE matches on the indexed column
    # with BINARY collation (NOT 'COLLATE NOCASE', which would defeat the index and
    # force a full table scan per row). EPSS lookup is case-insensitive (uppercased key).
    raw_cves = sorted({
        r[0].strip()
        for r in cur.execute(f"SELECT DISTINCT VULReferentialID FROM VULNERABILITY WHERE {where}").fetchall()
        if r[0] and r[0].strip().upper().startswith("CVE-")
    })
    log(f"{len(raw_cves)} CVE(s) to score ({'all' if args.refresh else 'missing EPSS only'})")
    if not raw_cves:
        conn.close()
        return

    epss_map = (fetch_api([c.upper() for c in raw_cves], args.batch) if args.api
                else download_epss_map())

    updates = []
    for cve in raw_cves:
        score = epss_map.get(cve.upper())
        if score is not None:
            updates.append((score, cve))  # match WHERE VULReferentialID = <raw stored value>
            if args.limit and len(updates) >= args.limit:
                break
    cur.executemany("UPDATE VULNERABILITY SET EPSS=? WHERE VULReferentialID=?", updates)
    conn.commit()
    total = cur.execute("SELECT COUNT(*) FROM VULNERABILITY WHERE EPSS IS NOT NULL AND VULReferentialID LIKE 'CVE-%'").fetchone()[0]
    conn.close()
    log(f"Done ({now()}): {len(updates)} CVE matched & updated; {total} CVE rows now have EPSS.")


if __name__ == "__main__":
    main()
