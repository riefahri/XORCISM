"""
import_ctem.py -- Import the ctem.org exposure-identifier taxonomy into XVULNERABILITY.CTEMIDENTIFIER.

Source: https://ctem.org/  (machine-readable feed: https://ctem.org/source.json)

ctem.org (SecureCoders) publishes a vendor-neutral, standardized "CVE/CWE for exposures": identifiers
CTEM-<CAT>-<n> across 8 categories (Brand, Credentials, Domain, System Exposure, Financial, Infection,
Ransomware, Source-Code), licensed CC BY-NC-SA 4.0. This importer fetches source.json (stdlib only,
no extra deps) and upserts each identifier; if the network is unavailable it falls back to an embedded
snapshot (v1.0, 29 identifiers). Idempotent (upsert keyed by CtemId), runs against config.DB_DIR.

    python import_ctem.py             # fetch source.json (live) and import / refresh
    python import_ctem.py --offline   # use the embedded snapshot only
    python import_ctem.py --dry-run   # print what would be imported, touch no DB
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

DB_PATH = os.path.join(config.DB_DIR, "XVULNERABILITY.db")
SOURCE_URL = "https://ctem.org/source.json"

CATEGORIES = {
    "BND": "Brand Impersonation", "CRD": "Credential Dump", "DOM": "Look-alike Domains",
    "EXP": "System Exposure", "FIN": "Financial Info Exposure", "INF": "Infected Device",
    "RAN": "Ransomware", "SRC": "Source-Code Exposure",
}

# Embedded offline snapshot (ctem.org v1.0): (CtemId, name, categoryCode)
EMBEDDED = [
    ("CTEM-BND-1", "Counterfeit Product Offered for Sale or Use", "BND"),
    ("CTEM-CRD-1", "Employee Credentials Dumped Publicly", "CRD"),
    ("CTEM-CRD-2", "Vendor System Dump with Credentials", "CRD"),
    ("CTEM-DOM-1", "Typo-Squatted Domain", "DOM"),
    ("CTEM-DOM-2", "Homoglyph Attack Domain", "DOM"),
    ("CTEM-DOM-3", "Phishing Indicator Domain", "DOM"),
    ("CTEM-DOM-4", "Brand Impersonation Domain", "DOM"),
    ("CTEM-EXP-1", "Directly Connected Internal System", "EXP"),
    ("CTEM-EXP-2", "Remote Site-Owned System Presumed Connected", "EXP"),
    ("CTEM-EXP-3", "Corporate Internet-Exposed Gateway Device", "EXP"),
    ("CTEM-EXP-4", "Corporate Cloud-Connected System", "EXP"),
    ("CTEM-EXP-5", "Presumed Company System by Branding", "EXP"),
    ("CTEM-EXP-6", "Contractor/Vendor-Managed System", "EXP"),
    ("CTEM-FIN-1", "Corporate Bank Account / Routing Information Exposed", "FIN"),
    ("CTEM-FIN-2", "Accounts Payable Information Exposure", "FIN"),
    ("CTEM-INF-1", "Infected Corporate Owned Device", "INF"),
    ("CTEM-INF-2", "Infected Vendor Owned Device", "INF"),
    ("CTEM-INF-3", "Infected Employee Owned Device (Corporate Credentials)", "INF"),
    ("CTEM-INF-4", "Infected Employee Owned Device (Personal Use of Corporate Identity)", "INF"),
    ("CTEM-INF-5", "Infected Customer Owned Device", "INF"),
    ("CTEM-INF-6", "Infected Employee Owned Device (Internal Network Connected)", "INF"),
    ("CTEM-INF-7", "Infected Employee Owned Device (3rd Party Business Use of Corporate Identity)", "INF"),
    ("CTEM-RAN-1", "Ransom Dump (Supplier)", "RAN"),
    ("CTEM-RAN-2", "Ransom Dump (Customer)", "RAN"),
    ("CTEM-SRC-1", "Public Source Code Repository - Company Sanctioned", "SRC"),
    ("CTEM-SRC-2", "Public Source Code Repository - Employee Created", "SRC"),
    ("CTEM-SRC-3", "Public Source Code Repository - Vendor Owned", "SRC"),
    ("CTEM-SRC-4", "Public Source Code Repository - Unrelated 3rd Party", "SRC"),
    ("CTEM-SRC-5", "Public Source Code Repository - Unrelated Company Comment / Issue", "SRC"),
]


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportCTEM] {msg}", flush=True)


def code_of(ctem_id: str) -> str:
    parts = ctem_id.split("-")
    return parts[1].upper() if len(parts) > 1 else ""


def clean_name(title: str, ctem_id: str) -> str:
    # titles look like "CTEM-BND-1 - Counterfeit Product ..." -> strip the id prefix
    if " - " in title:
        return title.split(" - ", 1)[1].strip()
    return title.strip()


def fetch_source(version_out: dict) -> list:
    """Fetch and parse source.json -> list of (ctemId, name, code, description, link, updated). Raises on failure."""
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "XORCISM-CTEM-importer/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        doc = json.loads(resp.read().decode("utf-8"))
    version_out["version"] = str(doc.get("version", "1.0"))
    out = []
    for e in doc.get("data", []):
        cid = str(e.get("id", "")).strip()
        if not cid:
            continue
        out.append((
            cid, clean_name(str(e.get("title", cid)), cid), code_of(cid),
            str(e.get("description", "")).strip(),
            str(e.get("link", f"https://ctem.org/docs/{cid.lower()}")).strip(),
            str(e.get("updated_at", "")).strip(),
        ))
    return out


def from_embedded() -> list:
    return [(cid, name, code, "", f"https://ctem.org/docs/{cid.lower()}", "") for (cid, name, code) in EMBEDDED]


def ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS CTEMIDENTIFIER (
          CtemIdentifierID INTEGER PRIMARY KEY, CtemId TEXT, Title TEXT, CategoryCode TEXT, Category TEXT,
          Description TEXT, Link TEXT, Version TEXT, UpdatedDate TEXT, CreatedDate TEXT);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_ctemidentifier ON CTEMIDENTIFIER(CtemId);
        """
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Import the ctem.org exposure-identifier taxonomy.")
    ap.add_argument("--offline", action="store_true", help="use the embedded snapshot instead of fetching source.json")
    ap.add_argument("--dry-run", action="store_true", help="print what would be imported, touch no DB")
    args = ap.parse_args()

    meta = {"version": "1.0"}
    rows = []
    if not args.offline:
        try:
            rows = fetch_source(meta)
            log(f"fetched {len(rows)} identifiers from {SOURCE_URL} (v{meta['version']})")
        except Exception as exc:  # noqa: BLE001
            log(f"live fetch failed ({exc}); falling back to embedded snapshot")
    if not rows:
        rows = from_embedded()
        log(f"using embedded snapshot: {len(rows)} identifiers")

    if args.dry_run:
        for cid, name, code, desc, link, upd in rows:
            log(f"  {cid:<12} [{code}] {name}")
        log(f"dry-run: {len(rows)} identifiers (no DB write)")
        return 0

    con = sqlite3.connect(DB_PATH)
    try:
        ensure_schema(con)
        cur = con.cursor()
        ins = upd = 0
        for cid, name, code, desc, link, updated in rows:
            cat = CATEGORIES.get(code, code)
            existing = cur.execute("SELECT CtemIdentifierID FROM CTEMIDENTIFIER WHERE CtemId = ?", (cid,)).fetchone()
            if existing:
                cur.execute(
                    "UPDATE CTEMIDENTIFIER SET Title=?, CategoryCode=?, Category=?, Description=COALESCE(NULLIF(?,''),Description), Link=?, Version=?, UpdatedDate=? WHERE CtemIdentifierID=?",
                    (name, code, cat, desc, link, meta["version"], updated, existing[0]),
                )
                upd += 1
            else:
                nid = (cur.execute("SELECT COALESCE(MAX(CtemIdentifierID),0)+1 FROM CTEMIDENTIFIER").fetchone()[0])
                cur.execute(
                    "INSERT INTO CTEMIDENTIFIER (CtemIdentifierID, CtemId, Title, CategoryCode, Category, Description, Link, Version, UpdatedDate, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (nid, cid, name, code, cat, desc, link, meta["version"], updated, now()),
                )
                ins += 1
        con.commit()
        log(f"done: {ins} inserted, {upd} updated -> CTEMIDENTIFIER ({DB_PATH})")
    finally:
        con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
