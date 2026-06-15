"""
import_cisa_kev.py — Synchronizes the VULNERABILITY.KEV flag with the
CISA KEV catalog (Known Exploited Vulnerabilities).
Jerome Athias - XORCISM

Downloads the official catalog (JSON, public domain) and sets KEV=1
on each row of XVULNERABILITY.VULNERABILITY whose VULReferentialID appears
in the catalog. Additive by default (never resets KEV to 0); --reset
first resets all KEV to 0 to mirror the catalog exactly.

Called automatically at the end of the NVD import (import_nvd_cve.py); usable
alone to catch up on the existing data:

    python import_cisa_kev.py [--file catalog.json] [--reset]

Catalog: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

import argparse
import json
import os
import sys
from typing import Optional

import requests
from sqlalchemy import text

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python.models.base import session_scope
from xorcism_python.utils import log

MODULE = "ImportCisaKEV"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CHUNK = 500  # size of the IN clauses (SQLite limit: 999 variables)


def _load_catalog(path: Optional[str] = None) -> dict:
    """Loads the KEV catalog from a local file or via download."""
    if path:
        log(MODULE, f"Lecture du catalogue local : {path}")
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    log(MODULE, f"Téléchargement du catalogue : {KEV_URL}")
    resp = requests.get(KEV_URL, timeout=60)
    resp.raise_for_status()
    return resp.json()


def sync_kev(catalog_path: Optional[str] = None, reset: bool = False) -> dict:
    """Sets KEV=1 on the catalog CVEs. Returns counters."""
    catalog = _load_catalog(catalog_path)
    cves = sorted({
        v.get("cveID", "").strip()
        for v in catalog.get("vulnerabilities", [])
        if v.get("cveID", "").startswith("CVE-")
    })
    version = catalog.get("catalogVersion", "?")
    log(MODULE, f"Catalogue v{version} : {len(cves)} CVE")

    flagged = 0
    with session_scope("XVULNERABILITY") as session:
        if reset:
            session.execute(text('UPDATE "VULNERABILITY" SET KEV = 0 WHERE KEV = 1'))
            log(MODULE, "Flags KEV existants remis à 0 (--reset)")
        for i in range(0, len(cves), CHUNK):
            chunk = cves[i : i + CHUNK]
            placeholders = ", ".join(f":c{j}" for j in range(len(chunk)))
            params = {f"c{j}": cve for j, cve in enumerate(chunk)}
            res = session.execute(
                text(
                    f'UPDATE "VULNERABILITY" SET KEV = 1 '
                    f"WHERE VULReferentialID IN ({placeholders}) "
                    f"AND (KEV IS NULL OR KEV != 1)"
                ),
                params,
            )
            flagged += res.rowcount or 0
        session.commit()

    log(MODULE, f"Synchronisation terminée : {flagged} ligne(s) marquée(s) KEV=1")
    return {"catalog": version, "cves": len(cves), "flagged": flagged}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Synchronise VULNERABILITY.KEV avec le catalogue CISA KEV"
    )
    parser.add_argument("--file", default=None, help="Catalogue JSON local (sinon téléchargement)")
    parser.add_argument("--reset", action="store_true",
                        help="Remet d'abord tous les KEV à 0 (miroir exact du catalogue)")
    args = parser.parse_args()
    sync_kev(catalog_path=args.file, reset=args.reset)


if __name__ == "__main__":
    main()
