"""
import_KEV.py — Imports the CISA KEV catalog (Known Exploited Vulnerabilities)
into XVULNERABILITY.VULNERABILITY.
Jerome Athias - XORCISM

Source  : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Schema  : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json
          (catalogVersion, dateReleased, count, vulnerabilities[]:
           cveID, vendorProject, product, vulnerabilityName, dateAdded,
           shortDescription, requiredAction, dueDate,
           knownRansomwareCampaignUse, notes, cwes[])

For each catalog entry (matched by VULReferentialID = cveID):
  - existing row  → KEV=1, Action=requiredAction, DueDate=dueDate
  - missing row   → creation: VULReferential/VULReferentialID/VULName=cveID,
                       VULShortName=vulnerabilityName, VULDescription=shortDescription
                       (+ vendor/product/ransomware/notes), VULPublishedDate=dateAdded,
                       KEV=1, Action, DueDate, Exploited=1 (observed exploitation).

Idempotent: re-running updates the same rows (no duplicate).

Usage:
    python import_KEV.py [--file catalog.json] [--dry-run]
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

MODULE = "ImportKEV"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CHUNK = 500  # IN clauses in batches (SQLite limit: 999 variables)


def _load_catalog(path: Optional[str] = None) -> dict:
    if path:
        log(MODULE, f"Lecture du catalogue local : {path}")
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    log(MODULE, f"Téléchargement du catalogue : {KEV_URL}")
    resp = requests.get(KEV_URL, timeout=60)
    resp.raise_for_status()
    return resp.json()


def _description(entry: dict) -> str:
    """Composed description: summary + vendor/product context + ransomware/notes."""
    parts = [entry.get("shortDescription", "").strip()]
    vendor = entry.get("vendorProject", "").strip()
    product = entry.get("product", "").strip()
    if vendor or product:
        parts.append(f"[KEV] {vendor} {product}".strip())
    if entry.get("knownRansomwareCampaignUse", "").lower() == "known":
        parts.append("[KEV] Utilisée dans des campagnes de ransomware connues.")
    notes = entry.get("notes", "").strip()
    if notes:
        parts.append(notes)
    return "\n".join(p for p in parts if p)[:4000]


def import_kev(catalog_path: Optional[str] = None, dry_run: bool = False) -> dict:
    """Upsert of the KEV catalog into VULNERABILITY. Returns counters."""
    catalog = _load_catalog(catalog_path)
    entries = {
        e["cveID"].strip(): e
        for e in catalog.get("vulnerabilities", [])
        if e.get("cveID", "").startswith("CVE-")
    }
    version = catalog.get("catalogVersion", "?")
    log(MODULE, f"Catalogue v{version} : {len(entries)} CVE "
                f"(dateReleased {catalog.get('dateReleased', '?')})")

    updated = created = 0
    cves = sorted(entries)

    with session_scope("XVULNERABILITY") as session:
        # 1) CVEs already present (batched matching)
        existing: set[str] = set()
        for i in range(0, len(cves), CHUNK):
            chunk = cves[i : i + CHUNK]
            ph = ", ".join(f":c{j}" for j in range(len(chunk)))
            rows = session.execute(
                text(f'SELECT VULReferentialID FROM "VULNERABILITY" '
                     f"WHERE VULReferentialID IN ({ph})"),
                {f"c{j}": c for j, c in enumerate(chunk)},
            ).fetchall()
            existing.update(r[0] for r in rows)

        # 2) update of the existing rows
        for cve in cves:
            if cve not in existing:
                continue
            e = entries[cve]
            if dry_run:
                updated += 1
                continue
            res = session.execute(
                text('UPDATE "VULNERABILITY" SET KEV = 1, "Action" = :action, '
                     '"DueDate" = :due WHERE VULReferentialID = :cve'),
                {"action": e.get("requiredAction", ""), "due": e.get("dueDate", ""), "cve": cve},
            )
            updated += res.rowcount or 0

        # 3) creation of the missing CVEs
        missing = [c for c in cves if c not in existing]
        if missing:
            next_id = session.execute(
                text('SELECT COALESCE(MAX(VulnerabilityID), 0) + 1 FROM "VULNERABILITY"')
            ).scalar_one()
            for cve in missing:
                e = entries[cve]
                log(MODULE, f"  Nouvelle CVE (absente du référentiel local) : {cve}")
                if dry_run:
                    created += 1
                    continue
                session.execute(
                    text('INSERT INTO "VULNERABILITY" '
                         "(VulnerabilityID, VULReferential, VULReferentialID, VULName, "
                         " VULShortName, VULDescription, VULPublishedDate, "
                         " KEV, Exploited, \"Action\", \"DueDate\") "
                         "VALUES (:id, :cve, :cve, :cve, :short, :descr, :added, "
                         "        1, 1, :action, :due)"),
                    {
                        "id": next_id,
                        "cve": cve,
                        "short": e.get("vulnerabilityName", "")[:400],
                        "descr": _description(e),
                        "added": e.get("dateAdded", ""),
                        "action": e.get("requiredAction", ""),
                        "due": e.get("dueDate", ""),
                    },
                )
                next_id += 1
                created += 1
        if not dry_run:
            session.commit()

    verb = "à traiter (dry-run)" if dry_run else "traitées"
    log(MODULE, f"Import terminé : {updated} CVE mises à jour, {created} créées — {verb}")
    return {"catalog": version, "cves": len(entries), "updated": updated, "created": created}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Importe le catalogue CISA KEV dans VULNERABILITY (KEV=1, Action, DueDate)"
    )
    parser.add_argument("--file", default=None, help="Catalogue JSON local (sinon téléchargement)")
    parser.add_argument("--dry-run", action="store_true", help="Compte sans écrire")
    args = parser.parse_args()
    import_kev(catalog_path=args.file, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
