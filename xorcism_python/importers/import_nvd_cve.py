"""
import_nvd_cve.py - Converted from import_nvd_cve.ps1
Jerome Athias - XORCISM

Downloads NVD CVE data via the NVD API 2.0 and stores it in XVULNERABILITY.db.

Usage:
    python import_nvd_cve.py [--api-key KEY] [--recent-only] [--batch-size 2000] [--limit N]

API: https://services.nvd.nist.gov/rest/json/cves/2.0
Rate limit: 5 req/30s (no key), 50 req/30s (with key)

NVD -> VULNERABILITY mapping (same convention as the existing rows,
inherited from import_nvd_cve.ps1):
    VULGUID = VULReferential = VULReferentialID = VULName = VULShortName = CVE id
    VULType = vulnStatus; ValidFromDate = published; CWEID = "CWE-n" (text)
Idempotent upsert by VULReferentialID (indexed, unique in the data):
the CVEs already present are updated, never re-inserted. The table has no
SQLite PRIMARY KEY (no autoincrement): the VulnerabilityID of the
new rows are allocated sequentially after MAX(VulnerabilityID).
"""

import argparse
import os
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

import requests
from sqlalchemy import bindparam, func, insert, select, update

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python.models.base import session_scope
from xorcism_python.utils import log

MODULE  = "ImportNVD"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CWE_RE = re.compile(r"^CWE-\d+$")

# Fields refreshed on each run (insert AND update). VULReferentialID,
# VULGUID, CreatedDate, KEV… are only set at insertion.
REFRESH_COLS = (
    "VULReferential", "VULName", "VULShortName", "VULDescription",
    "VULPublishedDate", "VULModifiedDate", "VULType",
    "CVSSBaseScore", "CVSSImpactSubscore", "CVSSExploitabilitySubscore",
    "CVSSMetricAccessVector", "CVSSMetricAccessComplexity",
    "CVSSMetricAuthentication", "CVSSMetricConfImpact",
    "CVSSMetricIntegImpact", "CVSSMetricAvailImpact",
)


# ---------------------------------------------------------------------------
# CVSS helpers (prefer V31 > V30 > V2)
# ---------------------------------------------------------------------------

def _cvss_summary(cve: dict) -> dict:
    """Extracts the CVSS (v3.1 > v3.0 > v2) into the historical CVSSMetric*
    columns: privilegesRequired (v3) / authentication (v2) go into
    CVSSMetricAuthentication, attackVector (v3) / accessVector (v2) into
    CVSSMetricAccessVector, etc."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = metrics.get(key) or []
        if not m:
            continue
        v2   = key == "cvssMetricV2"
        data = m[0].get("cvssData", {})
        return {
            "CVSSBaseScore":              data.get("baseScore"),
            "CVSSImpactSubscore":         m[0].get("impactScore"),
            "CVSSExploitabilitySubscore": m[0].get("exploitabilityScore"),
            "CVSSMetricAccessVector":     data.get("accessVector" if v2 else "attackVector"),
            "CVSSMetricAccessComplexity": data.get("accessComplexity" if v2 else "attackComplexity"),
            "CVSSMetricAuthentication":   data.get("authentication" if v2 else "privilegesRequired"),
            "CVSSMetricConfImpact":       data.get("confidentialityImpact"),
            "CVSSMetricIntegImpact":      data.get("integrityImpact"),
            "CVSSMetricAvailImpact":      data.get("availabilityImpact"),
        }
    return {
        "CVSSBaseScore": None, "CVSSImpactSubscore": None,
        "CVSSExploitabilitySubscore": None, "CVSSMetricAccessVector": None,
        "CVSSMetricAccessComplexity": None, "CVSSMetricAuthentication": None,
        "CVSSMetricConfImpact": None, "CVSSMetricIntegImpact": None,
        "CVSSMetricAvailImpact": None,
    }


# ---------------------------------------------------------------------------
# NVD API fetcher
# ---------------------------------------------------------------------------

def fetch_page(
    session: requests.Session,
    api_key: Optional[str],
    start_index: int,
    batch_size: int,
    pub_start_date: Optional[str] = None,
    pub_end_date: Optional[str] = None,
) -> dict:
    params: dict[str, Any] = {
        "resultsPerPage": batch_size,
        "startIndex": start_index,
    }
    if pub_start_date:
        params["pubStartDate"] = pub_start_date
    if pub_end_date:
        params["pubEndDate"] = pub_end_date

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    resp = session.get(NVD_URL, params=params, headers=headers, timeout=60)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Import runner
# ---------------------------------------------------------------------------

def import_nvd(
    api_key: Optional[str] = None,
    batch_size: int = 2000,
    recent_only: bool = False,
    kev_sync: bool = True,
    limit: Optional[int] = None,
) -> None:
    http = requests.Session()
    rate_delay = 0.65 if api_key else 6.5   # ~50/30s or ~5/30s

    # Date range for recent-only mode (last 120 days)
    pub_start = pub_end = None
    if recent_only:
        now = datetime.now(timezone.utc)
        pub_end   = now.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_start = (now - timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S.000")
        log(MODULE, f"Recent mode: {pub_start} -> {pub_end}")

    # First call to get total
    log(MODULE, "Fetching first page to get total count...")
    data = fetch_page(http, api_key, 0, batch_size, pub_start, pub_end)
    total = data.get("totalResults", 0)
    if limit is not None:
        total = min(total, limit)
    log(MODULE, f"Total CVEs to import: {total}")

    inserted = updated = cwe_added = cpe_added = processed = 0
    start_index = 0
    FLUSH_EVERY = 5000
    run_date    = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    with session_scope("XVULNERABILITY") as db_session:
        from xorcism_python.models.xvulnerability import (
            VULNERABILITY, VULNERABILITYFORCWE, VULNERABILITYFORCPE)

        log(MODULE, "Loading existing CVEs (upsert key: VULReferentialID)...")
        existing = {
            ref: vid
            for ref, vid in db_session.execute(
                select(VULNERABILITY.VULReferentialID, VULNERABILITY.VulnerabilityID)
            )
            if ref
        }
        cwe_pairs = {
            (vid, cwe)
            for vid, cwe in db_session.execute(
                select(VULNERABILITYFORCWE.VulnerabilityID, VULNERABILITYFORCWE.CWEID)
            )
        }
        next_vuln_id = (db_session.execute(
            select(func.max(VULNERABILITY.VulnerabilityID))).scalar() or 0) + 1
        next_cwe_id = (db_session.execute(
            select(func.max(VULNERABILITYFORCWE.CWEVulnerabilityID))).scalar() or 0) + 1
        # Affected CPE links (CPEID stores the CPE string, as CWEID stores "CWE-…")
        cpe_pairs = {
            (vid, cpe)
            for vid, cpe in db_session.execute(
                select(VULNERABILITYFORCPE.VulnerabilityID, VULNERABILITYFORCPE.CPEID)
            )
        }
        next_cpe_id = (db_session.execute(
            select(func.max(VULNERABILITYFORCPE.CPEVulnerabilityID))).scalar() or 0) + 1
        log(MODULE, f"Existing: {len(existing)} CVEs, {len(cwe_pairs)} CWE links, {len(cpe_pairs)} CPE links")

        # Targeted UPDATE on VULReferentialID (indexed; VulnerabilityID is not)
        upd_stmt = (
            update(VULNERABILITY)
            .where(VULNERABILITY.VULReferentialID == bindparam("b_ref"))
            .values({col: bindparam("b_" + col) for col in REFRESH_COLS})
        )

        insert_rows: list[dict] = []
        update_rows: list[dict] = []
        cwe_rows:    list[dict] = []
        cpe_rows:    list[dict] = []

        def _flush():
            if insert_rows:
                db_session.execute(insert(VULNERABILITY), insert_rows)
                insert_rows.clear()
            if update_rows:
                # Core connection (same transaction): an ORM update() with a
                # list of parameters would require the PK, but only VULReferentialID
                # is indexed.
                db_session.connection().execute(upd_stmt, update_rows)
                update_rows.clear()
            if cwe_rows:
                db_session.execute(insert(VULNERABILITYFORCWE), cwe_rows)
                cwe_rows.clear()
            if cpe_rows:
                db_session.execute(insert(VULNERABILITYFORCPE), cpe_rows)
                cpe_rows.clear()
            db_session.commit()
            log(MODULE, f"  Flushed. {inserted} new, {updated} updated, {cwe_added} CWE, {cpe_added} CPE links")

        while True:
            if start_index > 0:
                time.sleep(rate_delay)
                data = fetch_page(http, api_key, start_index, batch_size, pub_start, pub_end)

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for item in vulnerabilities:
                if limit is not None and processed >= limit:
                    break
                cve    = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                # Description (prefer English)
                descs = cve.get("descriptions", [])
                description = next(
                    (d["value"] for d in descs if d.get("lang") == "en"), ""
                )
                published = cve.get("published", "")
                modified  = cve.get("lastModified", "")

                fields = {
                    "VULReferential": cve_id,
                    "VULName": cve_id,
                    "VULShortName": cve_id,
                    "VULDescription": description or None,
                    "VULPublishedDate": published or None,
                    "VULModifiedDate": modified or None,
                    "VULType": cve.get("vulnStatus") or None,
                    **_cvss_summary(cve),
                }

                vuln_id = existing.get(cve_id)
                if vuln_id is None:
                    vuln_id = next_vuln_id
                    next_vuln_id += 1
                    existing[cve_id] = vuln_id
                    insert_rows.append({
                        "VulnerabilityID": vuln_id,
                        "VULGUID": cve_id,
                        "VULReferentialID": cve_id,
                        "CreatedDate": run_date,
                        "ValidFromDate": published or None,
                        "isEncrypted": 0,
                        **fields,
                    })
                    inserted += 1
                else:
                    update_rows.append(
                        {"b_ref": cve_id, **{"b_" + k: v for k, v in fields.items()}}
                    )
                    updated += 1
                processed += 1

                # CWE links: additive, deduplicated on (VulnerabilityID, CWEID)
                for weakness in cve.get("weaknesses", []):
                    for desc in weakness.get("description", []):
                        cwe_val = desc.get("value", "")
                        if not CWE_RE.match(cwe_val):
                            continue
                        if (vuln_id, cwe_val) in cwe_pairs:
                            continue
                        cwe_pairs.add((vuln_id, cwe_val))
                        cwe_rows.append({
                            "CWEVulnerabilityID": next_cwe_id,
                            "VulnerabilityID": vuln_id,
                            "CWEID": cwe_val,
                            "CreatedDate": run_date,
                            "isEncrypted": 0,
                        })
                        next_cwe_id += 1
                        cwe_added += 1

                # Affected CPE links: configurations[].nodes[].cpeMatch[] (vulnerable)
                # CPEID = CPE string (criteria), same text convention as CWEID.
                for config in cve.get("configurations", []):
                    for node in config.get("nodes", []):
                        for m in node.get("cpeMatch", []):
                            if not m.get("vulnerable"):
                                continue
                            crit = (m.get("criteria") or "").strip()
                            if not crit or (vuln_id, crit) in cpe_pairs:
                                continue
                            cpe_pairs.add((vuln_id, crit))
                            cpe_rows.append({
                                "CPEVulnerabilityID": next_cpe_id,
                                "VulnerabilityID": vuln_id,
                                "CPEID": crit,
                                "isKnownVulnerable": 1,
                                "CreatedDate": run_date,
                                "isEncrypted": 0,
                            })
                            next_cpe_id += 1
                            cpe_added += 1

                if len(insert_rows) + len(update_rows) + len(cwe_rows) + len(cpe_rows) >= FLUSH_EVERY:
                    _flush()

            start_index += len(vulnerabilities)
            log(MODULE, f"Progress: {min(start_index, total)}/{total}")

            if start_index >= total:
                break

        _flush()

    log(MODULE, f"Import complete. {inserted} new CVEs, {updated} updated, {cwe_added} CWE links, {cpe_added} CPE links added.")

    # CISA KEV: automatically flags the catalog CVEs (VULNERABILITY.KEV=1).
    # Best-effort: a failure (network…) does not invalidate the preceding NVD import.
    if kev_sync:
        try:
            try:
                from .import_cisa_kev import sync_kev  # module execution
            except ImportError:
                from import_cisa_kev import sync_kev   # direct script execution
            res = sync_kev()
            log(MODULE, f"KEV sync: {res['flagged']} CVE marquées (catalogue v{res['catalog']}, {res['cves']} entrées)")
        except Exception as e:  # noqa: BLE001
            log(MODULE, f"KEV sync ignorée (erreur : {e})")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Import NVD CVE data into XVULNERABILITY.db")
    parser.add_argument("--api-key", default=None, help="NVD API key (optional but recommended)")
    parser.add_argument("--batch-size", type=int, default=2000)
    parser.add_argument("--recent-only", action="store_true", help="Only import last 120 days")
    parser.add_argument("--limit", type=int, default=None,
                        help="Traiter au plus N CVE (tests sur un petit lot)")
    parser.add_argument("--no-kev", action="store_true",
                        help="Ne pas synchroniser le flag KEV (catalogue CISA) après l'import")
    args = parser.parse_args()

    import_nvd(
        api_key=args.api_key,
        batch_size=args.batch_size,
        recent_only=args.recent_only,
        kev_sync=not args.no_kev,
        limit=args.limit,
    )


if __name__ == "__main__":
    main()
