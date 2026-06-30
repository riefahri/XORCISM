"""import_nca_ecc.py — import the Saudi NCA Essential Cybersecurity Controls (ECC) into XORCISM.CONTROL.

The National Cybersecurity Authority (NCA) Essential Cybersecurity Controls (ECC-1:2018) is the Kingdom
of Saudi Arabia's baseline cybersecurity framework, organised as 5 main domains, 29 subdomains and 114
controls. This vocabulary lets XORCISM track ECC as controls, back the ECC compliance journey, and map
other controls to it.

Copyright-safe: only the official domain/subdomain numbers + titles and ORIGINAL one-line summaries are
stored (no normative NCA control text). Writes CONTROL rows (VocabularyID = the ECC vocab; ControlName =
"<ref> <title>", CIS = <ref>, Statement = summary, ControlDescription = "NCA ECC — Domain <n>") and
registers VOCABULARY "Saudi NCA Essential Cybersecurity Controls (ECC-1:2018)". Raw SQL; DB = XORCISM_DB_DIR.

    python xorcism_python/importers/import_nca_ecc.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "Saudi NCA Essential Cybersecurity Controls (ECC-1:2018)"

DOMAINS = {
    "1": "Cybersecurity Governance",
    "2": "Cybersecurity Defence",
    "3": "Cybersecurity Resilience",
    "4": "Third-Party and Cloud Computing Cybersecurity",
    "5": "Industrial Control Systems Cybersecurity",
}

# (ref, title, original summary). Refs follow the official ECC domain/subdomain numbering.
ITEMS = [
    ("1", "Cybersecurity Governance", "Establish the governance that directs and sustains cybersecurity across the organisation."),
    ("1-1", "Cybersecurity Strategy", "A documented, approved and resourced cybersecurity strategy aligned with the organisation's objectives and regulatory obligations."),
    ("1-2", "Cybersecurity Management", "A dedicated cybersecurity function reporting at the appropriate level, independent from the IT function."),
    ("1-3", "Cybersecurity Policies and Procedures", "Approved cybersecurity policies and procedures, communicated, implemented and periodically reviewed."),
    ("1-4", "Cybersecurity Roles and Responsibilities", "Cybersecurity roles and responsibilities are defined, assigned and supported by leadership."),
    ("1-5", "Cybersecurity Risk Management", "A cybersecurity risk-management methodology to identify, assess and treat risks throughout the lifecycle."),
    ("1-6", "Cybersecurity in Information & Technology Project Management", "Cybersecurity requirements are embedded in IT project and change management."),
    ("1-7", "Compliance with Cybersecurity Standards, Laws and Regulations", "Compliance with relevant national cybersecurity standards, laws and regulatory requirements is ensured and verified."),
    ("1-8", "Periodical Cybersecurity Review and Audit", "Cybersecurity implementation is periodically reviewed and independently audited."),
    ("1-9", "Cybersecurity in Human Resources", "Cybersecurity requirements are addressed before, during and after employment (screening, agreements, off-boarding)."),
    ("1-10", "Cybersecurity Awareness and Training Program", "A cybersecurity awareness programme and role-based training keep staff competent against threats."),
    ("2", "Cybersecurity Defence", "Protect the organisation's assets, networks, systems and data against cyber threats."),
    ("2-1", "Asset Management", "An accurate inventory of information and technology assets with assigned owners and acceptable-use rules."),
    ("2-2", "Identity and Access Management", "Identity and access management enforcing least privilege, strong authentication and periodic access review."),
    ("2-3", "Information System and Processing Facilities Protection", "Hardening, malware protection, patching and secure configuration of systems and processing facilities."),
    ("2-4", "Email Protection", "Protection of the email service against phishing, spoofing and malware (filtering, authentication, encryption)."),
    ("2-5", "Networks Security Management", "Segmentation, perimeter protection and secure management of networks."),
    ("2-6", "Mobile Devices Security", "Security of mobile devices and BYOD, including separation of corporate data and remote wipe."),
    ("2-7", "Data and Information Protection", "Classification and protection of data and information per its sensitivity, throughout its lifecycle."),
    ("2-8", "Cryptography", "Approved cryptographic standards and key management protect data confidentiality and integrity."),
    ("2-9", "Backup and Recovery Management", "Regular, protected and tested backups enable recovery of systems and data."),
    ("2-10", "Vulnerabilities Management", "Continuous identification, assessment and timely remediation of technical vulnerabilities."),
    ("2-11", "Penetration Testing", "Periodic penetration testing of internet-facing and critical systems to find exploitable weaknesses."),
    ("2-12", "Cybersecurity Event Logs and Monitoring Management", "Centralised logging and monitoring of cybersecurity events with adequate retention."),
    ("2-13", "Cybersecurity Incident and Threat Management", "Detection, response, escalation and threat management for cybersecurity incidents."),
    ("2-14", "Physical Security", "Physical protection of information-processing facilities against unauthorised access and environmental threats."),
    ("2-15", "Web Application Security", "Secure development and protection of external web applications (e.g. multi-tier, WAF, secure coding)."),
    ("3", "Cybersecurity Resilience", "Embed cybersecurity in business-continuity management so critical services survive disruption."),
    ("3-1", "Cybersecurity Resilience Aspects of Business Continuity Management (BCM)", "Cybersecurity is integrated into BCM, including resilience of systems, incident continuity and recovery objectives."),
    ("4", "Third-Party and Cloud Computing Cybersecurity", "Manage the cybersecurity risks of third parties and hosting/cloud services."),
    ("4-1", "Third-Party Cybersecurity", "Cybersecurity requirements in third-party contracts, with assessment and monitoring before and during engagement."),
    ("4-2", "Cloud Computing and Hosting Cybersecurity", "Cybersecurity requirements for cloud and hosting, including data location, segregation and provider assurance."),
    ("5", "Industrial Control Systems Cybersecurity", "Protect industrial control systems / operational technology that run critical processes."),
    ("5-1", "Industrial Control Systems (ICS) Protection", "Protection of OT/ICS environments: segregation from IT, hardening, access control and monitoring."),
]


def _db_path() -> str:
    d = os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, "XORCISM.db")


def _ensure_vocab(cur: sqlite3.Cursor, name: str) -> int:
    cols = {r[1] for r in cur.execute("PRAGMA table_info(VOCABULARY)").fetchall()}
    namecol = "VocabularyName" if "VocabularyName" in cols else ("Name" if "Name" in cols else None)
    if namecol:
        row = cur.execute(f"SELECT VocabularyID FROM VOCABULARY WHERE {namecol}=?", (name,)).fetchone()
        if row:
            return int(row[0])
    nid = (cur.execute("SELECT COALESCE(MAX(VocabularyID),0) FROM VOCABULARY").fetchone()[0] or 0) + 1
    rec = {"VocabularyID": nid}
    if namecol:
        rec[namecol] = name
    if "VocabularyGUID" in cols:
        rec["VocabularyGUID"] = str(uuid.uuid4())
    keys = list(rec)
    cur.execute(f"INSERT INTO VOCABULARY ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
    return nid


def main() -> int:
    con = sqlite3.connect(_db_path()); con.execute("PRAGMA busy_timeout=15000"); cur = con.cursor()
    now = datetime.now(timezone.utc).isoformat()
    vid = _ensure_vocab(cur, VOCAB)
    ccols = {r[1] for r in cur.execute("PRAGMA table_info(CONTROL)").fetchall()}
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))  # idempotent
    next_id = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    n = 0
    for ref, title, summary in ITEMS:
        dom = ref.split("-")[0]
        rec = {
            "ControlID": next_id, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{ref} {title}"[:300],
            "ControlDescription": f"NCA ECC — Domain {dom} {DOMAINS.get(dom, '')}".strip(),
            "VocabularyID": vid, "CIS": ref, "Statement": summary,
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
        next_id += 1; n += 1
    con.commit(); con.close()
    print(f"[nca-ecc] VocabularyID={vid}: {n} ECC entries imported (5 domains + 29 subdomains).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
