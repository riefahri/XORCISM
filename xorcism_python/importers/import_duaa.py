"""import_duaa.py - import the UK Data (Use and Access) Act 2025 (DUAA) into XORCISM.CONTROL.

The Data (Use and Access) Act 2025 received Royal Assent on 19 June 2025. It is an *amending* Act
that reforms the UK GDPR, the Data Protection Act 2018 and PECR, and creates new data-access /
digital-verification regimes. This importer registers the VOCABULARY
"Data (Use and Access) Act 2025 (DUAA)" and writes the Act's key provisions - grouped by Part,
with the substantive data-protection reforms of Part 5 broken out individually - as CONTROL rows
(reference + short factual title; UK legislation is Crown copyright under the Open Government
Licence). Only the structural references and provision titles + own-words obligation notes are
stored, not the statutory text.

It also writes CONTROLMAPPING rows (Framework='GDPR') crosswalking each Part 5 reform to the
(UK/EU) GDPR article(s) it amends or relates to - mirroring the ISO/IEC 27701 -> GDPR crosswalk in
import_iso27701.py and complementing import_gdpr.py.

Idempotent: re-running deletes the DUAA controls + their GDPR mappings and re-inserts. Raw SQL;
DB path = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_duaa.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "Data (Use and Access) Act 2025 (DUAA)"

# Part -> [(ref, title, own-words obligation note)].
PARTS = [
    ("Part 1 - Access to customer data and business data", [
        ("DUAA.1", "Customer and business data access (Smart Data schemes)",
         "Powers to require holders of customer/business data to share it with the customer or authorised third parties."),
    ]),
    ("Part 2 - Digital verification services", [
        ("DUAA.2", "Digital verification services and the DVS trust framework",
         "Trust framework, register and information gateway for certified digital identity verification providers."),
    ]),
    ("Part 3 - National Underground Asset Register", [
        ("DUAA.3", "National Underground Asset Register",
         "Statutory register of underground apparatus with duties to record and keep information up to date."),
    ]),
    ("Part 4 - Registers of births and deaths", [
        ("DUAA.4", "Digital registers of births and deaths",
         "Moves civil registration to electronic registers."),
    ]),
    ("Part 5 - Data protection and privacy", [
        ("DUAA.5.1", "Recognised legitimate interests",
         "New lawful ground for specified public-interest purposes that does not require a legitimate-interests balancing test."),
        ("DUAA.5.2", "Purpose limitation and compatible further processing",
         "Clarifies when further processing is compatible with the original purpose; lists conditions and safeguards."),
        ("DUAA.5.3", "Reform of automated decision-making and profiling",
         "Permits more solely-automated significant decisions outside special-category data, subject to safeguards."),
        ("DUAA.5.4", "Subject access requests - reasonable and proportionate searches",
         "Controllers need only carry out reasonable and proportionate searches when responding to access requests."),
        ("DUAA.5.5", "Time limits for responding to requests (stop-the-clock)",
         "Allows pausing the response clock while seeking clarification or verifying identity."),
        ("DUAA.5.6", "Duty to facilitate and respond to complaints",
         "Controllers must provide a means to complain, acknowledge within 30 days and respond without undue delay."),
        ("DUAA.5.7", "International transfers - the data protection test",
         "New risk-based 'data protection test' for adequacy regulations and transfer mechanisms."),
        ("DUAA.5.8", "Processing for scientific research, consent and safeguards",
         "Broad consent to areas of scientific research and a clearer research regime with safeguards."),
        ("DUAA.5.9", "Records of processing activities - risk-based simplification",
         "ROPA obligations focused on high-risk processing for many organisations."),
        ("DUAA.5.10", "Higher protection for children's personal data online",
         "Information-society services likely accessed by children must consider their higher protection needs."),
        ("DUAA.5.11", "PECR - cookies and tracking exceptions",
         "Exempts certain low-risk uses (e.g. analytics, appearance/functionality) from prior consent."),
        ("DUAA.5.12", "PECR - direct marketing and charity soft opt-in",
         "Extends the soft opt-in to charities communicating for their charitable purposes."),
        ("DUAA.5.13", "PECR - penalties aligned to UK GDPR fine levels",
         "Raises maximum PECR fines to UK GDPR levels (up to GBP 17.5m / 4% turnover)."),
    ]),
    ("Part 6 - The Information Commission", [
        ("DUAA.6", "Establishment of the Information Commission",
         "Replaces the Information Commissioner (ICO) with a body corporate, the Information Commission, with new duties."),
    ]),
    ("Part 7 - Final and supplementary provisions", [
        ("DUAA.7", "Other data provisions",
         "Further provisions (e.g. retention of biometric data, special categories, information standards)."),
    ]),
]

# (UK/EU) GDPR article -> short title (for CONTROLMAPPING.ExternalName).
GDPR_TITLES = {
    "Art.5": "Principles relating to processing of personal data",
    "Art.6": "Lawfulness of processing",
    "Art.8": "Conditions applicable to child's consent (information society services)",
    "Art.12": "Transparent information and modalities for exercising rights",
    "Art.15": "Right of access by the data subject",
    "Art.21": "Right to object",
    "Art.22": "Automated individual decision-making, including profiling",
    "Art.30": "Records of processing activities",
    "Art.44": "General principle for transfers",
    "Art.45": "Transfers on the basis of an adequacy decision",
    "Art.46": "Transfers subject to appropriate safeguards",
    "Art.77": "Right to lodge a complaint with a supervisory authority",
    "Art.89": "Safeguards for archiving, research and statistics",
}

# DUAA Part 5 reform -> (UK/EU) GDPR article(s) amended or related.
GDPR_MAP = {
    "DUAA.5.1": ["Art.6"], "DUAA.5.2": ["Art.5", "Art.6"], "DUAA.5.3": ["Art.22"],
    "DUAA.5.4": ["Art.12", "Art.15"], "DUAA.5.5": ["Art.12"], "DUAA.5.6": ["Art.77"],
    "DUAA.5.7": ["Art.44", "Art.45", "Art.46"], "DUAA.5.8": ["Art.5", "Art.89"],
    "DUAA.5.9": ["Art.30"], "DUAA.5.10": ["Art.8"], "DUAA.5.11": ["Art.6"], "DUAA.5.12": ["Art.21"],
}


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
    if "CreatedDate" in cols:
        rec["CreatedDate"] = datetime.now(timezone.utc).isoformat()
    keys = list(rec)
    cur.execute(f"INSERT INTO VOCABULARY ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
    return nid


def main() -> int:
    con = sqlite3.connect(_db_path())
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    now = datetime.now(timezone.utc).isoformat()

    vid = _ensure_vocab(cur, VOCAB)
    ccols = {r[1] for r in cur.execute("PRAGMA table_info(CONTROL)").fetchall()}
    has_map = cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLMAPPING'").fetchone() is not None

    old_ids = [r[0] for r in cur.execute("SELECT ControlID FROM CONTROL WHERE VocabularyID=?", (vid,)).fetchall()]
    if old_ids and has_map:
        cur.execute(f"DELETE FROM CONTROLMAPPING WHERE Framework='GDPR' AND ControlID IN ({','.join('?'*len(old_ids))})", old_ids)
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))

    next_cid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    next_mid = 1
    if has_map:
        next_mid = (cur.execute("SELECT COALESCE(MAX(MappingID),0) FROM CONTROLMAPPING").fetchone()[0] or 0) + 1

    def insert_control(rec: dict) -> None:
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])

    n_ctrl = n_map = 0
    for part, items in PARTS:
        for ref, title, note in items:
            cid = next_cid
            next_cid += 1
            insert_control({
                "ControlID": cid, "ControlGUID": str(uuid.uuid4()),
                "ControlName": f"{ref} {title}"[:300],
                "ISO": ref, "CIS": ref,
                "ControlDescription": f"Data (Use and Access) Act 2025 - {part}",
                "Guidance": note,
                "VocabularyID": vid,
                "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
            })
            n_ctrl += 1
            if has_map:
                for art in GDPR_MAP.get(ref, []):
                    cur.execute(
                        "INSERT INTO CONTROLMAPPING (MappingID, MappingGUID, ControlID, Framework, ExternalID, ExternalName, Relationship, Source, CreatedDate) "
                        "VALUES (?,?,?,?,?,?,?,?,?)",
                        (next_mid, str(uuid.uuid4()), cid, "GDPR", art, GDPR_TITLES.get(art, art), "amends",
                         "DUAA 2025 (UK) <-> UK/EU GDPR correspondence", now))
                    next_mid += 1
                    n_map += 1

    con.commit()
    con.close()
    print(f"[duaa] VocabularyID={vid}: {n_ctrl} DUAA 2025 provisions, {n_map} GDPR mappings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
