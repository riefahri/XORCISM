"""import_gdpr.py - import the EU GDPR (Regulation (EU) 2016/679) into XORCISM.CONTROL.

Until now GDPR existed in XORCISM only as a *crosswalk target* (CONTROLMAPPING.Framework='GDPR',
e.g. from ISO/IEC 27701 - see import_iso27701.py) and as a value in the framework picker. This
importer makes it a first-class control catalogue: it registers the VOCABULARY "GDPR" and writes
the operative compliance articles (Chapters II-V plus the key remedies/penalties and specific-
processing articles) as CONTROL rows.

EU legislation is published by the EU (EUR-Lex) and the official article TITLES are factual legal
references; only those titles + the chapter grouping are stored.

Mapping per article:
  ControlName        = "<art> <title>"   (e.g. "Art.17 Right to erasure ('right to be forgotten')")
  ISO / CIS          = "<art>"           (e.g. "Art.17")  - the reference, reused as the join key
  ControlDescription = "EU GDPR - <chapter>"
  Guidance           = obligation owner note
  VocabularyID       = get-or-create("GDPR")

Idempotent: re-running deletes the GDPR controls and re-inserts. Raw SQL; DB path = XORCISM_DB_DIR
env or the default.

    python xorcism_python/importers/import_gdpr.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "GDPR"

# Chapter -> [(article, official title)]. EU GDPR (Regulation (EU) 2016/679).
CHAPTERS = [
    ("Chapter II - Principles", [
        ("Art.5", "Principles relating to processing of personal data"),
        ("Art.6", "Lawfulness of processing"),
        ("Art.7", "Conditions for consent"),
        ("Art.8", "Conditions applicable to child's consent in relation to information society services"),
        ("Art.9", "Processing of special categories of personal data"),
        ("Art.10", "Processing of personal data relating to criminal convictions and offences"),
        ("Art.11", "Processing which does not require identification"),
    ]),
    ("Chapter III - Rights of the data subject", [
        ("Art.12", "Transparent information, communication and modalities for the exercise of the rights"),
        ("Art.13", "Information to be provided where personal data are collected from the data subject"),
        ("Art.14", "Information to be provided where personal data have not been obtained from the data subject"),
        ("Art.15", "Right of access by the data subject"),
        ("Art.16", "Right to rectification"),
        ("Art.17", "Right to erasure ('right to be forgotten')"),
        ("Art.18", "Right to restriction of processing"),
        ("Art.19", "Notification obligation regarding rectification or erasure or restriction of processing"),
        ("Art.20", "Right to data portability"),
        ("Art.21", "Right to object"),
        ("Art.22", "Automated individual decision-making, including profiling"),
        ("Art.23", "Restrictions"),
    ]),
    ("Chapter IV - Controller and processor", [
        ("Art.24", "Responsibility of the controller"),
        ("Art.25", "Data protection by design and by default"),
        ("Art.26", "Joint controllers"),
        ("Art.27", "Representatives of controllers or processors not established in the Union"),
        ("Art.28", "Processor"),
        ("Art.29", "Processing under the authority of the controller or processor"),
        ("Art.30", "Records of processing activities"),
        ("Art.31", "Cooperation with the supervisory authority"),
        ("Art.32", "Security of processing"),
        ("Art.33", "Notification of a personal data breach to the supervisory authority"),
        ("Art.34", "Communication of a personal data breach to the data subject"),
        ("Art.35", "Data protection impact assessment"),
        ("Art.36", "Prior consultation"),
        ("Art.37", "Designation of the data protection officer"),
        ("Art.38", "Position of the data protection officer"),
        ("Art.39", "Tasks of the data protection officer"),
        ("Art.40", "Codes of conduct"),
        ("Art.41", "Monitoring of approved codes of conduct"),
        ("Art.42", "Certification"),
        ("Art.43", "Certification bodies"),
    ]),
    ("Chapter V - Transfers to third countries or international organisations", [
        ("Art.44", "General principle for transfers"),
        ("Art.45", "Transfers on the basis of an adequacy decision"),
        ("Art.46", "Transfers subject to appropriate safeguards"),
        ("Art.47", "Binding corporate rules"),
        ("Art.48", "Transfers or disclosures not authorised by Union law"),
        ("Art.49", "Derogations for specific situations"),
        ("Art.50", "International cooperation for the protection of personal data"),
    ]),
    ("Chapter VIII - Remedies, liability and penalties", [
        ("Art.77", "Right to lodge a complaint with a supervisory authority"),
        ("Art.82", "Right to compensation and liability"),
        ("Art.83", "General conditions for imposing administrative fines"),
        ("Art.84", "Penalties"),
    ]),
    ("Chapter IX - Provisions relating to specific processing situations", [
        ("Art.88", "Processing in the context of employment"),
        ("Art.89", "Safeguards and derogations: archiving, scientific or historical research and statistics"),
    ]),
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
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))
    next_cid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1

    def insert_control(rec: dict) -> None:
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])

    n = 0
    for chapter, items in CHAPTERS:
        for art, title in items:
            cid = next_cid
            next_cid += 1
            insert_control({
                "ControlID": cid, "ControlGUID": str(uuid.uuid4()),
                "ControlName": f"{art} {title}"[:300],
                "ISO": art, "CIS": art,
                "ControlDescription": f"EU GDPR (Regulation (EU) 2016/679) - {chapter}",
                "Guidance": "EU GDPR obligation - controllers and processors of personal data.",
                "VocabularyID": vid,
                "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
            })
            n += 1

    con.commit()
    con.close()
    print(f"[gdpr] VocabularyID={vid}: {n} GDPR articles imported as controls.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
