"""import_iso21434.py - import ISO/SAE 21434:2021 (automotive cybersecurity engineering) into XORCISM.

ISO/SAE 21434:2021 "Road vehicles - Cybersecurity engineering" is the standard for cybersecurity risk
management across the lifecycle of road-vehicle E/E systems (concept, development, production,
operations, maintenance, decommissioning), underpinning UNECE WP.29 R155 (CSMS) type approval.

This loads the standard's CLAUSE / SUB-CLAUSE STRUCTURE (clauses 5-15, the normative "requirements
and recommendations" sub-clauses) as a selectable control framework:

  XORCISM.CONTROL  -> VOCABULARY "ISO/SAE 21434:2021"; one CONTROL per sub-clause. CIS = the clause id
                     (e.g. "5.4.1"), ControlName = id + sub-clause title, ControlDescription = the
                     parent clause, Statement = a short XORCISM paraphrase of the sub-clause's intent.

Only the factual clause numbering + short headings are used; the copyrighted normative text of
ISO/SAE 21434 is NOT reproduced (the Statement is an original one-line summary). The catalogue is
embedded in this script and a committed JSON snapshot is written to importers/data/iso21434.json.
Idempotent (delete-then-insert by VocabularyID). DB dir = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_iso21434.py
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "ISO/SAE 21434:2021"
SOURCE = "https://www.iso.org/standard/70918.html"
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "iso21434.json")

# Clause -> sub-clauses (id, title, original short summary of intent — NOT the ISO normative text).
CLAUSES: list[dict] = [
    {"num": "5", "title": "Organizational cybersecurity management", "subs": [
        ("5.4.1", "Cybersecurity governance", "Establish and maintain cybersecurity governance with executive accountability, policy, rules and assigned responsibilities."),
        ("5.4.2", "Cybersecurity culture", "Build a cybersecurity culture through competence, awareness and continuous improvement of the people doing the work."),
        ("5.4.3", "Managing cybersecurity risk", "Define an organization-wide approach to managing cybersecurity risk."),
        ("5.4.4", "Information sharing", "Define rules for sharing cybersecurity information internally and with external parties."),
        ("5.4.5", "Management systems", "Operate the supporting (quality / IT) management systems that the cybersecurity processes rely on."),
        ("5.4.6", "Tool management", "Manage engineering tools so they cannot adversely affect the cybersecurity of the item or component."),
        ("5.4.7", "Information security management", "Protect work products and cybersecurity information from unauthorized access and alteration."),
        ("5.4.8", "Organizational cybersecurity audit", "Independently audit the organizational cybersecurity processes for adequacy and effectiveness."),
    ]},
    {"num": "6", "title": "Project dependent cybersecurity management", "subs": [
        ("6.4.1", "Cybersecurity responsibilities", "Assign and communicate the cybersecurity responsibilities for the project."),
        ("6.4.2", "Cybersecurity planning", "Plan the cybersecurity activities, dependencies and work products for the project."),
        ("6.4.3", "Tailoring", "Justify and document any tailoring of the cybersecurity activities."),
        ("6.4.4", "Reuse", "Assess reused components/work products for cybersecurity relevance and gaps."),
        ("6.4.5", "Component out-of-context", "Handle components developed out of context against assumed requirements."),
        ("6.4.6", "Off-the-shelf component", "Assess off-the-shelf components for cybersecurity suitability."),
        ("6.4.7", "Cybersecurity case", "Compile the cybersecurity case: the argument and evidence that the item is cybersecure."),
        ("6.4.8", "Cybersecurity assessment", "Perform an independent cybersecurity assessment and judge the item's cybersecurity."),
        ("6.4.9", "Release for post-development", "Decide and document release for post-development (production/operations)."),
    ]},
    {"num": "7", "title": "Distributed cybersecurity activities", "subs": [
        ("7.4.1", "Supplier capability", "Evaluate a supplier's capability to perform the required cybersecurity activities."),
        ("7.4.2", "Request for quotation", "State cybersecurity requirements and expectations in the request for quotation."),
        ("7.4.3", "Alignment of responsibilities", "Agree and document the division of cybersecurity responsibilities (cybersecurity interface agreement)."),
    ]},
    {"num": "8", "title": "Continual cybersecurity activities", "subs": [
        ("8.3", "Cybersecurity monitoring", "Continuously gather and triage cybersecurity information (sources, weaknesses) relevant to the item."),
        ("8.4", "Cybersecurity event assessment", "Assess cybersecurity events to determine whether they are vulnerabilities."),
        ("8.5", "Vulnerability analysis", "Analyse identified weaknesses/vulnerabilities for attack paths and impact."),
        ("8.6", "Vulnerability management", "Manage vulnerabilities to closure (remediation or risk treatment) over time."),
    ]},
    {"num": "9", "title": "Concept", "subs": [
        ("9.3", "Item definition", "Define the item, its boundary, functions, and operational environment."),
        ("9.4", "Cybersecurity goals", "Run the TARA, decide risk treatment, and set cybersecurity goals and claims for the item."),
        ("9.5", "Cybersecurity concept", "Derive cybersecurity requirements and controls that achieve the cybersecurity goals."),
    ]},
    {"num": "10", "title": "Product development", "subs": [
        ("10.4.1", "Design", "Refine cybersecurity requirements into an architectural design with cybersecurity controls."),
        ("10.4.2", "Integration and verification", "Integrate and verify that the implementation meets the cybersecurity requirements (incl. testing)."),
    ]},
    {"num": "11", "title": "Cybersecurity validation", "subs": [
        ("11.4", "Cybersecurity validation", "Validate at vehicle level that the cybersecurity goals are adequate and met before release."),
    ]},
    {"num": "12", "title": "Production", "subs": [
        ("12.4", "Production", "Apply a production control plan so cybersecurity controls are correctly implemented in manufacturing."),
    ]},
    {"num": "13", "title": "Operations and maintenance", "subs": [
        ("13.3", "Cybersecurity incident response", "Operate a cybersecurity incident response capability for fielded items."),
        ("13.4", "Updates", "Manage cybersecurity-relevant updates to items in the field."),
    ]},
    {"num": "14", "title": "End of cybersecurity support and decommissioning", "subs": [
        ("14.4.1", "End of cybersecurity support", "Plan and communicate the end of cybersecurity support for the item."),
        ("14.4.2", "Decommissioning", "Account for cybersecurity in the decommissioning of the item."),
    ]},
    {"num": "15", "title": "Threat analysis and risk assessment (TARA) methods", "subs": [
        ("15.3", "Asset identification", "Identify assets, their cybersecurity properties and damage scenarios."),
        ("15.4", "Threat scenario identification", "Identify threat scenarios that could compromise the assets' cybersecurity properties."),
        ("15.5", "Impact rating", "Rate the impact of damage scenarios (safety, financial, operational, privacy)."),
        ("15.6", "Attack path analysis", "Analyse the attack paths that realize the threat scenarios."),
        ("15.7", "Attack feasibility rating", "Rate the feasibility of the attack paths."),
        ("15.8", "Risk value determination", "Determine risk values from impact and attack feasibility."),
        ("15.9", "Risk treatment decision", "Decide the treatment for each risk (avoid, reduce, share, retain)."),
    ]},
]


def _db(n: str) -> str:
    d = os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, f"{n}.db")


def _cols(cur: sqlite3.Cursor, t: str) -> set:
    return {r[1] for r in cur.execute(f'PRAGMA table_info("{t}")').fetchall()}


def _ins(cur: sqlite3.Cursor, t: str, rec: dict, present: set) -> None:
    keys = [k for k in rec if k in present]
    cur.execute(f"INSERT INTO {t} ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])


def _ensure_vocab(cur: sqlite3.Cursor, name: str, version: str, ref: str, desc: str) -> int:
    cols = _cols(cur, "VOCABULARY")
    nc = "VocabularyName" if "VocabularyName" in cols else "Name"
    now = datetime.now(timezone.utc).isoformat()
    row = cur.execute(f"SELECT VocabularyID FROM VOCABULARY WHERE {nc}=?", (name,)).fetchone()
    if row:
        vid = int(row[0])
        for col, val in (("VocabularyVersion", version), ("VocabularyReference", ref), ("VocabularyDescription", desc)):
            if val and col in cols:
                cur.execute(f"UPDATE VOCABULARY SET {col}=? WHERE VocabularyID=?", (val, vid))
        return vid
    vid = (cur.execute("SELECT COALESCE(MAX(VocabularyID),0) FROM VOCABULARY").fetchone()[0] or 0) + 1
    _ins(cur, "VOCABULARY", {"VocabularyID": vid, "VocabularyGUID": str(uuid.uuid4()), "CreatedDate": now,
                             nc: name, "VocabularyVersion": version, "VocabularyReference": ref,
                             "VocabularyDescription": desc}, cols)
    return vid


def main() -> int:
    controls = []
    for cl in CLAUSES:
        for cid, title, summary in cl["subs"]:
            controls.append({"id": cid, "title": title, "clause": cl["num"], "clauseTitle": cl["title"], "summary": summary})
    os.makedirs(os.path.dirname(DATA), exist_ok=True)
    json.dump({"meta": {"title": "ISO/SAE 21434:2021 - Road vehicles - Cybersecurity engineering",
                        "publisher": "ISO/SAE", "version": "2021", "source": SOURCE, "controls": len(controls)},
               "controls": controls}, open(DATA, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    now = datetime.now(timezone.utc).isoformat()
    xo = sqlite3.connect(_db("XORCISM")); xo.execute("PRAGMA busy_timeout=20000"); cur = xo.cursor()
    vid = _ensure_vocab(cur, VOCAB, "2021", SOURCE,
                        "ISO/SAE 21434:2021 Road vehicles - Cybersecurity engineering: lifecycle cybersecurity risk "
                        "management for road-vehicle E/E systems (clauses 5-15: organizational & project management, "
                        "distributed & continual activities, concept, development, validation, production, operations, "
                        "end-of-support, and TARA methods). Underpins UNECE WP.29 R155 CSMS type approval.")
    ccols = _cols(cur, "CONTROL")
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))
    nid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    for c in controls:
        _ins(cur, "CONTROL", {
            "ControlID": nid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{c['id']} {c['title']}"[:300],
            "ControlDescription": f"ISO/SAE 21434:2021 / Clause {c['clause']} {c['clauseTitle']}"[:600],
            "VocabularyID": vid, "CIS": c["id"], "Statement": c["summary"][:2000],
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }, ccols)
        nid += 1
    xo.commit(); xo.close()
    clauses = len({c["clause"] for c in controls})
    print(f"[iso21434] VocabularyID={vid}: {len(controls)} sub-clauses imported under '{VOCAB}' ({clauses} clauses).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
