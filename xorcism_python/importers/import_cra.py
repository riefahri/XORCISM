"""import_cra.py — import the EU Cyber Resilience Act into XORCISM.CONTROL.

The Cyber Resilience Act (Regulation (EU) 2024/2847) sets horizontal cybersecurity requirements for
products with digital elements (PDE) placed on the EU market. Its core is Annex I:
  * Part I  — essential cybersecurity requirements (security properties of the product), points (a)-(m)
  * Part II — vulnerability-handling requirements, points (1)-(8)
plus key manufacturer obligations / reporting timelines (Art. 13/14) and conformity artifacts
(Annex IV/V/VII). This vocabulary backs the CRA conformity cockpit (/cra-compliance).

Copyright-safe: only official references/titles + ORIGINAL one-line summaries are stored (no normative
EU text). Writes CONTROL rows (VocabularyID = the CRA vocab; ControlName="<ref> <title>", CIS=<ref>,
Statement=summary, ControlDescription="EU CRA — <part>") idempotently; registers VOCABULARY. Raw SQL.

    python xorcism_python/importers/import_cra.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "EU Cyber Resilience Act (Regulation (EU) 2024/2847)"

# (ref, part, title, original summary). Refs follow Annex I structure + key articles.
ITEMS = [
    # ── Annex I, Part I — essential cybersecurity requirements (product properties) ──
    ("Annex I.1.(2)(a)", "Annex I Part I — product security", "No known exploitable vulnerabilities",
     "The product is placed on the market without any known exploitable vulnerabilities."),
    ("Annex I.1.(2)(b)", "Annex I Part I — product security", "Secure by default configuration",
     "The product ships with a secure-by-default configuration, with the ability to reset to a secure state."),
    ("Annex I.1.(2)(c)", "Annex I Part I — product security", "Security updates",
     "Vulnerabilities can be addressed through security updates, including (where applicable) automatic updates that can be opted out of."),
    ("Annex I.1.(2)(d)", "Annex I Part I — product security", "Protection from unauthorised access",
     "Access is protected by appropriate control mechanisms such as authentication, identity and access management."),
    ("Annex I.1.(2)(e)", "Annex I Part I — product security", "Confidentiality of data",
     "The confidentiality of stored, transmitted or processed data is protected, e.g. by encryption at rest and in transit."),
    ("Annex I.1.(2)(f)", "Annex I Part I — product security", "Integrity of data",
     "The integrity of stored/transmitted/processed data, commands, programs and configuration is protected against unauthorised manipulation."),
    ("Annex I.1.(2)(g)", "Annex I Part I — product security", "Data minimisation",
     "Only data that is adequate, relevant and limited to what is necessary for the intended purpose is processed."),
    ("Annex I.1.(2)(h)", "Annex I Part I — product security", "Availability of essential functions",
     "The availability of essential and basic functions is protected, including resilience against and mitigation of denial-of-service attacks."),
    ("Annex I.1.(2)(i)", "Annex I Part I — product security", "Minimise impact on other devices",
     "The product minimises its own negative impact on the availability of services provided by other devices or networks."),
    ("Annex I.1.(2)(j)", "Annex I Part I — product security", "Limit attack surfaces",
     "Attack surfaces, including external interfaces, are limited by design."),
    ("Annex I.1.(2)(k)", "Annex I Part I — product security", "Reduce impact of incidents",
     "The impact of an incident is reduced using appropriate exploitation-mitigation mechanisms and techniques."),
    ("Annex I.1.(2)(l)", "Annex I Part I — product security", "Security-relevant logging & monitoring",
     "Security-relevant information is recorded and monitored, including logging of access to or modification of data/services with opt-out."),
    ("Annex I.1.(2)(m)", "Annex I Part I — product security", "Secure data & configuration removal",
     "Users can securely and easily remove on a permanent basis all data and settings, and transfer them to another product."),
    # ── Annex I, Part II — vulnerability-handling requirements ──
    ("Annex I.2.(1)", "Annex I Part II — vulnerability handling", "Identify & document components (SBOM)",
     "Identify and document vulnerabilities and components, including by drawing up a software bill of materials in a machine-readable format."),
    ("Annex I.2.(2)", "Annex I Part II — vulnerability handling", "Remediate vulnerabilities without delay",
     "Address and remediate vulnerabilities without delay, including by providing security updates."),
    ("Annex I.2.(3)", "Annex I Part II — vulnerability handling", "Regular security testing & review",
     "Apply effective and regular tests and reviews of the security of the product."),
    ("Annex I.2.(4)", "Annex I Part II — vulnerability handling", "Publicly disclose fixed vulnerabilities",
     "Once a security update is available, share and publicly disclose information about fixed vulnerabilities (description, severity, remediation)."),
    ("Annex I.2.(5)", "Annex I Part II — vulnerability handling", "Coordinated vulnerability disclosure policy",
     "Put in place and enforce a coordinated vulnerability disclosure policy."),
    ("Annex I.2.(6)", "Annex I Part II — vulnerability handling", "Facilitate vulnerability reporting",
     "Provide a contact address for reporting vulnerabilities and facilitate the sharing of information about potential vulnerabilities."),
    ("Annex I.2.(7)", "Annex I Part II — vulnerability handling", "Secure update distribution",
     "Provide mechanisms to securely distribute updates to ensure vulnerabilities are fixed or mitigated in a timely manner."),
    ("Annex I.2.(8)", "Annex I Part II — vulnerability handling", "Disseminate free security patches with advisory",
     "Ensure security patches/updates are disseminated without delay and (for security fixes) free of charge, with advisory messages to users."),
    # ── Key manufacturer obligations & reporting ──
    ("Art. 13", "Obligations of manufacturers", "Manufacturer obligations & support period",
     "Manufacturers ensure CRA conformity, perform a cybersecurity risk assessment, provide security updates over a support period (at least 5 years unless shorter is justified) and supply an SBOM."),
    ("Art. 14(1)", "Reporting obligations", "Actively exploited vulnerability — 24h early warning",
     "Notify the CSIRT and ENISA of an actively exploited vulnerability without undue delay and in any event within 24 hours of becoming aware (early warning)."),
    ("Art. 14(2)", "Reporting obligations", "Vulnerability notification — 72h",
     "Submit a vulnerability notification within 72 hours of becoming aware, with corrective/mitigating measures."),
    ("Art. 14(4)", "Reporting obligations", "Final report — 14 days",
     "Submit a final report no later than 14 days after a corrective or mitigating measure is available."),
    ("Art. 14(3)", "Reporting obligations", "Severe incident — 24h / 72h",
     "Notify any severe incident having an impact on the security of the product: early warning within 24 hours and incident notification within 72 hours."),
    # ── Conformity ──
    ("Annex III/IV", "Product classification", "Important & critical products",
     "Important products with digital elements (Annex III, Class I/II) and critical products (Annex IV) are subject to stricter conformity-assessment routes."),
    ("Annex V", "Conformity", "EU declaration of conformity",
     "Draw up the EU declaration of conformity stating that the essential requirements have been fulfilled, and affix the CE marking."),
    ("Annex VII", "Conformity", "Technical documentation",
     "Compile and keep up to date the technical documentation demonstrating conformity with the essential requirements (incl. risk assessment and SBOM)."),
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
    for ref, part, title, summary in ITEMS:
        rec = {
            "ControlID": next_id, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{ref} {title}"[:300],
            "ControlDescription": f"EU CRA — {part}",
            "VocabularyID": vid, "CIS": ref, "Statement": summary,
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
        next_id += 1; n += 1
    con.commit(); con.close()
    print(f"[cra] VocabularyID={vid}: {n} CRA controls imported (Annex I Part I+II + Art.13/14 + conformity).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
