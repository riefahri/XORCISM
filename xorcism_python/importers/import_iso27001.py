"""
import_iso27001.py — Imports the Annex A controls of ISO/IEC 27001:2022
into XORCISM.CONTROL with VocabularyID = 10.

Annex A:2022 has 93 controls split into 4 themes:
  A.5 Organizational (37) · A.6 People (8) · A.7 Physical (14) · A.8 Technological (34)

Only the clause REFERENCE and the TITLE (short, factual title) are imported —
the normative ISO text is protected and is NOT reproduced.

Mapping:
  ControlName        = "<ref> <title>"   (e.g. "A.5.1 Policies for information security")
  ISO                = "<ref>"            (e.g. "A.5.1")
  ControlDescription = theme              (e.g. "Organizational controls")
  VocabularyID       = 10

Idempotent: get-or-update by (ISO == ref AND VocabularyID == 10).

Usage:
    python import_iso27001.py
"""

import os
import sys
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import event, text, Integer, BigInteger, SmallInteger
from sqlalchemy.orm import Mapper

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python.models.base import session_scope
from xorcism_python.utils import log

MODULE = "ImportISO27001"
VOCAB_ID = 10

# (reference, title) by theme — ISO/IEC 27001:2022 Annex A
ORGANIZATIONAL = [
    ("A.5.1", "Policies for information security"),
    ("A.5.2", "Information security roles and responsibilities"),
    ("A.5.3", "Segregation of duties"),
    ("A.5.4", "Management responsibilities"),
    ("A.5.5", "Contact with authorities"),
    ("A.5.6", "Contact with special interest groups"),
    ("A.5.7", "Threat intelligence"),
    ("A.5.8", "Information security in project management"),
    ("A.5.9", "Inventory of information and other associated assets"),
    ("A.5.10", "Acceptable use of information and other associated assets"),
    ("A.5.11", "Return of assets"),
    ("A.5.12", "Classification of information"),
    ("A.5.13", "Labelling of information"),
    ("A.5.14", "Information transfer"),
    ("A.5.15", "Access control"),
    ("A.5.16", "Identity management"),
    ("A.5.17", "Authentication information"),
    ("A.5.18", "Access rights"),
    ("A.5.19", "Information security in supplier relationships"),
    ("A.5.20", "Addressing information security within supplier agreements"),
    ("A.5.21", "Managing information security in the ICT supply chain"),
    ("A.5.22", "Monitoring, review and change management of supplier services"),
    ("A.5.23", "Information security for use of cloud services"),
    ("A.5.24", "Information security incident management planning and preparation"),
    ("A.5.25", "Assessment and decision on information security events"),
    ("A.5.26", "Response to information security incidents"),
    ("A.5.27", "Learning from information security incidents"),
    ("A.5.28", "Collection of evidence"),
    ("A.5.29", "Information security during disruption"),
    ("A.5.30", "ICT readiness for business continuity"),
    ("A.5.31", "Legal, statutory, regulatory and contractual requirements"),
    ("A.5.32", "Intellectual property rights"),
    ("A.5.33", "Protection of records"),
    ("A.5.34", "Privacy and protection of personal identifiable information (PII)"),
    ("A.5.35", "Independent review of information security"),
    ("A.5.36", "Compliance with policies, rules and standards for information security"),
    ("A.5.37", "Documented operating procedures"),
]
PEOPLE = [
    ("A.6.1", "Screening"),
    ("A.6.2", "Terms and conditions of employment"),
    ("A.6.3", "Information security awareness, education and training"),
    ("A.6.4", "Disciplinary process"),
    ("A.6.5", "Responsibilities after termination or change of employment"),
    ("A.6.6", "Confidentiality or non-disclosure agreements"),
    ("A.6.7", "Remote working"),
    ("A.6.8", "Information security event reporting"),
]
PHYSICAL = [
    ("A.7.1", "Physical security perimeters"),
    ("A.7.2", "Physical entry"),
    ("A.7.3", "Securing offices, rooms and facilities"),
    ("A.7.4", "Physical security monitoring"),
    ("A.7.5", "Protecting against physical and environmental threats"),
    ("A.7.6", "Working in secure areas"),
    ("A.7.7", "Clear desk and clear screen"),
    ("A.7.8", "Equipment siting and protection"),
    ("A.7.9", "Security of assets off-premises"),
    ("A.7.10", "Storage media"),
    ("A.7.11", "Supporting utilities"),
    ("A.7.12", "Cabling security"),
    ("A.7.13", "Equipment maintenance"),
    ("A.7.14", "Secure disposal or re-use of equipment"),
]
TECHNOLOGICAL = [
    ("A.8.1", "User endpoint devices"),
    ("A.8.2", "Privileged access rights"),
    ("A.8.3", "Information access restriction"),
    ("A.8.4", "Access to source code"),
    ("A.8.5", "Secure authentication"),
    ("A.8.6", "Capacity management"),
    ("A.8.7", "Protection against malware"),
    ("A.8.8", "Management of technical vulnerabilities"),
    ("A.8.9", "Configuration management"),
    ("A.8.10", "Information deletion"),
    ("A.8.11", "Data masking"),
    ("A.8.12", "Data leakage prevention"),
    ("A.8.13", "Information backup"),
    ("A.8.14", "Redundancy of information processing facilities"),
    ("A.8.15", "Logging"),
    ("A.8.16", "Monitoring activities"),
    ("A.8.17", "Clock synchronization"),
    ("A.8.18", "Use of privileged utility programs"),
    ("A.8.19", "Installation of software on operational systems"),
    ("A.8.20", "Networks security"),
    ("A.8.21", "Security of network services"),
    ("A.8.22", "Segregation of networks"),
    ("A.8.23", "Web filtering"),
    ("A.8.24", "Use of cryptography"),
    ("A.8.25", "Secure development life cycle"),
    ("A.8.26", "Application security requirements"),
    ("A.8.27", "Secure system architecture and engineering principles"),
    ("A.8.28", "Secure coding"),
    ("A.8.29", "Security testing in development and acceptance"),
    ("A.8.30", "Outsourced development"),
    ("A.8.31", "Separation of development, test and production environments"),
    ("A.8.32", "Change management"),
    ("A.8.33", "Test information"),
    ("A.8.34", "Protection of information systems during audit testing"),
]

THEMES = [
    ("Organizational controls", ORGANIZATIONAL),
    ("People controls", PEOPLE),
    ("Physical controls", PHYSICAL),
    ("Technological controls", TECHNOLOGICAL),
]


# ─── Auto-increment of integer primary keys (cf. other importers) ───────
_pk_counters: dict = {}
_INT_TYPES = (Integer, BigInteger, SmallInteger)


def _auto_pk(mapper, connection, target) -> None:
    pk_cols = mapper.primary_key
    if len(pk_cols) != 1:
        return
    col = pk_cols[0]
    if not isinstance(col.type, _INT_TYPES):
        return
    attr = mapper.get_property_by_column(col).key
    if getattr(target, attr, None) is not None:
        return
    tbl = mapper.local_table.name
    key = (str(connection.engine.url), tbl)
    db_max = connection.execute(
        text(f'SELECT COALESCE(MAX("{col.name}"), 0) FROM "{tbl}"')
    ).scalar()
    nxt = max(_pk_counters.get(key, 0), int(db_max or 0)) + 1
    _pk_counters[key] = nxt
    setattr(target, attr, nxt)


event.listen(Mapper, "before_insert", _auto_pk)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def run() -> None:
    from xorcism_python.models.xorcism import CONTROL
    created = updated = 0
    with session_scope("XORCISM") as session:
        for theme, items in THEMES:
            for ref, title in items:
                name = f"{ref} {title}"
                ctrl = session.query(CONTROL).filter_by(ISO=ref, VocabularyID=VOCAB_ID).first()
                if ctrl is None:
                    ctrl = CONTROL(CreatedDate=_now())
                    session.add(ctrl)
                    created += 1
                else:
                    updated += 1
                ctrl.ControlName = name
                ctrl.ISO = ref
                ctrl.ControlDescription = theme
                ctrl.VocabularyID = VOCAB_ID
                session.flush()
        session.commit()
    total = sum(len(i) for _, i in THEMES)
    log(MODULE, f"ISO/IEC 27001:2022 Annexe A : {total} contrôles — {created} créés, {updated} mis à jour (VocabularyID={VOCAB_ID}).")


if __name__ == "__main__":
    run()
