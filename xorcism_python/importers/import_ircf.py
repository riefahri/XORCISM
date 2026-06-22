"""import_ircf.py — import the ITMG Insider Risk Capability Framework (IRCF) into XORCISM.CONTROL.

The IRCF (Insider Threat Management Group, https://itmg.co/insider-risk-capability-framework/) is a
public reference model for building, managing and maturing an insider risk program. v1.0 organizes
insider-risk capability into **10 components** assessed against a **5-level maturity model**.

This importer registers the VOCABULARY "ITMG IRCF v1.0" and writes one CONTROL row per component
(idempotent: DELETE+reinsert by VocabularyID), so the framework is browsable in the explorer,
control-management and compliance — like the OWASP ASVS / SCF / CSA CCM imports. The 5 maturity
levels are documented on each component's Statement so an assessment can score each 1-5.

    python xorcism_python/importers/import_ircf.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "ITMG IRCF v1.0"

# 5-level maturity model (Nascent -> Mature).
MATURITY = [
    ("1", "Nascent", "Informal and reactive"),
    ("2", "Limited", "Basic activity with partial governance"),
    ("3", "Functional", "Formally defined and repeatable"),
    ("4", "Operational", "Actively managed and risk-informed"),
    ("5", "Mature", "Integrated, measurable, and continuously improved"),
]
_MATURITY_TXT = "Maturity model (score 1-5): " + "; ".join(f"{n}={name} ({d})" for n, name, d in MATURITY) + "."

# The 10 IRCF v1.0 components (code, name, purpose).
COMPONENTS = [
    ("IRCF-01", "Governance", "Authority, ownership and executive oversight for the insider risk program — charter, sponsorship, policy, roles and funding."),
    ("IRCF-02", "Monitoring", "Observation and correlation of insider risk signals across user activity, endpoints, data movement, network and physical sources."),
    ("IRCF-03", "Analysis", "Converting fragmented information into actionable insider-risk insight — triage, scoring, behavioral analytics and prioritization of indicators."),
    ("IRCF-04", "Investigation", "Consistent, lawful and repeatable investigation processes — case management, evidence handling, escalation and outcomes."),
    ("IRCF-05", "Identity and Access Management", "The right access at the right time — provisioning/deprovisioning, least privilege, privileged access, and entitlement review for insider-risk reduction."),
    ("IRCF-06", "Data Protection", "Identifying, classifying and protecting sensitive data — data discovery/classification, DLP, encryption and controls over exfiltration paths."),
    ("IRCF-07", "Personnel Assurance", "Managing workforce risk factors across the employee lifecycle — screening, onboarding, role changes, stressors, and offboarding."),
    ("IRCF-08", "Oversight and Compliance", "Ensuring responsible, lawful and privacy-respecting program operation — legal/HR/privacy alignment, auditability and proportionality."),
    ("IRCF-09", "Training", "Awareness and role-based education to recognize, deter and report insider risk across the workforce and program staff."),
    ("IRCF-10", "Risk Management and Reporting", "Prioritizing insider-risk exposure and tracking program progress — risk register, metrics/KPIs, and reporting to leadership."),
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
    con = sqlite3.connect(_db_path())
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    now = datetime.now(timezone.utc).isoformat()
    vid = _ensure_vocab(cur, VOCAB)
    ccols = {r[1] for r in cur.execute("PRAGMA table_info(CONTROL)").fetchall()}
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))  # idempotent
    next_id = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1

    n = 0
    for i, (code, name, purpose) in enumerate(COMPONENTS, 1):
        rec = {
            "ControlID": next_id, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{code} {name}"[:300],
            "ControlDescription": f"ITMG IRCF v1.0 — Insider Risk Capability ({i}/10)",
            "VocabularyID": vid, "CIS": code,
            "Statement": f"{purpose}\n\n{_MATURITY_TXT}"[:4000],
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
        next_id += 1
        n += 1
    con.commit()
    con.close()
    print(f"[ircf] VocabularyID={vid}: {n} IRCF components imported (5-level maturity model embedded).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
