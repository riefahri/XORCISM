"""import_owasp_api_top10.py — import the OWASP API Security Top 10 (2023) into XORCISM.CONTROL.

The OWASP API Security Top 10 is the reference list of the most critical API risks; it is dominated by
broken authorization (API1 BOLA, API3 BOPLA, API5 BFLA). It backs the posture scoring in the API
Authorization Governance cockpit (/authz-governance), whose controls map to these IDs.

Copyright-safe: only the official short IDs + titles and ORIGINAL one-line summaries are stored (no
normative OWASP text). Writes CONTROL rows (VocabularyID = the OWASP API vocab; ControlName="API#:2023
Title", Statement=summary, CIS=shortcode) idempotently, and registers VOCABULARY "OWASP API Security
Top 10 2023". Raw SQL; DB = XORCISM_DB_DIR.

    python xorcism_python/importers/import_owasp_api_top10.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "OWASP API Security Top 10 2023"

# (shortcode, title, original concise summary). Authorization-class risks are flagged in the summary.
ITEMS = [
    ("API1:2023", "Broken Object Level Authorization (BOLA)",
     "An endpoint exposes object identifiers but fails to verify the caller may access that specific object, letting a user read or change another user's data. Authorize on resource ownership/attributes, not just the endpoint."),
    ("API2:2023", "Broken Authentication",
     "Authentication is missing or weak (guessable tokens, no rotation, weak credential/JWT validation), letting attackers assume other identities. Enforce strong, standards-based authentication at the edge."),
    ("API3:2023", "Broken Object Property Level Authorization (BOPLA)",
     "The API returns or accepts object properties the caller should not see or set (excessive data exposure + mass assignment). Authorize per property and filter input/output to the caller's rights."),
    ("API4:2023", "Unrestricted Resource Consumption",
     "Requests are served without limits on rate, payload size, or compute, enabling denial of service and runaway cost. Apply rate/quota limits and resource ceilings."),
    ("API5:2023", "Broken Function Level Authorization (BFLA)",
     "Privileged or administrative functions are reachable by regular users because role/function checks are missing or inconsistent. Deny by default and enforce role/scope checks per function."),
    ("API6:2023", "Unrestricted Access to Sensitive Business Flows",
     "A sensitive business flow (purchase, signup, comment) can be automated and abused at scale without business-risk protections. Add anti-automation proportional to the flow's risk."),
    ("API7:2023", "Server Side Request Forgery (SSRF)",
     "The API fetches a user-supplied URL without validation, letting attackers reach internal services. Validate and allowlist destinations; never follow untrusted URLs."),
    ("API8:2023", "Security Misconfiguration",
     "Missing hardening — default settings, verbose errors, open CORS, absent security headers, unpatched stacks. Apply repeatable, reviewed configuration across the API surface."),
    ("API9:2023", "Improper Inventory Management",
     "Undocumented, deprecated, or shadow API versions/hosts remain exposed and ungoverned. Maintain an accurate inventory of every API host, version and environment."),
    ("API10:2023", "Unsafe Consumption of APIs",
     "An API trusts data from third-party/upstream APIs without the same scrutiny applied to user input. Validate and sanitize data received from integrated services."),
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
    for short, title, summary in ITEMS:
        rec = {
            "ControlID": next_id, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{short} {title}"[:300],
            "ControlDescription": "OWASP API Security Top 10 2023",
            "VocabularyID": vid, "CIS": short, "Statement": summary,
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
        next_id += 1; n += 1
    con.commit(); con.close()
    print(f"[owasp-api] VocabularyID={vid}: {n} OWASP API Security Top 10 (2023) controls imported.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
