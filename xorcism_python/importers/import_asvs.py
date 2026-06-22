"""import_asvs.py — import the OWASP Application Security Verification Standard (ASVS) into XORCISM.CONTROL.

ASVS is the de-facto application-security requirements / verification standard: requirements
`V<chapter>.<section>.<item>` across 14 chapters, each tagged with the verification Level it applies
to (L1 opportunistic / L2 standard / L3 advanced).

Two modes:
  * --download : fetch the official OWASP ASVS 4.0.3 flat CSV (stdlib urllib) and import every
                 requirement (~286) with its level.
  * (no flag)  : seed the 14 chapters + a representative set of key requirements (embedded), so the
                 framework is present immediately; run --download later for the full set.

Writes CONTROL rows (VocabularyID = the ASVS vocab; ControlName="V#.#.# text", ControlDescription=
"OWASP ASVS — <chapter> · L<n>", Statement=requirement text, CIS=shortcode) keyed idempotently by
VocabularyID, and registers the VOCABULARY entry "OWASP ASVS 4.0.3". Raw SQL; DB = XORCISM_DB_DIR.

    python xorcism_python/importers/import_asvs.py            # embedded seed
    python xorcism_python/importers/import_asvs.py --download # full official set
"""
from __future__ import annotations

import argparse
import csv
import io
import os
import sqlite3
import urllib.request
import uuid
from datetime import datetime, timezone

VOCAB = "OWASP ASVS 4.0.3"
CSV_URL = (
    "https://raw.githubusercontent.com/OWASP/ASVS/v4.0.3/4.0/docs_en/"
    "OWASP%20Application%20Security%20Verification%20Standard%204.0.3-en.csv"
)

# 14 ASVS 4.0.3 chapters (V# -> name)
CHAPTERS = {
    "V1": "Architecture, Design and Threat Modeling", "V2": "Authentication", "V3": "Session Management",
    "V4": "Access Control", "V5": "Validation, Sanitization and Encoding", "V6": "Stored Cryptography",
    "V7": "Error Handling and Logging", "V8": "Data Protection", "V9": "Communication",
    "V10": "Malicious Code", "V11": "Business Logic", "V12": "Files and Resources",
    "V13": "API and Web Service", "V14": "Configuration",
}

# Representative requirements (shortcode, level, text). The full ~286 come from --download.
SEED = [
    ("V1.1.1", "L2", "Use of a secure software development lifecycle that addresses security in all stages of development."),
    ("V1.2.2", "L2", "All communications between application components are authenticated, and use the least necessary privileges."),
    ("V1.4.1", "L2", "Trusted enforcement points such as access control gateways enforce access controls; access control is not enforced client-side."),
    ("V1.14.6", "L2", "Application avoids unsupported, insecure, or deprecated client-side technologies."),
    ("V2.1.1", "L1", "User passwords are at least 12 characters in length (after multiple spaces are combined)."),
    ("V2.1.7", "L1", "Passwords are checked against a set of breached/compromised passwords."),
    ("V2.2.1", "L1", "Anti-automation controls are effective against credential stuffing, brute force and account lockout attacks."),
    ("V2.5.4", "L1", "No default accounts (e.g. root, admin) are present with default/guessable passwords."),
    ("V2.8.1", "L1", "Time-based one-time passwords (TOTP) are verified securely with a valid time window."),
    ("V3.2.1", "L1", "A new session token is generated on user authentication."),
    ("V3.3.1", "L1", "Logout and session expiry invalidate the session token server-side."),
    ("V3.4.1", "L1", "Cookie-based session tokens use the 'Secure' attribute."),
    ("V4.1.1", "L1", "The application enforces access control rules on a trusted service layer, not relying on client-side checks."),
    ("V4.1.3", "L1", "The principle of least privilege exists — users access only the features/data for which they are authorized."),
    ("V4.2.1", "L1", "Sensitive data and APIs are protected against Insecure Direct Object Reference (IDOR) attacks."),
    ("V4.3.1", "L1", "Administrative interfaces use appropriate multi-factor authentication."),
    ("V5.1.1", "L1", "The application has defenses against HTTP parameter pollution attacks."),
    ("V5.2.1", "L1", "All untrusted HTML input is sanitized with an appropriate library or framework feature."),
    ("V5.3.3", "L1", "Context-aware output encoding/escaping protects against reflected, stored and DOM-based XSS."),
    ("V5.3.4", "L1", "Data selection or database queries use parameterized queries, ORMs or escaping to prevent SQL injection."),
    ("V6.2.1", "L1", "All cryptographic modules fail securely, and errors are handled so as not to enable padding oracle attacks."),
    ("V6.2.3", "L2", "Only approved, strong cryptographic algorithms, modes and libraries are used."),
    ("V6.4.1", "L2", "A secrets-management solution (e.g. key vault) securely creates, stores and controls access to secrets."),
    ("V7.1.1", "L2", "The application does not log credentials or payment details; session tokens are only stored in logs in irreversible/hashed form."),
    ("V7.3.1", "L2", "Security-relevant events (logins, failures, access-control failures) are logged with sufficient detail."),
    ("V7.4.1", "L2", "A generic error message is shown when an unexpected or security-sensitive error occurs."),
    ("V8.2.1", "L1", "The application sets anti-caching headers so that sensitive data is not cached in browsers."),
    ("V8.3.1", "L1", "Sensitive data is sent to the server in the HTTP message body or headers — never in URL query strings."),
    ("V9.1.1", "L1", "TLS is used for all client connectivity and does not fall back to insecure or unencrypted protocols."),
    ("V9.1.2", "L1", "Only the latest, recommended TLS versions and strong cipher suites are enabled."),
    ("V9.2.1", "L2", "Connections to and from the server use trusted TLS certificates."),
    ("V10.2.1", "L2", "The application source code does not contain backdoors, malicious code, time/logic bombs or undocumented features."),
    ("V10.3.2", "L2", "The application employs integrity protections such as code signing or subresource integrity for third-party code."),
    ("V11.1.1", "L1", "The application processes business-logic flows for the same user in sequential step order, without skipping steps."),
    ("V11.1.4", "L1", "The application has anti-automation controls to protect against excessive calls such as mass data exfiltration."),
    ("V12.1.1", "L1", "The application will not accept large files that could fill storage or cause a denial of service."),
    ("V12.3.1", "L1", "User-submitted filename metadata is validated/ignored to prevent path traversal and local/remote file inclusion."),
    ("V13.1.1", "L1", "All application components use the same encodings and parsers to avoid parsing attacks across the API and web tier."),
    ("V13.2.1", "L1", "Enabled RESTful HTTP methods are a valid choice for the user/action; CSRF protection covers state-changing methods."),
    ("V13.2.3", "L1", "RESTful web services that use cookies are protected from Cross-Site Request Forgery."),
    ("V14.1.1", "L2", "The application build and deployment pipeline is automated, repeatable and secured."),
    ("V14.2.1", "L1", "All application components, libraries and dependencies are up to date and free of known vulnerabilities."),
    ("V14.4.1", "L1", "Every HTTP response sets a Content-Type header with a safe character set (e.g. UTF-8)."),
    ("V14.5.1", "L1", "The application server only accepts the HTTP methods in use by the application/API, logging/alerting on others."),
    # ── Level 3 (advanced / high-assurance) ──
    ("V1.1.4", "L3", "Documentation and justification of all the application's trust boundaries, components, and significant data flows."),
    ("V1.6.4", "L3", "The architecture treats client-side secrets (symmetric keys, passwords, API tokens) as insecure and never uses them to protect or access sensitive data."),
    ("V1.11.3", "L3", "All high-value business-logic flows, including authentication and session management, are thread-safe and resistant to time-of-check/time-of-use race conditions."),
    ("V2.2.4", "L3", "Impersonation resistance against phishing is verified — e.g. multi-factor authentication, cryptographic devices with intent (FIDO/WebAuthn), or client-side certificates."),
    ("V2.8.4", "L3", "Time-based OTP seeds and keys are stored securely and protected against disclosure (e.g. in a hardware security module)."),
    ("V3.6.1", "L3", "Re-authentication is required before high-value transactions or changes to sensitive account settings."),
    ("V4.3.3", "L3", "The application uses additional authorization (step-up or adaptive authentication) for lower-value systems, and segregation of duties for high-value applications."),
    ("V6.2.7", "L3", "Symmetric cryptographic operations are implemented to resist side-channel (timing) attacks."),
    ("V7.2.2", "L3", "All authentication decisions are logged, without storing sensitive session tokens or passwords."),
    ("V8.1.6", "L3", "Backups are stored securely to prevent sensitive data from being stolen or corrupted."),
    ("V9.2.4", "L3", "Proper certificate revocation, such as OCSP stapling, is enabled and configured."),
    ("V10.2.4", "L3", "The application source code and third-party libraries do not contain unauthorized phone-home or data-collection capabilities."),
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


def _truthy(cell: str) -> bool:
    return cell.strip() not in ("", "-", "x", "X", "0", "false", "no")


def _from_csv() -> list:
    """Download + parse the official ASVS 4.0.3 CSV → list of (shortcode, level, text)."""
    req = urllib.request.Request(CSV_URL, headers={"User-Agent": "XORCISM-ASVS-importer/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode("utf-8-sig")
    out = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        rid = (row.get("req_id") or row.get("Item") or "").strip()
        desc = (row.get("req_description") or row.get("Description") or "").strip()
        if not rid or not desc:
            continue
        short = rid if rid.upper().startswith("V") else "V" + rid
        l1 = _truthy(str(row.get("level1") or row.get("L1") or ""))
        l2 = _truthy(str(row.get("level2") or row.get("L2") or ""))
        level = "L1" if l1 else "L2" if l2 else "L3"
        out.append((short, level, desc[:4000]))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Import OWASP ASVS into XORCISM.CONTROL")
    ap.add_argument("--download", action="store_true", help="fetch the full official ASVS 4.0.3 CSV")
    a = ap.parse_args()

    reqs = []
    if a.download:
        try:
            reqs = _from_csv()
            print(f"[asvs] downloaded {len(reqs)} requirements from OWASP ASVS 4.0.3")
        except Exception as exc:  # noqa: BLE001
            print(f"[asvs] download failed ({exc}); using embedded seed")
    if not reqs:
        reqs = list(SEED)
        print(f"[asvs] using embedded seed: {len(reqs)} requirements across 14 chapters")

    con = sqlite3.connect(_db_path()); con.execute("PRAGMA busy_timeout=15000"); cur = con.cursor()
    now = datetime.now(timezone.utc).isoformat()
    vid = _ensure_vocab(cur, VOCAB)
    ccols = {r[1] for r in cur.execute("PRAGMA table_info(CONTROL)").fetchall()}
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))  # idempotent
    next_id = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1

    n = 0
    for short, level, text in reqs:
        ch = short.split(".")[0]  # V2
        rec = {
            "ControlID": next_id, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{short} {text}"[:300],
            "ControlDescription": f"OWASP ASVS — {CHAPTERS.get(ch, ch)} · {level}",
            "VocabularyID": vid, "CIS": short, "Statement": text or None,
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
        next_id += 1; n += 1
    con.commit(); con.close()
    src = "official CSV" if a.download and n > len(SEED) else "embedded seed"
    print(f"[asvs] VocabularyID={vid}: {n} ASVS requirements across {len({r[0].split('.')[0] for r in reqs})} chapters ({src}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
