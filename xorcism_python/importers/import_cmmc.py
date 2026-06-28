"""import_cmmc.py - import the DoD CMMC 2.0 model into XORCISM as a control framework.

CMMC 2.0 (Cybersecurity Maturity Model Certification, 32 CFR Part 170) is the U.S. Department of
Defense certification for contractors in the Defense Industrial Base. It has three levels:

  * Level 1 (Foundational)  - 17 practices from FAR 52.204-21, protecting Federal Contract
                              Information (FCI). Annual self-assessment.
  * Level 2 (Advanced)      - 110 practices = the 110 security requirements of NIST SP 800-171
                              Rev 2, protecting Controlled Unclassified Information (CUI).
                              Self-assessment or C3PAO third-party assessment.
  * Level 3 (Expert)        - Level 2 + a selected subset of NIST SP 800-172 enhanced
                              requirements; government-led (DIBCAC) assessment.

This importer loads the assessable practice set (Level 1 + Level 2 = the 110 NIST SP 800-171 Rev 2
requirements, with the 17 Level-1 practices flagged) into:

  XORCISM.CONTROL         -> VOCABULARY "CMMC 2.0"; one CONTROL per practice. CIS = the CMMC practice
                             id (e.g. "AC.L2-3.1.1", or "AC.L1-3.1.1" for the 17 Level-1 practices),
                             Statement = the requirement text, ControlDescription = domain / levels.
  XORCISM.CONTROLMAPPING  -> a 1:1 crosswalk of every practice to its NIST SP 800-171 Rev 2 id
                             (Framework "NIST SP 800-171 Rev 2"), so CMMC is interoperable.

NIST SP 800-171 and the DoD CMMC model are U.S. Government works (public domain). The catalogue is
embedded in this script (authoritative; no fragile network fetch) and a committed JSON snapshot is
written to importers/data/cmmc.json for transparency. Idempotent (delete-then-insert by VocabularyID
/ mapping Source). DB dir = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_cmmc.py
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "CMMC 2.0"
SOURCE = "https://dodcio.defense.gov/CMMC/"
MAP_FRAMEWORK = "NIST SP 800-171 Rev 2"
MAP_SOURCE = "CMMC 2.0 crosswalk"
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cmmc.json")

# Family prefix (3.1 .. 3.14) -> (CMMC domain abbreviation, domain name).
DOMAINS = {
    "3.1": ("AC", "Access Control"), "3.2": ("AT", "Awareness and Training"),
    "3.3": ("AU", "Audit and Accountability"), "3.4": ("CM", "Configuration Management"),
    "3.5": ("IA", "Identification and Authentication"), "3.6": ("IR", "Incident Response"),
    "3.7": ("MA", "Maintenance"), "3.8": ("MP", "Media Protection"),
    "3.9": ("PS", "Personnel Security"), "3.10": ("PE", "Physical Protection"),
    "3.11": ("RA", "Risk Assessment"), "3.12": ("CA", "Security Assessment"),
    "3.13": ("SC", "System and Communications Protection"), "3.14": ("SI", "System and Information Integrity"),
}

# CMMC Level 1 practice set (17), by NIST SP 800-171 id (the FAR 52.204-21 basic safeguards).
L1 = {"3.1.1", "3.1.2", "3.1.20", "3.1.22", "3.5.1", "3.5.2", "3.8.3",
      "3.10.1", "3.10.3", "3.10.4", "3.10.5", "3.13.1", "3.13.5",
      "3.14.1", "3.14.2", "3.14.4", "3.14.5"}

# The 110 NIST SP 800-171 Rev 2 security requirements (= CMMC 2.0 Level 2 practices). Public domain.
REQS: dict[str, str] = {
    "3.1.1": "Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems).",
    "3.1.2": "Limit system access to the types of transactions and functions that authorized users are permitted to execute.",
    "3.1.3": "Control the flow of CUI in accordance with approved authorizations.",
    "3.1.4": "Separate the duties of individuals to reduce the risk of malevolent activity without collusion.",
    "3.1.5": "Employ the principle of least privilege, including for specific security functions and privileged accounts.",
    "3.1.6": "Use non-privileged accounts or roles when accessing nonsecurity functions.",
    "3.1.7": "Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs.",
    "3.1.8": "Limit unsuccessful logon attempts.",
    "3.1.9": "Provide privacy and security notices consistent with applicable CUI rules.",
    "3.1.10": "Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity.",
    "3.1.11": "Terminate (automatically) a user session after a defined condition.",
    "3.1.12": "Monitor and control remote access sessions.",
    "3.1.13": "Employ cryptographic mechanisms to protect the confidentiality of remote access sessions.",
    "3.1.14": "Route remote access via managed access control points.",
    "3.1.15": "Authorize remote execution of privileged commands and remote access to security-relevant information.",
    "3.1.16": "Authorize wireless access prior to allowing such connections.",
    "3.1.17": "Protect wireless access using authentication and encryption.",
    "3.1.18": "Control connection of mobile devices.",
    "3.1.19": "Encrypt CUI on mobile devices and mobile computing platforms.",
    "3.1.20": "Verify and control/limit connections to and use of external systems.",
    "3.1.21": "Limit use of portable storage devices on external systems.",
    "3.1.22": "Control CUI posted or processed on publicly accessible systems.",
    "3.2.1": "Ensure that managers, system administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems.",
    "3.2.2": "Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities.",
    "3.2.3": "Provide security awareness training on recognizing and reporting potential indicators of insider threat.",
    "3.3.1": "Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.",
    "3.3.2": "Ensure that the actions of individual system users can be uniquely traced to those users, so they can be held accountable for their actions.",
    "3.3.3": "Review and update logged events.",
    "3.3.4": "Alert in the event of an audit logging process failure.",
    "3.3.5": "Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity.",
    "3.3.6": "Provide audit record reduction and report generation to support on-demand analysis and reporting.",
    "3.3.7": "Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records.",
    "3.3.8": "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.",
    "3.3.9": "Limit management of audit logging functionality to a subset of privileged users.",
    "3.4.1": "Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.",
    "3.4.2": "Establish and enforce security configuration settings for information technology products employed in organizational systems.",
    "3.4.3": "Track, review, approve or disapprove, and log changes to organizational systems.",
    "3.4.4": "Analyze the security impact of changes prior to implementation.",
    "3.4.5": "Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems.",
    "3.4.6": "Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities.",
    "3.4.7": "Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services.",
    "3.4.8": "Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software.",
    "3.4.9": "Control and monitor user-installed software.",
    "3.5.1": "Identify system users, processes acting on behalf of users, and devices.",
    "3.5.2": "Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems.",
    "3.5.3": "Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.",
    "3.5.4": "Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts.",
    "3.5.5": "Prevent reuse of identifiers for a defined period.",
    "3.5.6": "Disable identifiers after a defined period of inactivity.",
    "3.5.7": "Enforce a minimum password complexity and change of characters when new passwords are created.",
    "3.5.8": "Prohibit password reuse for a specified number of generations.",
    "3.5.9": "Allow temporary password use for system logons with an immediate change to a permanent password.",
    "3.5.10": "Store and transmit only cryptographically-protected passwords.",
    "3.5.11": "Obscure feedback of authentication information.",
    "3.6.1": "Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.",
    "3.6.2": "Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.",
    "3.6.3": "Test the organizational incident response capability.",
    "3.7.1": "Perform maintenance on organizational systems.",
    "3.7.2": "Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance.",
    "3.7.3": "Ensure equipment removed for off-site maintenance is sanitized of any CUI.",
    "3.7.4": "Check media containing diagnostic and test programs for malicious code before the media are used in organizational systems.",
    "3.7.5": "Require multifactor authentication to establish nonlocal maintenance sessions via external network connections and terminate such connections when nonlocal maintenance is complete.",
    "3.7.6": "Supervise the maintenance activities of maintenance personnel without required access authorization.",
    "3.8.1": "Protect (i.e., physically control and securely store) system media containing CUI, both paper and digital.",
    "3.8.2": "Limit access to CUI on system media to authorized users.",
    "3.8.3": "Sanitize or destroy system media containing CUI before disposal or release for reuse.",
    "3.8.4": "Mark media with necessary CUI markings and distribution limitations.",
    "3.8.5": "Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas.",
    "3.8.6": "Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport unless otherwise protected by alternative physical safeguards.",
    "3.8.7": "Control the use of removable media on system components.",
    "3.8.8": "Prohibit the use of portable storage devices when such devices have no identifiable owner.",
    "3.8.9": "Protect the confidentiality of backup CUI at storage locations.",
    "3.9.1": "Screen individuals prior to authorizing access to organizational systems containing CUI.",
    "3.9.2": "Ensure that organizational systems containing CUI are protected during and after personnel actions such as terminations and transfers.",
    "3.10.1": "Limit physical access to organizational systems, equipment, and the respective operating environments to authorized individuals.",
    "3.10.2": "Protect and monitor the physical facility and support infrastructure for organizational systems.",
    "3.10.3": "Escort visitors and monitor visitor activity.",
    "3.10.4": "Maintain audit logs of physical access.",
    "3.10.5": "Control and manage physical access devices.",
    "3.10.6": "Enforce safeguarding measures for CUI at alternate work sites.",
    "3.11.1": "Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI.",
    "3.11.2": "Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified.",
    "3.11.3": "Remediate vulnerabilities in accordance with risk assessments.",
    "3.12.1": "Periodically assess the security controls in organizational systems to determine if the controls are effective in their application.",
    "3.12.2": "Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational systems.",
    "3.12.3": "Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls.",
    "3.12.4": "Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems.",
    "3.13.1": "Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems.",
    "3.13.2": "Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems.",
    "3.13.3": "Separate user functionality from system management functionality.",
    "3.13.4": "Prevent unauthorized and unintended information transfer via shared system resources.",
    "3.13.5": "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.",
    "3.13.6": "Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).",
    "3.13.7": "Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks (i.e., split tunneling).",
    "3.13.8": "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards.",
    "3.13.9": "Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity.",
    "3.13.10": "Establish and manage cryptographic keys for cryptography employed in organizational systems.",
    "3.13.11": "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.",
    "3.13.12": "Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device.",
    "3.13.13": "Control and monitor the use of mobile code.",
    "3.13.14": "Control and monitor the use of Voice over Internet Protocol (VoIP) technologies.",
    "3.13.15": "Protect the authenticity of communications sessions.",
    "3.13.16": "Protect the confidentiality of CUI at rest.",
    "3.14.1": "Identify, report, and correct system flaws in a timely manner.",
    "3.14.2": "Provide protection from malicious code at designated locations within organizational systems.",
    "3.14.3": "Monitor system security alerts and advisories and take action in response.",
    "3.14.4": "Update malicious code protection mechanisms when new releases are available.",
    "3.14.5": "Perform periodic scans of organizational systems and real-time scans of files from external sources as files are downloaded, opened, or executed.",
    "3.14.6": "Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.",
    "3.14.7": "Identify unauthorized use of organizational systems.",
}


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


def _practices() -> list[dict]:
    """Build the ordered CMMC practice list from the embedded 800-171 Rev 2 catalogue."""
    def sort_key(nid: str):
        return tuple(int(x) for x in nid.split("."))
    out = []
    for nid in sorted(REQS, key=sort_key):
        fam = nid.rsplit(".", 1)[0]
        abbr, dname = DOMAINS[fam]
        is_l1 = nid in L1
        level = "1" if is_l1 else "2"
        out.append({
            "id": f"{abbr}.L{level}-{nid}", "nist": nid, "domain": abbr, "domainName": dname,
            "levels": "L1, L2" if is_l1 else "L2", "statement": REQS[nid],
        })
    return out


def main() -> int:
    practices = _practices()
    # committed snapshot (generated artifact; the embedded REQS are the source of truth)
    os.makedirs(os.path.dirname(DATA), exist_ok=True)
    json.dump({"meta": {"title": "CMMC 2.0", "publisher": "U.S. DoD", "source": SOURCE,
                        "basis": MAP_FRAMEWORK, "level1": len(L1), "level2": len(REQS)},
               "practices": practices}, open(DATA, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    now = datetime.now(timezone.utc).isoformat()
    xo = sqlite3.connect(_db("XORCISM")); xo.execute("PRAGMA busy_timeout=20000"); cur = xo.cursor()
    vid = _ensure_vocab(cur, VOCAB, "2.0", SOURCE,
                        "DoD CMMC 2.0 (Cybersecurity Maturity Model Certification, 32 CFR Part 170). Level 1 "
                        "(17 FAR 52.204-21 practices, FCI) + Level 2 (110 practices = NIST SP 800-171 Rev 2, CUI) "
                        "are imported here as one practice catalogue, with the 17 Level-1 practices flagged; "
                        "Level 3 = Level 2 + selected NIST SP 800-172 enhanced requirements (government-assessed).")
    ccols = _cols(cur, "CONTROL")
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))
    nid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    cis2id: dict[str, int] = {}
    for p in practices:
        _ins(cur, "CONTROL", {
            "ControlID": nid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{p['id']}: {p['statement']}"[:300],
            "ControlDescription": f"CMMC 2.0 / {p['domain']} {p['domainName']} / Levels: {p['levels']} / NIST SP 800-171 Rev 2 {p['nist']}"[:600],
            "VocabularyID": vid, "CIS": p["id"], "Statement": p["statement"][:2000],
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }, ccols)
        cis2id[p["id"]] = nid
        nid += 1

    # CONTROLMAPPING crosswalk: every CMMC practice -> its NIST SP 800-171 Rev 2 id (1:1).
    n_map = 0
    if cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLMAPPING'").fetchone():
        mcols = _cols(cur, "CONTROLMAPPING")
        cur.execute("DELETE FROM CONTROLMAPPING WHERE Source=?", (MAP_SOURCE,))
        mid = (cur.execute("SELECT COALESCE(MAX(MappingID),0) FROM CONTROLMAPPING").fetchone()[0] or 0) + 1
        for p in practices:
            _ins(cur, "CONTROLMAPPING", {
                "MappingID": mid, "MappingGUID": str(uuid.uuid4()), "ControlID": cis2id[p["id"]],
                "Framework": MAP_FRAMEWORK, "ExternalID": p["nist"], "ExternalName": p["domainName"],
                "Relationship": "equivalent", "Source": MAP_SOURCE, "CreatedDate": now,
            }, mcols)
            mid += 1; n_map += 1
    xo.commit(); xo.close()
    l1 = sum(1 for p in practices if p["levels"].startswith("L1"))
    print(f"[cmmc] VocabularyID={vid}: {len(practices)} CMMC 2.0 practices imported under '{VOCAB}' "
          f"({l1} Level-1, {len(practices)} Level-2; {len(DOMAINS)} domains; {n_map} crosswalk rows to {MAP_FRAMEWORK}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
