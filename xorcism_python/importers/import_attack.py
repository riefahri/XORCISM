"""
import_attack.py — Imports the MITRE ATT&CK matrix (Enterprise + Mobile + ICS)
into XTHREAT.db.  Jerome Athias - XORCISM

Source: official STIX 2.1 bundles (github.com/mitre-attack/attack-stix-data).
Downloaded by default; --file for a local bundle.

HYBRID mapping:
  • New ATTACK* tables (authoritative storage):
      ATTACKTACTIC, ATTACKTECHNIQUE, ATTACKTECHNIQUETACTIC, ATTACKMITIGATION,
      ATTACKGROUP, ATTACKSOFTWARE, ATTACKDATASOURCE, ATTACKRELATIONSHIP
  • Reuse of the existing XTHREAT tables (integration into the threat model):
      Techniques   → THREATACTORTTP    (TTPTitle / TTPDescription)
      Groups       → THREATACTOR       (ThreatActorName / Description / GUID)
      Tactics      → THREATACTORTACTIC (TacticID link = ATTACKTACTIC.AttackTacticID)
    The created identifier is linked in the corresponding ATTACK* table.

Idempotent: get-or-create by StixID (ATTACK* tables) and by name (reused).

Usage:
    python import_attack.py                       # downloads the 3 domains
    python import_attack.py --domain enterprise   # a single domain
    python import_attack.py --file ent.json --domain enterprise
    python import_attack.py --no-reuse            # does NOT populate the existing tables
"""
import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

DB_PATH = os.path.join(config.DB_DIR, "XTHREAT.db")

BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
DOMAIN_URLS = {
    "enterprise": f"{BASE}/enterprise-attack/enterprise-attack.json",
    "mobile":     f"{BASE}/mobile-attack/mobile-attack.json",
    "ics":        f"{BASE}/ics-attack/ics-attack.json",
    # MITRE ATLAS ("ATT&CK for AI") — STIX 2.1 bundle, same schema (source mitre-atlas).
    "atlas":      "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/stix-atlas.json",
}
ATTACK_SOURCES = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack", "mitre-atlas"}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportATTACK] {msg}", flush=True)


def attack_ref(obj):
    """(attack_id, url) from external_references (source mitre-*)."""
    for r in obj.get("external_references", []):
        if r.get("source_name") in ATTACK_SOURCES:
            return r.get("external_id"), r.get("url")
    return None, None


def joincsv(v):
    return ",".join(v) if isinstance(v, list) else (v or None)


# NB: the ATT&CK bundles share StixIDs across domains → identity (Domain, StixID).
SCHEMA = """
CREATE TABLE IF NOT EXISTS ATTACKTACTIC (
  AttackTacticID INTEGER PRIMARY KEY,
  StixID TEXT, AttackID TEXT, Name TEXT, ShortName TEXT, Description TEXT,
  Domain TEXT, URL TEXT, Deprecated INTEGER DEFAULT 0, MatrixOrder INTEGER,
  ThreatActorTacticID INTEGER, CreatedDate TEXT, UNIQUE(Domain, StixID));
CREATE TABLE IF NOT EXISTS ATTACKTECHNIQUE (
  AttackTechniqueID INTEGER PRIMARY KEY,
  StixID TEXT, AttackID TEXT, Name TEXT, Description TEXT, Domain TEXT,
  IsSubtechnique INTEGER DEFAULT 0, ParentAttackID TEXT,
  Platforms TEXT, DataSources TEXT, Detection TEXT, URL TEXT, Deprecated INTEGER DEFAULT 0,
  ThreatActorTTPID INTEGER, CreatedDate TEXT, UNIQUE(Domain, StixID));
CREATE TABLE IF NOT EXISTS ATTACKTECHNIQUETACTIC (
  AttackTechniqueTacticID INTEGER PRIMARY KEY,
  AttackTechniqueID INTEGER, AttackTacticID INTEGER, TacticShortName TEXT, Domain TEXT, CreatedDate TEXT,
  UNIQUE(AttackTechniqueID, AttackTacticID));
CREATE TABLE IF NOT EXISTS ATTACKMITIGATION (
  AttackMitigationID INTEGER PRIMARY KEY,
  StixID TEXT, AttackID TEXT, Name TEXT, Description TEXT, Domain TEXT, URL TEXT,
  Deprecated INTEGER DEFAULT 0, CreatedDate TEXT, UNIQUE(Domain, StixID));
CREATE TABLE IF NOT EXISTS ATTACKGROUP (
  AttackGroupID INTEGER PRIMARY KEY,
  StixID TEXT, AttackID TEXT, Name TEXT, Description TEXT, Aliases TEXT, Domain TEXT, URL TEXT,
  Deprecated INTEGER DEFAULT 0, ThreatActorID INTEGER, CreatedDate TEXT, UNIQUE(Domain, StixID));
CREATE TABLE IF NOT EXISTS ATTACKSOFTWARE (
  AttackSoftwareID INTEGER PRIMARY KEY,
  StixID TEXT, AttackID TEXT, Name TEXT, SoftwareType TEXT, Description TEXT, Aliases TEXT,
  Platforms TEXT, Domain TEXT, URL TEXT, Deprecated INTEGER DEFAULT 0, CreatedDate TEXT, UNIQUE(Domain, StixID));
CREATE TABLE IF NOT EXISTS ATTACKDATASOURCE (
  AttackDataSourceID INTEGER PRIMARY KEY,
  StixID TEXT, AttackID TEXT, Name TEXT, Description TEXT, Platforms TEXT, Domain TEXT, URL TEXT,
  Deprecated INTEGER DEFAULT 0, CreatedDate TEXT, UNIQUE(Domain, StixID));
CREATE TABLE IF NOT EXISTS ATTACKRELATIONSHIP (
  AttackRelationshipID INTEGER PRIMARY KEY,
  StixID TEXT, RelationshipType TEXT, SourceStixID TEXT, TargetStixID TEXT,
  SourceAttackID TEXT, TargetAttackID TEXT, Description TEXT, Domain TEXT, CreatedDate TEXT,
  UNIQUE(Domain, StixID));
CREATE INDEX IF NOT EXISTS ix_attacktech_aid ON ATTACKTECHNIQUE(AttackID);
CREATE INDEX IF NOT EXISTS ix_attacktactic_aid ON ATTACKTACTIC(AttackID);
CREATE INDEX IF NOT EXISTS ix_attackrel_type ON ATTACKRELATIONSHIP(RelationshipType);
CREATE INDEX IF NOT EXISTS ix_attackrel_src ON ATTACKRELATIONSHIP(SourceStixID);
"""


def next_id(cur, table, col):
    return cur.execute(f"SELECT COALESCE(MAX({col}),0)+1 FROM {table}").fetchone()[0]


# ── Reuse of the existing tables (without an auto-incremented PK → MAX+1) ──
def reuse_ttp(cur, title, desc):
    row = cur.execute("SELECT ThreatActorTTPID FROM THREATACTORTTP WHERE TTPTitle=? LIMIT 1", (title,)).fetchone()
    if row:
        return row[0]
    nid = next_id(cur, "THREATACTORTTP", "ThreatActorTTPID")
    cur.execute("INSERT INTO THREATACTORTTP (ThreatActorTTPID, TTPTitle, TTPDescription, Information_Source, CreatedDate) VALUES (?,?,?,?,?)",
                (nid, title, desc, "MITRE ATT&CK", now()))
    return nid


def reuse_actor(cur, name, desc, guid):
    row = cur.execute("SELECT ThreatActorID FROM THREATACTOR WHERE ThreatActorName=? LIMIT 1", (name,)).fetchone()
    if row:
        return row[0]
    nid = next_id(cur, "THREATACTOR", "ThreatActorID")
    cur.execute("INSERT INTO THREATACTOR (ThreatActorID, ThreatActorGUID, ThreatActorName, ThreatActorDescription, ActorExternal, CreatedDate) VALUES (?,?,?,?,?,?)",
                (nid, guid, name, desc, 1, now()))
    return nid


def reuse_tactic_link(cur, attack_tactic_id):
    row = cur.execute("SELECT ThreatActorTacticID FROM THREATACTORTACTIC WHERE TacticID=? LIMIT 1", (attack_tactic_id,)).fetchone()
    if row:
        return row[0]
    nid = next_id(cur, "THREATACTORTACTIC", "ThreatActorTacticID")
    cur.execute("INSERT INTO THREATACTORTACTIC (ThreatActorTacticID, TacticID) VALUES (?,?)", (nid, attack_tactic_id))
    return nid


def import_objects(cur, domain, objects, reuse):
    stix_to_attack = {}
    for o in objects:
        if o.get("type") in ("attack-pattern", "x-mitre-tactic", "course-of-action",
                              "intrusion-set", "malware", "tool", "x-mitre-data-source"):
            aid, _ = attack_ref(o)
            if aid:
                stix_to_attack[o["id"]] = aid

    counts = {k: 0 for k in ("tactic", "technique", "mitigation", "group", "software", "datasource", "relationship", "tech_tactic")}
    tactic_by_short = {}

    # Official order of the matrix columns: from x-mitre-matrix.tactic_refs
    # (version-proof: no hard-coded list).
    matrix_order = {}
    for o in objects:
        if o.get("type") == "x-mitre-matrix" and not o.get("x_mitre_deprecated") and not o.get("revoked"):
            for i, ref in enumerate(o.get("tactic_refs", [])):
                matrix_order[ref] = i
            break

    # 1) Tactics (needed to link the techniques by phase)
    for o in objects:
        if o.get("type") != "x-mitre-tactic":
            continue
        aid, url = attack_ref(o)
        dep = 1 if (o.get("x_mitre_deprecated") or o.get("revoked")) else 0
        mord = matrix_order.get(o["id"])
        cur.execute("""INSERT INTO ATTACKTACTIC (StixID, AttackID, Name, ShortName, Description, Domain, URL, Deprecated, MatrixOrder, CreatedDate)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(Domain, StixID) DO UPDATE SET AttackID=excluded.AttackID, Name=excluded.Name, ShortName=excluded.ShortName,
              Description=excluded.Description, Domain=excluded.Domain, URL=excluded.URL, Deprecated=excluded.Deprecated, MatrixOrder=excluded.MatrixOrder""",
            (o["id"], aid, o.get("name"), o.get("x_mitre_shortname"), o.get("description"), domain, url, dep, mord, now()))
        tid = cur.execute("SELECT AttackTacticID FROM ATTACKTACTIC WHERE Domain=? AND StixID=?", (domain, o["id"])).fetchone()[0]
        if o.get("x_mitre_shortname"):
            tactic_by_short[o["x_mitre_shortname"]] = tid
        if reuse:
            link = reuse_tactic_link(cur, tid)
            cur.execute("UPDATE ATTACKTACTIC SET ThreatActorTacticID=? WHERE AttackTacticID=?", (link, tid))
        counts["tactic"] += 1

    # 2) Techniques, mitigations, groups, software, data sources
    for o in objects:
        typ = o.get("type")
        aid, url = attack_ref(o)
        dep = 1 if (o.get("x_mitre_deprecated") or o.get("revoked")) else 0
        if typ == "attack-pattern":
            is_sub = 1 if o.get("x_mitre_is_subtechnique") else 0
            parent = aid.split(".")[0] if (is_sub and aid and "." in aid) else None
            ttp_id = reuse_ttp(cur, o.get("name") or aid, o.get("description")) if reuse else None
            cur.execute("""INSERT INTO ATTACKTECHNIQUE (StixID, AttackID, Name, Description, Domain, IsSubtechnique, ParentAttackID,
                  Platforms, DataSources, Detection, URL, Deprecated, ThreatActorTTPID, CreatedDate)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(Domain, StixID) DO UPDATE SET AttackID=excluded.AttackID, Name=excluded.Name, Description=excluded.Description,
                  Domain=excluded.Domain, IsSubtechnique=excluded.IsSubtechnique, ParentAttackID=excluded.ParentAttackID,
                  Platforms=excluded.Platforms, DataSources=excluded.DataSources, Detection=excluded.Detection, URL=excluded.URL,
                  Deprecated=excluded.Deprecated""",
                (o["id"], aid, o.get("name"), o.get("description"), domain, is_sub, parent,
                 joincsv(o.get("x_mitre_platforms")), joincsv(o.get("x_mitre_data_sources")),
                 o.get("x_mitre_detection"), url, dep, ttp_id, now()))
            tech_id = cur.execute("SELECT AttackTechniqueID FROM ATTACKTECHNIQUE WHERE Domain=? AND StixID=?", (domain, o["id"])).fetchone()[0]
            if ttp_id is not None:
                cur.execute("UPDATE ATTACKTECHNIQUE SET ThreatActorTTPID=? WHERE AttackTechniqueID=?", (ttp_id, tech_id))
            counts["technique"] += 1
            for kc in o.get("kill_chain_phases", []):
                if str(kc.get("kill_chain_name", "")).startswith("mitre"):
                    short = kc.get("phase_name")
                    tac = tactic_by_short.get(short)
                    cur.execute("INSERT OR IGNORE INTO ATTACKTECHNIQUETACTIC (AttackTechniqueID, AttackTacticID, TacticShortName, Domain, CreatedDate) VALUES (?,?,?,?,?)",
                                (tech_id, tac, short, domain, now()))
                    counts["tech_tactic"] += 1
        elif typ == "course-of-action":
            cur.execute("""INSERT INTO ATTACKMITIGATION (StixID, AttackID, Name, Description, Domain, URL, Deprecated, CreatedDate)
                VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(Domain, StixID) DO UPDATE SET AttackID=excluded.AttackID, Name=excluded.Name, Description=excluded.Description,
                  Domain=excluded.Domain, URL=excluded.URL, Deprecated=excluded.Deprecated""",
                (o["id"], aid, o.get("name"), o.get("description"), domain, url, dep, now()))
            counts["mitigation"] += 1
        elif typ == "intrusion-set":
            actor_id = reuse_actor(cur, o.get("name"), o.get("description"), o["id"]) if reuse else None
            cur.execute("""INSERT INTO ATTACKGROUP (StixID, AttackID, Name, Description, Aliases, Domain, URL, Deprecated, ThreatActorID, CreatedDate)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(Domain, StixID) DO UPDATE SET AttackID=excluded.AttackID, Name=excluded.Name, Description=excluded.Description,
                  Aliases=excluded.Aliases, Domain=excluded.Domain, URL=excluded.URL, Deprecated=excluded.Deprecated""",
                (o["id"], aid, o.get("name"), o.get("description"), joincsv(o.get("aliases")), domain, url, dep, actor_id, now()))
            if actor_id is not None:
                cur.execute("UPDATE ATTACKGROUP SET ThreatActorID=? WHERE Domain=? AND StixID=?", (actor_id, domain, o["id"]))
            counts["group"] += 1
        elif typ in ("malware", "tool"):
            cur.execute("""INSERT INTO ATTACKSOFTWARE (StixID, AttackID, Name, SoftwareType, Description, Aliases, Platforms, Domain, URL, Deprecated, CreatedDate)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(Domain, StixID) DO UPDATE SET AttackID=excluded.AttackID, Name=excluded.Name, SoftwareType=excluded.SoftwareType,
                  Description=excluded.Description, Aliases=excluded.Aliases, Platforms=excluded.Platforms, Domain=excluded.Domain,
                  URL=excluded.URL, Deprecated=excluded.Deprecated""",
                (o["id"], aid, o.get("name"), typ, o.get("description"),
                 joincsv(o.get("x_mitre_aliases")), joincsv(o.get("x_mitre_platforms")), domain, url, dep, now()))
            counts["software"] += 1
        elif typ == "x-mitre-data-source":
            cur.execute("""INSERT INTO ATTACKDATASOURCE (StixID, AttackID, Name, Description, Platforms, Domain, URL, Deprecated, CreatedDate)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(Domain, StixID) DO UPDATE SET AttackID=excluded.AttackID, Name=excluded.Name, Description=excluded.Description,
                  Platforms=excluded.Platforms, Domain=excluded.Domain, URL=excluded.URL, Deprecated=excluded.Deprecated""",
                (o["id"], aid, o.get("name"), o.get("description"), joincsv(o.get("x_mitre_platforms")), domain, url, dep, now()))
            counts["datasource"] += 1

    # 3) Relations (uses / mitigates / subtechnique-of / detects / revoked-by)
    for o in objects:
        if o.get("type") != "relationship":
            continue
        src, tgt = o.get("source_ref"), o.get("target_ref")
        cur.execute("""INSERT INTO ATTACKRELATIONSHIP (StixID, RelationshipType, SourceStixID, TargetStixID, SourceAttackID, TargetAttackID, Description, Domain, CreatedDate)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(Domain, StixID) DO UPDATE SET RelationshipType=excluded.RelationshipType, SourceStixID=excluded.SourceStixID,
              TargetStixID=excluded.TargetStixID, SourceAttackID=excluded.SourceAttackID, TargetAttackID=excluded.TargetAttackID,
              Description=excluded.Description, Domain=excluded.Domain""",
            (o["id"], o.get("relationship_type"), src, tgt,
             stix_to_attack.get(src), stix_to_attack.get(tgt), o.get("description"), domain, now()))
        counts["relationship"] += 1
    return counts


def load_bundle(domain, file_path):
    if file_path:
        log(f"{domain}: lecture du fichier {file_path}")
        import json
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    url = DOMAIN_URLS[domain]
    log(f"{domain}: téléchargement {url}")
    r = requests.get(url, timeout=180)
    r.raise_for_status()
    return r.json()


def main():
    ap = argparse.ArgumentParser(description="Import MITRE ATT&CK → XTHREAT.db")
    ap.add_argument("--domain", choices=list(DOMAIN_URLS), help="un seul domaine (défaut : tous)")
    ap.add_argument("--file", help="bundle STIX local (implique --domain)")
    ap.add_argument("--no-reuse", action="store_true", help="ne pas peupler THREATACTORTTP/THREATACTOR/THREATACTORTACTIC")
    args = ap.parse_args()
    if args.file and not args.domain:
        ap.error("--file nécessite --domain")
    domains = [args.domain] if args.domain else list(DOMAIN_URLS)
    reuse = not args.no_reuse

    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA foreign_keys=OFF")
    con.execute("PRAGMA busy_timeout=30000")
    cur = con.cursor()
    cur.executescript(SCHEMA)
    con.commit()

    total = {}
    for domain in domains:
        bundle = load_bundle(domain, args.file)
        objs = bundle.get("objects", [])
        log(f"{domain}: {len(objs)} objets STIX")
        counts = import_objects(cur, domain, objs, reuse)
        con.commit()
        for k, v in counts.items():
            total[k] = total.get(k, 0) + v
        log(f"{domain} importé : " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    con.close()
    log("TOTAL : " + ", ".join(f"{k}={v}" for k, v in total.items()))
    log(f"Réutilisation tables existantes : {'OUI' if reuse else 'NON'}")
    log("Terminé.")


if __name__ == "__main__":
    main()
