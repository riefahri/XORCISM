#!/usr/bin/env python3
"""
import_mitigant.py -- import the Mitigant Threat Catalog (cloud/AWS attack-technique matrix) into XTHREAT.db.

The Mitigant Threat Catalog (https://threats.mitigant.io/, derived from the AWS Threat Technique Catalog,
aws-samples.github.io/threat-technique-catalog-for-aws) is a matrix of cloud attack techniques organized by
tactic, each with a severity, an AWS service, a MITRE ATT&CK technique id, executable AWS CLI commands and the
CloudTrail events they generate. This importer loads a committed snapshot (importers/data/mitigant.json,
parsed from the catalog's techniques-data.js + matrix.js) and upserts it into:

  XTHREAT.MITIGANTTACTIC     (TacticKey UNIQUE, Name, MitreTacticID, MatrixOrder)
  XTHREAT.MITIGANTTECHNIQUE  (TechID UNIQUE, Title, Description, TacticKey, Severity, Service, MitreID,
                              Commands(JSON), CloudTrail(JSON), MatrixOrder, URL)

surfaced as the matrix view at /cloud-attacks (GET /api/mitigant/matrix). Mirrors import_a3m.py / import_saif.py.
Idempotent (upsert by TacticKey / TechID). ASCII-only output.

Usage:
    python import_mitigant.py [--json path/to/mitigant.json] [--db path/to/XTHREAT.db]

DB resolution: --db, else $XORCISM_DB_DIR/XTHREAT.db, else C:/Users/jerom/XORCISM_databases/XTHREAT.db.
"""
import argparse
import json
import os
import sqlite3
import sys

MODULE = "import_mitigant"
URL = "https://threats.mitigant.io/"
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_JSON = os.path.join(HERE, "data", "mitigant.json")
# Friendly names for technique tactics not listed in the catalog's display matrix.
EXTRA_TACTICS = {"resource-development": ("Resource Development", "TA0042")}


def log(msg):
    print("[%s] %s" % (MODULE, msg))


def resolve_db(arg_db):
    if arg_db:
        return arg_db
    env = os.environ.get("XORCISM_DB_DIR")
    if env:
        return os.path.join(env, "XTHREAT.db")
    return "C:/Users/jerom/XORCISM_databases/XTHREAT.db"


def ensure_tables(cur):
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS MITIGANTTACTIC (
          MitigantTacticID INTEGER PRIMARY KEY, TacticKey TEXT UNIQUE, Name TEXT, MitreTacticID TEXT, MatrixOrder INTEGER);
        CREATE TABLE IF NOT EXISTS MITIGANTTECHNIQUE (
          MitigantTechniqueID INTEGER PRIMARY KEY, TechID TEXT, Title TEXT, Description TEXT,
          TacticKey TEXT, Severity TEXT, Service TEXT, MitreID TEXT, Commands TEXT, CloudTrail TEXT,
          MatrixOrder INTEGER, URL TEXT);
        CREATE INDEX IF NOT EXISTS ix_mitiganttech_tactic ON MITIGANTTECHNIQUE(TacticKey);
        CREATE INDEX IF NOT EXISTS ix_mitiganttech_service ON MITIGANTTECHNIQUE(Service);
        CREATE INDEX IF NOT EXISTS ix_mitiganttech_id ON MITIGANTTECHNIQUE(TechID);
        """
    )


def main():
    ap = argparse.ArgumentParser(description="Import the Mitigant Threat Catalog into XTHREAT.MITIGANT*")
    ap.add_argument("--json", default=DEFAULT_JSON, help="Path to mitigant.json snapshot")
    ap.add_argument("--db", help="Path to XTHREAT.db (default: $XORCISM_DB_DIR/XTHREAT.db)")
    args = ap.parse_args()

    if not os.path.isfile(args.json):
        log("ERROR: snapshot not found: %s" % args.json)
        sys.exit(2)
    db_path = resolve_db(args.db)
    if not os.path.isfile(db_path):
        log("ERROR: XTHREAT.db not found: %s" % db_path)
        sys.exit(2)

    with open(args.json, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    tactics = data.get("tactics") or []
    techniques = data.get("techniques") or []
    log("snapshot: %d tactics, %d techniques" % (len(tactics), len(techniques)))

    conn = sqlite3.connect(db_path, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")  # the live server keeps XTHREAT open (WAL) — wait, don't fail
    cur = conn.cursor()
    ensure_tables(cur)

    # Tactics from the catalog matrix, plus any extra tactic referenced by a technique.
    known = {t.get("key") for t in tactics}
    rows = [(t.get("key"), t.get("name"), t.get("id"), t.get("order")) for t in tactics if t.get("key")]
    nxt = (max([t.get("order") or 0 for t in tactics]) if tactics else 0)
    for tk in sorted({str(x.get("tactic") or "") for x in techniques} - known):
        if not tk:
            continue
        nxt += 1
        name, mitre = EXTRA_TACTICS.get(tk, (tk.replace("-", " ").replace("_", " ").title(), None))
        rows.append((tk, name, mitre, nxt))

    tac_ins = tac_upd = 0
    for key, name, mitre, order in rows:
        cur.execute("SELECT MitigantTacticID FROM MITIGANTTACTIC WHERE TacticKey=?", (key,))
        if cur.fetchone():
            cur.execute("UPDATE MITIGANTTACTIC SET Name=?, MitreTacticID=?, MatrixOrder=? WHERE TacticKey=?",
                        (name, mitre, order, key))
            tac_upd += 1
        else:
            cur.execute("INSERT INTO MITIGANTTACTIC (TacticKey, Name, MitreTacticID, MatrixOrder) VALUES (?,?,?,?)",
                        (key, name, mitre, order))
            tac_ins += 1

    # Full replace: the catalog repeats technique ids across/within tactics, so there is no stable
    # unique key — clearing and reinserting all rows keeps every technique and stays idempotent.
    cur.execute("DELETE FROM MITIGANTTECHNIQUE")
    t_ins = 0
    for i, t in enumerate(techniques):
        tid = str(t.get("id") or "").strip()
        if not tid:
            continue
        cur.execute(
            "INSERT INTO MITIGANTTECHNIQUE (TechID, Title, Description, TacticKey, Severity, Service, MitreID, "
            "Commands, CloudTrail, MatrixOrder, URL) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (tid, t.get("title") or "", t.get("description") or "", t.get("tactic") or "",
             t.get("severity") or "", t.get("service") or "", t.get("mitre") or "",
             json.dumps(t.get("commands") or []), json.dumps(t.get("cloudtrail") or []), i + 1, URL))
        t_ins += 1

    conn.commit()
    n_tac = cur.execute("SELECT COUNT(*) FROM MITIGANTTACTIC").fetchone()[0]
    n_tech = cur.execute("SELECT COUNT(*) FROM MITIGANTTECHNIQUE").fetchone()[0]
    conn.close()
    log("tactics: %d inserted, %d updated (total %d)" % (tac_ins, tac_upd, n_tac))
    log("techniques: %d inserted via full replace (total %d)" % (t_ins, n_tech))
    log("done (db=%s)" % db_path)


if __name__ == "__main__":
    main()
