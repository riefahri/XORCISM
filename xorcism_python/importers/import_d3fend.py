"""
import_d3fend.py — Import the MITRE D3FEND matrix (defensive countermeasures) into
XTHREAT.db, and mirror every technique as a row in XORCISM.CONTROL.
Jerome Athias - XORCISM

Official MITRE sources:
  1. JSON-LD ontology  https://d3fend.mitre.org/ontologies/d3fend.json
     -> technique + tactic tree (--file for a local file).
  2. Inferred mappings  https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json
     -> D3FEND <-> ATT&CK links (via "digital artifacts", ~45 MB, SPARQL-JSON format).
     --mappings-file for a local file, --no-mappings to skip importing them.

Tables populated:
  XTHREAT.db (also created by the server in ensureThreatTables):
  • D3FENDTACTIC      (Model/Harden/Detect/Isolate/Deceive/Evict/Restore, matrix order)
  • D3FENDTECHNIQUE   (D3FENDID, Name, Definition, TacticShortName, ParentD3FENDID, IsSubtechnique, URL)
  • D3FENDATTACKMAP   (D3FENDID <-> AttackID of the countered ATT&CK techniques, Relationship)
  XORCISM.db:
  • CONTROL           (one row per D3FEND technique; D3FEND column = D3-XXX id, like the ISO/NIST/CIS
                       framework-reference columns). Idempotent by the D3FEND column. --no-controls to skip.

The parser reads the JSON-LD @graph, identifies techniques (property "d3fend-id" = D3-XXX),
derives the **tactic** from the `d3f:enables` relation (direct property or OWL restriction under
subClassOf), inherited from the parent technique for sub-techniques, and the **parent technique**
via subClassOf. The ATT&CK links come from the inferred-mappings file (the @graph does not contain
them: they are only attack-id stubs). Idempotent (ON CONFLICT / MAX(id)+1).

Usage:
    python import_d3fend.py                                  # download everything and import
    python import_d3fend.py --file d3fend.json               # local ontology
    python import_d3fend.py --file d3fend.json --no-mappings # without ATT&CK links
    python import_d3fend.py --mappings-file d3fend-full-mappings.json
    python import_d3fend.py --no-controls                    # skip the XORCISM.CONTROL mirror
"""
import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from uuid import uuid4

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

DB_PATH = os.path.join(config.DB_DIR, "XTHREAT.db")
XORCISM_DB_PATH = os.path.join(config.DB_DIR, "XORCISM.db")
DEFAULT_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"
DEFAULT_MAPPINGS_URL = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json"

# D3FEND tactics in the official matrix order.
TACTICS = ["Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"]
TACTIC_SET = {t.lower() for t in TACTICS}

SCHEMA = """
CREATE TABLE IF NOT EXISTS D3FENDTACTIC (
  D3FENDTacticID INTEGER PRIMARY KEY, ShortName TEXT UNIQUE, Name TEXT,
  Definition TEXT, MatrixOrder INTEGER, URL TEXT);
CREATE TABLE IF NOT EXISTS D3FENDTECHNIQUE (
  D3FENDTechniqueID INTEGER PRIMARY KEY, D3FENDID TEXT UNIQUE, Name TEXT,
  Definition TEXT, TacticShortName TEXT, ParentD3FENDID TEXT,
  IsSubtechnique INTEGER DEFAULT 0, URL TEXT);
CREATE TABLE IF NOT EXISTS D3FENDATTACKMAP (
  D3FENDAttackMapID INTEGER PRIMARY KEY, D3FENDID TEXT, AttackID TEXT, Relationship TEXT,
  UNIQUE(D3FENDID, AttackID, Relationship));
CREATE INDEX IF NOT EXISTS ix_d3tech_tactic ON D3FENDTECHNIQUE(TacticShortName);
CREATE INDEX IF NOT EXISTS ix_d3map_d3 ON D3FENDATTACKMAP(D3FENDID);
CREATE INDEX IF NOT EXISTS ix_d3map_attack ON D3FENDATTACKMAP(AttackID);
"""


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportD3FEND] {msg}", flush=True)


def localname(key: str) -> str:
    """Local name of a JSON-LD key/URI (handles prefix:, #frag and /path)."""
    return key.split("#")[-1].split("/")[-1].split(":")[-1]


def getp(node: dict, name: str):
    """Value of a property by its local name (ignores the JSON-LD prefix)."""
    for k, v in node.items():
        if not k.startswith("@") and localname(k) == name:
            return v
    return None


def scalar(v):
    if v is None:
        return None
    if isinstance(v, list):
        v = v[0] if v else None
    if isinstance(v, dict):
        return v.get("@value") or v.get("@id")
    return v


def idrefs(v):
    """List of @id values referenced by a value (object/string/list)."""
    out = []
    if v is None:
        return out
    for x in (v if isinstance(v, list) else [v]):
        if isinstance(x, dict) and "@id" in x:
            out.append(x["@id"])
        elif isinstance(x, str) and x:
            out.append(x)
    return out


def load_graph(args) -> list:
    if args.file:
        log(f"Reading file {args.file}")
        with open(args.file, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    else:
        log(f"Downloading {DEFAULT_URL}")
        r = requests.get(DEFAULT_URL, timeout=120, headers={"User-Agent": "XORCISM-D3FEND-importer"})
        r.raise_for_status()
        data = r.json()
    graph = data.get("@graph") if isinstance(data, dict) else data
    if not isinstance(graph, list):
        raise SystemExit("Unexpected format: @graph missing.")
    return graph


def load_mappings(args) -> list:
    """SPARQL-JSON bindings of the inferred D3FEND<->ATT&CK mappings (can be large)."""
    if args.no_mappings:
        return []
    if args.mappings_file:
        log(f"Reading mappings {args.mappings_file}")
        with open(args.mappings_file, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    else:
        log(f"Downloading ATT&CK mappings {DEFAULT_MAPPINGS_URL} (~45 MB)")
        r = requests.get(DEFAULT_MAPPINGS_URL, timeout=300, headers={"User-Agent": "XORCISM-D3FEND-importer"})
        r.raise_for_status()
        data = r.json()
    if isinstance(data, dict):
        return data.get("results", {}).get("bindings", []) or []
    return data if isinstance(data, list) else []


def import_controls(techs) -> int:
    """Mirror each D3FEND technique as a row in XORCISM.CONTROL.

    Idempotent by a dedicated D3FEND column (added by ALTER if missing), mirroring the
    existing ISO/NIST/CIS framework-reference columns. CONTROL.ControlID is not an
    auto-increment primary key, so new ids are MAX(ControlID)+1. Returns the number of
    newly inserted controls.
    """
    if not os.path.exists(XORCISM_DB_PATH):
        log(f"XORCISM.db not found ({XORCISM_DB_PATH}) — skipping CONTROL import.")
        return 0
    conn = sqlite3.connect(XORCISM_DB_PATH)
    conn.execute("PRAGMA busy_timeout = 5000")
    cur = conn.cursor()
    if not cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROL'").fetchone():
        log("CONTROL table absent in XORCISM.db — skipping CONTROL import.")
        conn.close()
        return 0
    cols = {r[1] for r in cur.execute("PRAGMA table_info(CONTROL)").fetchall()}
    if "D3FEND" not in cols:
        cur.execute("ALTER TABLE CONTROL ADD COLUMN D3FEND TEXT")
        log("Added column CONTROL.D3FEND")
    inserted = 0
    for (d3id, name, definition, _tactic, _parent, _is_sub, _url) in techs:
        desc = definition or name
        row = cur.execute("SELECT ControlID FROM CONTROL WHERE D3FEND=?", (d3id,)).fetchone()
        if row:
            cur.execute(
                "UPDATE CONTROL SET ControlName=?, ControlDescription=? WHERE ControlID=?",
                (name, desc, row[0]),
            )
        else:
            cid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0]) + 1
            cur.execute(
                """INSERT INTO CONTROL
                     (ControlID, ControlGUID, ControlName, ControlDescription,
                      CreatedDate, ValidFromDate, D3FEND)
                   VALUES (?,?,?,?,?,?,?)""",
                (cid, str(uuid4()), name, desc, now(), now(), d3id),
            )
            inserted += 1
    conn.commit()
    total = cur.execute("SELECT COUNT(*) FROM CONTROL WHERE D3FEND IS NOT NULL AND D3FEND<>''").fetchone()[0]
    conn.close()
    log(f"CONTROL: {inserted} new, {total} D3FEND controls total in XORCISM.db.")
    return inserted


def main() -> None:
    ap = argparse.ArgumentParser(description="Import MITRE D3FEND into XTHREAT.db (+ XORCISM.CONTROL)")
    ap.add_argument("--file", help="Local D3FEND ontology (JSON-LD) instead of downloading")
    ap.add_argument("--mappings-file", help="Local inferred-mappings file (SPARQL-JSON) instead of downloading")
    ap.add_argument("--no-mappings", action="store_true", help="Do not import the D3FEND<->ATT&CK links")
    ap.add_argument("--no-controls", action="store_true", help="Do not mirror techniques into XORCISM.CONTROL")
    args = ap.parse_args()

    graph = load_graph(args)
    nodes = {n["@id"]: n for n in graph if isinstance(n, dict) and "@id" in n}
    log(f"{len(nodes)} nodes in the ontology")

    # Index: @id -> d3fend-id (techniques) ; resolvable URI localname -> @id.
    dfid_of = {}
    for nid, node in nodes.items():
        d = scalar(getp(node, "d3fend-id"))
        if isinstance(d, str) and d.upper().startswith("D3-"):
            dfid_of[nid] = d

    def restriction(x):
        """Return the owl:Restriction node of a subClassOf entry (inline or blank node)."""
        if not isinstance(x, dict):
            return None
        rid = x.get("@id")
        if isinstance(rid, str) and rid.startswith("_:"):
            return nodes.get(rid, x)
        return x if getp(x, "onProperty") is not None else None

    # Tactic of a technique via `d3f:enables` -> tactic (direct property OR OWL restriction).
    enables_of = {}  # technique @id -> tactic name (lowercase)
    for nid, node in nodes.items():
        if nid not in dfid_of:
            continue
        for ref in idrefs(getp(node, "enables")):
            if localname(ref).lower() in TACTIC_SET:
                enables_of[nid] = localname(ref).lower()
                break
        if nid in enables_of:
            continue
        sc = getp(node, "subClassOf") or []
        for x in (sc if isinstance(sc, list) else [sc]):
            rn = restriction(x)
            if not rn:
                continue
            onp = idrefs(getp(rn, "onProperty"))
            svf = idrefs(getp(rn, "someValuesFrom"))
            if onp and localname(onp[0]) == "enables" and svf and localname(svf[0]).lower() in TACTIC_SET:
                enables_of[nid] = localname(svf[0]).lower()
                break

    def parent_tech(nid):
        """@id of the parent technique (subClassOf entry carrying a d3fend-id), else None."""
        for r in idrefs(getp(nodes[nid], "subClassOf")):
            if r in dfid_of and r != nid:
                return r
        return None

    def resolve(nid):
        """(tacticShort, parentD3FENDID): tactic via enables (inherited from parent), parent via subClassOf."""
        parent_nid = parent_tech(nid)
        parent = dfid_of.get(parent_nid)
        tactic = None
        cur, seen = nid, set()
        while cur and cur not in seen:
            seen.add(cur)
            if cur in enables_of:
                tactic = enables_of[cur]
                break
            cur = parent_tech(cur)
        tac = next((t for t in TACTICS if t.lower() == tactic), None) if tactic else None
        return tac, parent

    techs = []        # (d3id, name, definition, tactic, parent, is_sub, url)
    for nid, d3id in dfid_of.items():
        node = nodes[nid]
        name = scalar(getp(node, "label")) or d3id
        definition = scalar(getp(node, "definition"))
        tactic, parent = resolve(nid)
        # D3FEND technique pages are keyed by the d3f: class name (e.g.
        # /technique/d3f:NetworkTrafficAnalysis/), NOT by the D3-XXX id
        # (/technique/D3-NTA/ returns 404).
        url = f"https://d3fend.mitre.org/technique/d3f:{localname(nid)}/"
        techs.append((d3id, name, definition, tactic, parent, 1 if parent else 0, url))

    # ATT&CK links from the inferred mappings (def_tech URI -> D3FENDID via localname, off_tech_id = AttackID).
    maps = set()      # (d3id, attack_id, relationship)
    for b in load_mappings(args):
        dt = (b.get("def_tech") or {}).get("value")
        off = (b.get("off_tech_id") or {}).get("value")
        rel = (b.get("def_artifact_rel_label") or {}).get("value") or "related"
        if not dt or not off:
            continue
        d3id = dfid_of.get("d3f:" + localname(dt))
        if d3id:
            maps.add((d3id, off, rel))
    maps = sorted(maps)

    with_tactic = sum(1 for t in techs if t[3])
    log(f"{len(techs)} techniques ({with_tactic} with a tactic), {len(maps)} ATT&CK links")

    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    cur = conn.cursor()

    # Tactics (matrix order) — Definition/URL updated when present in the ontology.
    tac_meta = {}
    for nid, node in nodes.items():
        ln = localname(nid).lower()
        if ln in TACTIC_SET:
            tac_meta[ln] = scalar(getp(node, "definition"))
    for i, t in enumerate(TACTICS, start=1):
        cur.execute(
            """INSERT INTO D3FENDTACTIC (ShortName, Name, Definition, MatrixOrder, URL)
               VALUES (?,?,?,?,?)
               ON CONFLICT(ShortName) DO UPDATE SET Name=excluded.Name,
                 Definition=COALESCE(excluded.Definition, D3FENDTACTIC.Definition),
                 MatrixOrder=excluded.MatrixOrder""",
            (t, t, tac_meta.get(t.lower()), i, "https://d3fend.mitre.org/"),
        )

    for (d3id, name, definition, tactic, parent, is_sub, url) in techs:
        cur.execute(
            """INSERT INTO D3FENDTECHNIQUE
                 (D3FENDID, Name, Definition, TacticShortName, ParentD3FENDID, IsSubtechnique, URL)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(D3FENDID) DO UPDATE SET Name=excluded.Name,
                 Definition=excluded.Definition, TacticShortName=excluded.TacticShortName,
                 ParentD3FENDID=excluded.ParentD3FENDID, IsSubtechnique=excluded.IsSubtechnique,
                 URL=excluded.URL""",
            (d3id, name, definition, tactic, parent, is_sub, url),
        )

    for (d3id, aid, rel) in maps:
        cur.execute(
            "INSERT OR IGNORE INTO D3FENDATTACKMAP (D3FENDID, AttackID, Relationship) VALUES (?,?,?)",
            (d3id, aid, rel),
        )

    conn.commit()
    tcount = cur.execute("SELECT COUNT(*) FROM D3FENDTECHNIQUE").fetchone()[0]
    mcount = cur.execute("SELECT COUNT(*) FROM D3FENDATTACKMAP").fetchone()[0]
    conn.close()
    log(f"XTHREAT done ({now()}) — {tcount} techniques, {mcount} ATT&CK mappings.")

    # Mirror techniques into XORCISM.CONTROL (unless disabled).
    if not args.no_controls:
        import_controls(techs)

    log("Import D3FEND finished.")


if __name__ == "__main__":
    main()
