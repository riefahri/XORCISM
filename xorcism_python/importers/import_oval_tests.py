#!/usr/bin/env python3
"""
import_oval_tests.py -- import OVAL *test content* (objects / states / variables) into XOVAL.db.

The historical XOVAL import captured only the definition -> criteria -> test skeleton, so OVALTEST rows
carry just an id + comment (OVALTEST.BLOB is NULL, OVALOBJECT/OVALSTATE are empty). This importer parses
a full OVAL document (an <oval_definitions> file with <tests>/<objects>/<states>/<variables> -- e.g. a CIS
benchmark or a distro OVAL feed from github.com/OVAL-Community/OVAL) and, for each *_test, stores a small
self-contained bundle (the test element + its referenced object, states and variables, verbatim with the
original namespace prefixes) into OVALTEST.BLOB. The /oval-editor "view test" inspector then shows what
each criterion's test actually checks, and self-contained OVAL generation can inline the objects/states.

Idempotent: upsert by OVALTestIDPattern (existing rows get their BLOB updated; new tests are inserted).
Dependency-free (regex, namespace-tolerant by matching element local-names -- same approach as arf.ts).

Usage:
    python import_oval_tests.py --file path/to/oval.xml [--db path/to/XOVAL.db]

DB resolution: --db, else $XORCISM_DB_DIR/XOVAL.db, else ./XOVAL.db.
"""
import argparse
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone

MODULE = "import_oval_tests"


def log(msg):
    print("[%s] %s" % (MODULE, msg))


def resolve_db(arg_db):
    if arg_db:
        return arg_db
    env = os.environ.get("XORCISM_DB_DIR")
    if env:
        return os.path.join(env, "XOVAL.db")
    return os.path.join(os.getcwd(), "XOVAL.db")


# --- regex helpers (match by local-name suffix; any/no prefix) ---
def re_suffix(suffix):
    # <prefix:foo_<suffix> ...>...</...> OR self-closing <prefix:foo_<suffix> .../>
    return re.compile(
        r"<((?:[\w.\-]+:)?[\w.\-]*%s)\b([^>]*?)(?:/>|>([\s\S]*?)</(?:[\w.\-]+:)?[\w.\-]*%s\s*>)" % (suffix, suffix)
    )


def attr_of(attrs, name):
    m = re.search(r'\b%s\s*=\s*"([^"]*)"' % name, attrs or "")
    return m.group(1) if m else None


def open_attrs(el_xml):
    m = re.match(r"<[^>]*?>", el_xml or "")
    return m.group(0) if m else ""


def ns_decls(xml, skip_base=True):
    decls = re.findall(r'xmlns(?::[\w.\-]+)?="[^"]*"', xml)
    base = {"", "oval", "xsi"}
    seen = []
    for d in decls:
        if d in seen:
            continue
        if skip_base:
            pm = re.match(r"xmlns(?::([\w.\-]+))?=", d)
            pre = pm.group(1) if (pm and pm.group(1)) else ""
            if pre in base:
                continue
        seen.append(d)
    return seen


def parse_tests(xml):
    """Return a list of bundles: dict(id, comment, test_xml, object_xml, state_xmls, var_xmls)."""
    obj_by_id, st_by_id, var_by_id = {}, {}, {}
    for suffix, store in (("_object", obj_by_id), ("_state", st_by_id), ("_variable", var_by_id)):
        for m in re_suffix(suffix).finditer(xml):
            oid = attr_of(m.group(2), "id")
            if oid:
                store[oid] = m.group(0)
    bundles = []
    for tm in re_suffix("_test").finditer(xml):
        attrs, body, full = tm.group(2), (tm.group(3) or ""), tm.group(0)
        tid = attr_of(attrs, "id")
        if not tid:
            continue
        obj_ref_m = re.search(r'<(?:[\w.\-]+:)?object\b[^>]*?\bobject_ref="([^"]+)"', body)
        obj_ref = obj_ref_m.group(1) if obj_ref_m else None
        st_refs = re.findall(r'<(?:[\w.\-]+:)?state\b[^>]*?\bstate_ref="([^"]+)"', body)
        obj_xml = obj_by_id.get(obj_ref) if obj_ref else None
        st_xmls = [st_by_id[r] for r in st_refs if r in st_by_id]
        var_refs = []
        for x in [obj_xml] + st_xmls:
            if x:
                var_refs += re.findall(r'\bvar_ref="([^"]+)"', x)
        var_xmls = [var_by_id[v] for v in dict.fromkeys(var_refs) if v in var_by_id]
        bundles.append({
            "id": tid,
            "comment": attr_of(attrs, "comment"),
            "test": full,
            "object": obj_xml or "",
            "states": st_xmls,
            "variables": var_xmls,
        })
    return bundles


def bundle_xml(b, decls, schema_version):
    nd = (" " + " ".join(decls)) if decls else ""
    return (
        '<oval-test-bundle%s schema_version="%s">' % (nd, schema_version)
        + "<tests>%s</tests>" % b["test"]
        + "<objects>%s</objects>" % b["object"]
        + "<states>%s</states>" % "".join(b["states"])
        + "<variables>%s</variables>" % "".join(b["variables"])
        + "</oval-test-bundle>"
    )


def next_id(cur):
    row = cur.execute("SELECT COALESCE(MAX(OVALTestID),0)+1 FROM OVALTEST").fetchone()
    return int(row[0])


def main():
    ap = argparse.ArgumentParser(description="Import OVAL test content (objects/states) into XOVAL.OVALTEST.BLOB")
    ap.add_argument("--file", required=True, help="Path to a full OVAL <oval_definitions> XML document")
    ap.add_argument("--db", help="Path to XOVAL.db (default: $XORCISM_DB_DIR/XOVAL.db or ./XOVAL.db)")
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        log("ERROR: file not found: %s" % args.file)
        sys.exit(2)
    db_path = resolve_db(args.db)
    if not os.path.isfile(db_path):
        log("ERROR: XOVAL.db not found: %s" % db_path)
        sys.exit(2)

    with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
        xml = fh.read()

    decls = ns_decls(xml)
    sv_m = re.search(r"schema_version\s*>\s*([\d.]+)", xml)
    schema_version = sv_m.group(1) if sv_m else "5.12.3"
    bundles = parse_tests(xml)
    log("parsed %d test(s) from %s (schema %s)" % (len(bundles), os.path.basename(args.file), schema_version))
    if not bundles:
        log("nothing to import")
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cols = {r[1] for r in cur.execute("PRAGMA table_info(OVALTEST)").fetchall()}
    if not cols:
        log("ERROR: OVALTEST table not present in %s" % db_path)
        sys.exit(2)
    has_comment = "comment" in cols
    now = datetime.now(timezone.utc).isoformat()
    created = updated = skipped = 0
    for b in bundles:
        if not b["id"]:
            skipped += 1
            continue
        blob = bundle_xml(b, decls, schema_version)
        row = cur.execute("SELECT OVALTestID FROM OVALTEST WHERE OVALTestIDPattern=? LIMIT 1", (b["id"],)).fetchone()
        if row:
            if b["comment"] and has_comment:
                cur.execute("UPDATE OVALTEST SET BLOB=?, comment=COALESCE(NULLIF(comment,''),?) WHERE OVALTestID=?",
                            (blob, b["comment"], row[0]))
            else:
                cur.execute("UPDATE OVALTEST SET BLOB=? WHERE OVALTestID=?", (blob, row[0]))
            updated += 1
        else:
            tid = next_id(cur)
            # OVALTestVersion + comment are NOT NULL on the legacy table (no default).
            fields = {"OVALTestID": tid, "OVALTestIDPattern": b["id"], "BLOB": blob}
            if "OVALTestVersion" in cols:
                fields["OVALTestVersion"] = 1
            if has_comment:
                fields["comment"] = b["comment"] or ""
            if "CreatedDate" in cols:
                fields["CreatedDate"] = now
            keys = [k for k in fields if k in cols]
            cur.execute("INSERT INTO OVALTEST (%s) VALUES (%s)" % (",".join(keys), ",".join(["?"] * len(keys))),
                        tuple(fields[k] for k in keys))
            created += 1
    conn.commit()
    conn.close()
    log("done: %d created, %d updated, %d skipped (db=%s)" % (created, updated, skipped, db_path))


if __name__ == "__main__":
    main()
