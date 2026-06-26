"""migrate_db.py — copy XORCISM's SQLite databases into another SQL backend.

XORCISM's Python data layer is SQLAlchemy, so it can run on PostgreSQL / MySQL / MariaDB.
This tool provisions the target schema and copies all rows from the per-file SQLite databases
to one database-per-logical-name on the target server (mirroring the SQLite layout):
    XORCISM.db -> "xorcism", XVULNERABILITY.db -> "xvulnerability", …

It reflects each SQLite database's schema, recreates it on the target (coercing SQLite's
untyped columns to TEXT so PostgreSQL/MySQL accept them), then bulk-copies the rows. The
target databases must already exist on the server (CREATE DATABASE) — this tool creates the
tables, not the databases.

Usage:
    # 1) self-test / SQLite -> SQLite copy (no server needed) — proves the copy logic:
    python tools/migrate_db.py --target-dir C:\\tmp\\xorcism_copy --only XOVAL

    # 2) SQLite -> PostgreSQL (one database per logical name, all lowercased):
    #    createdb xorcism xvulnerability … first, then:
    set XORCISM_DB_HOST=localhost & set XORCISM_DB_USER=xorcism & set XORCISM_DB_PASSWORD=...
    python tools/migrate_db.py --engine postgresql        # needs: pip install psycopg2-binary

    # 3) SQLite -> MySQL/MariaDB:
    python tools/migrate_db.py --engine mysql             # needs: pip install pymysql

Flags: --engine {postgresql,mysql,mariadb}  --only NAME[,NAME]  --target-dir DIR (sqlite test)
       --batch N (default 1000)  --drop (drop+recreate target tables)  --dry-run
After migrating, run XORCISM's Python side against the target by setting XORCISM_DB_ENGINE
(see config.py / docs/DATABASE_BACKENDS.md). The Node server remains on SQLite for now.
"""
from __future__ import annotations

import argparse
import os
import sys

from sqlalchemy import create_engine, MetaData, select, insert
from sqlalchemy.types import NullType, Text

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from xorcism_python import config  # noqa: E402


def _target_url(name: str, args) -> str:
    if args.target_dir:
        os.makedirs(args.target_dir, exist_ok=True)
        return f"sqlite:///{os.path.join(args.target_dir, name + '.db')}"
    drivers = {"postgresql": "postgresql+psycopg2", "postgres": "postgresql+psycopg2",
               "mysql": "mysql+pymysql", "mariadb": "mysql+pymysql"}
    driver = drivers.get(args.engine)
    if not driver:
        raise SystemExit(f"--engine must be one of {sorted(set(drivers))} (or use --target-dir for a SQLite copy)")
    import urllib.parse
    host = os.getenv("XORCISM_DB_HOST", "localhost")
    port = os.getenv("XORCISM_DB_PORT", "5432" if "postgresql" in driver else "3306")
    user = urllib.parse.quote_plus(os.getenv("XORCISM_DB_USER", "xorcism"))
    pw = urllib.parse.quote_plus(os.getenv("XORCISM_DB_PASSWORD", ""))
    dbname = (os.getenv("XORCISM_DB_PREFIX", "") + name).lower()
    return f"{driver}://{user}:{pw}@{host}:{port}/{dbname}"


def migrate_one(name: str, args) -> dict:
    src_path = os.path.join(config.DB_DIR, name + ".db")
    if not os.path.exists(src_path):
        return {"db": name, "skipped": "no SQLite file"}
    src = create_engine(f"sqlite:///{src_path}")
    dst = create_engine(_target_url(name, args))

    md = MetaData()
    md.reflect(bind=src)
    # SQLite is permissive (untyped columns); coerce NullType -> TEXT so the target accepts them.
    for tbl in md.tables.values():
        for col in tbl.columns:
            if isinstance(col.type, NullType):
                col.type = Text()

    tables = list(md.sorted_tables)
    if args.dry_run:
        return {"db": name, "tables": len(tables), "dry_run": True,
                "table_names": [t.name for t in tables]}

    if args.drop:
        md.drop_all(bind=dst, checkfirst=True)
    md.create_all(bind=dst, checkfirst=True)

    copied, errors = {}, {}
    with src.connect() as sc:
        for tbl in tables:
            try:
                rows = [dict(r._mapping) for r in sc.execute(select(tbl))]
                if rows:
                    with dst.begin() as dc:
                        for i in range(0, len(rows), args.batch):
                            dc.execute(insert(tbl), rows[i:i + args.batch])
                copied[tbl.name] = len(rows)
            except Exception as e:  # noqa: BLE001 — report and continue
                errors[tbl.name] = str(e)[:200]
    return {"db": name, "tables": len(tables), "rows": sum(copied.values()),
            "table_errors": errors}


def main() -> int:
    ap = argparse.ArgumentParser(description="Migrate XORCISM SQLite databases to another SQL backend")
    ap.add_argument("--engine", default="", help="postgresql | mysql | mariadb (target server)")
    ap.add_argument("--target-dir", default="", help="copy to SQLite files in this dir instead (self-test)")
    ap.add_argument("--only", default="", help="comma-separated logical DB names (default: all)")
    ap.add_argument("--batch", type=int, default=1000)
    ap.add_argument("--drop", action="store_true", help="drop+recreate target tables first")
    ap.add_argument("--dry-run", action="store_true", help="reflect only; copy nothing")
    args = ap.parse_args()
    if not args.engine and not args.target_dir and not args.dry_run:
        ap.error("specify --engine (server) or --target-dir (SQLite copy) or --dry-run")

    names = [n.strip().upper() for n in args.only.split(",") if n.strip()] or list(config.LOGICAL_DBS)
    print(f"[migrate] {len(names)} database(s) -> "
          + (f"sqlite dir {args.target_dir}" if args.target_dir else f"{args.engine} server")
          + (f" (dry-run)" if args.dry_run else ""))
    total_rows = total_err = 0
    for name in names:
        r = migrate_one(name, args)
        if r.get("skipped"):
            print(f"  - {name}: skipped ({r['skipped']})")
            continue
        if r.get("dry_run"):
            print(f"  · {name}: {r['tables']} table(s)")
            continue
        errs = r.get("table_errors") or {}
        total_rows += r.get("rows", 0); total_err += len(errs)
        print(f"  + {name}: {r['tables']} table(s), {r.get('rows', 0)} row(s)"
              + (f" — {len(errs)} table error(s): {list(errs)[:3]}" if errs else ""))
    print(f"[migrate] done: {total_rows} row(s) copied, {total_err} table error(s)")
    return 1 if total_err else 0


if __name__ == "__main__":
    sys.exit(main())
