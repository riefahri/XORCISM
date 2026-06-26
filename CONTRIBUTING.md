# Contributing to XORCISM

Thanks for helping build XORCISM — the free, open-source Cyber Risk Operations Center. This guide
covers how the project is laid out, how to build & run it, and the two most common contributions:
**connectors** (feed a tool's output into XORCISM) and **importers** (bulk-load a framework / dataset).

> **Golden rule:** verify DB-writing code against a **copy** of the databases, never the live ones.
> Point `DB_DIR` (Node) / `XORCISM_DB_DIR` (Python) at a temp folder of copied `*.db` files.

---

## Project layout

```
xorcism_ts/                # the app (TypeScript)
  server/                  # Express server, one module per cockpit (aisystems.ts, aibas.ts, …)
    routes/                # one router per module
    data/toolsSeed.ts      # the TOOL catalogue (seeded into XORCISM.TOOL at boot)
  client/                  # static HTML pages + client/ts/*.ts (bundled by esbuild)
  esbuild.config.js        # client entry-point list (add yours here)
connectors/<id>/           # one folder per connector: connector.json + run.py + sample.json + README.md
connectors/runner.py       # imports a connector's normalized result into the DBs (import_result dispatch)
xorcism_python/importers/  # bulk framework / dataset importers (import_*.py)
databases/*_sqlite.sql     # canonical DDL — keep in sync when you add a table
docs/                      # design docs
```

## Build & run

```bash
cd xorcism_ts
npm install
npm run build            # build:server (tsc) + build:client (esbuild)
npm start                # serves the app
```

- **Use the bundled Node 20** to *run* the server (`tools/nodejs/node.exe` on the reference setup) —
  `better-sqlite3`'s native ABI is built for Node 20, not a newer system Node.
- `npm run build:server` is also your **type-check** (`tsc`). The client build (esbuild) bundles but
  does **not** type-check — keep client TS self-contained.
- Tables are created idempotently at boot (`CREATE TABLE IF NOT EXISTS` + additive `ALTER`), so
  upgrading is in-place and never drops data. Mirror any new table into `databases/*_sqlite.sql`.

---

## Writing a connector (~40 lines)

A connector turns one tool's output into XORCISM's normalized shape; the **runner** does all DB writes.

### The contract

`run.py` exposes `run(params: dict, workdir: str) -> dict`. For a scanner/findings tool, return:

```jsonc
{
  "project": "MyScanner",
  "assets":   [{ "hostname": "web01", "key": "web01", "ip": "10.0.0.5", "tags": "myscanner" }],
  "services": [{ "asset": "web01", "port": 443, "proto": "tcp", "name": "https", "product": "nginx" }],
  "vulns":    [{ "asset": "web01", "ref": "CVE-2023-1234", "name": "Path traversal", "severity": "high" }]
}
```

Other mappings the runner understands (return whichever keys apply): `identities`, `aisystems`,
`intel`, `sigma`/`yara`, `guardrail_violations`, `compliance`, `monitors`, `alerts`/`incidents`.
`import_result(mapping, result)` in `connectors/runner.py` routes on the keys present.

### The 4 files in `connectors/<id>/`

1. **`connector.json`** — manifest:
   ```json
   {
     "id": "myscanner", "name": "MyScanner — example web scanner", "type": "import",
     "category": "Penetration Testing",
     "description": "Imports MyScanner JSON. Pass `file` = an export, or run with no config for the sample.",
     "intrusive": false, "permission": "connector:myscanner", "run": "run.py", "mapping": "myscanner",
     "parameters": [ { "name": "file", "type": "file", "required": false, "help": "A MyScanner JSON report" } ]
   }
   ```
   Set `"intrusive": true` for anything that touches the target (so it's gated behind authorization).

2. **`run.py`** — worker-safe: **stdlib only, secrets via `os.environ`, ASCII-only output, no DB access.**
   Implement the three modes: **live** (env creds → API), **offline** (`file` param → parse export),
   **demo** (neither → bundled `sample.json`). End with a `__main__` that prints the normalized JSON.

3. **`sample.json`** — the bundled demo input. **Always ship one** — without it, `python run.py` throws.

4. **`README.md`** — what it maps, the env config, and the `python run.py` demo line.

### Test & wire in
```bash
python connectors/myscanner/run.py        # must print clean normalized JSON
```
- Add a one-liner to `server/data/toolsSeed.ts` so it appears in the catalogue.
- (Optional) add a rule to `server/chain.ts` `DEFAULT_PLAYBOOK.rules` to chain it after another step.

**Gotchas:** keep `ref` stable (CVE ids link to KEV/EPSS enrichment; non-CVE refs become named
findings); keep `asset.key` stable across runs (it's the dedupe key); never `print` non-ASCII.

---

## Writing an importer (bulk framework / dataset loader)

Importers live in `xorcism_python/importers/` and load reference data (frameworks, CVEs, ATT&CK/ATLAS,
Sigma…). They write the SQLite DBs directly, **idempotently**.

### The pattern (raw `sqlite3`)

```python
"""import_myframework.py — load MyFramework controls into XORCISM.CONTROL."""
import os, sqlite3, uuid
from datetime import datetime, timezone

VOCAB = "MyFramework v1.0"
CONTROLS = [("MF-1", "First control title"), ("MF-2", "Second control title")]  # titles only — no copyrighted text

def _db_path() -> str:                       # ALWAYS honour the env override (lets us dry-run on a copy)
    d = os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, "XORCISM.db")

def _ensure_vocab(cur, name):                # get-or-create the VOCABULARY, return its id
    cols = {r[1] for r in cur.execute("PRAGMA table_info(VOCABULARY)").fetchall()}
    namecol = "VocabularyName" if "VocabularyName" in cols else "Name"
    row = cur.execute(f"SELECT VocabularyID FROM VOCABULARY WHERE {namecol}=?", (name,)).fetchone()
    if row: return int(row[0])
    nid = (cur.execute("SELECT COALESCE(MAX(VocabularyID),0) FROM VOCABULARY").fetchone()[0] or 0) + 1
    cur.execute(f"INSERT INTO VOCABULARY (VocabularyID,{namecol},CreatedDate) VALUES (?,?,?)",
                (nid, name, datetime.now(timezone.utc).isoformat()))
    return nid

def main() -> int:
    con = sqlite3.connect(_db_path()); con.execute("PRAGMA busy_timeout=15000"); cur = con.cursor()
    now = datetime.now(timezone.utc).isoformat()
    vid = _ensure_vocab(cur, VOCAB)
    ccols = {r[1] for r in cur.execute("PRAGMA table_info(CONTROL)").fetchall()}   # guard: only insert existing cols
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))                # idempotent: delete + re-insert
    nid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    for ref, title in CONTROLS:
        rec = {"ControlID": nid, "ControlGUID": str(uuid.uuid4()), "ControlName": f"{ref} {title}",
               "ISO": ref, "VocabularyID": vid, "CreatedDate": now}
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
        nid += 1
    con.commit(); con.close()
    print(f"[myframework] {len(CONTROLS)} controls under VocabularyID={vid}.")   # ASCII only
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

### Importer rules
- **Idempotent** — either get-or-create by a natural key, or `DELETE … WHERE VocabularyID=?` then
  re-insert. Re-running must not duplicate.
- **`XORCISM_DB_DIR` override** — always read it, so contributors and CI can run against a copy.
- **PRAGMA column guard** — insert only columns that exist (`ccols`), so the importer survives schema drift.
- **Copyright** — for ISO / paywalled standards, store **clause references + short factual titles only**,
  never the normative text. (See `import_iso27001.py` / `import_iso27701.py`.)
- **Crosswalks** — write `CONTROLMAPPING` rows (`Framework`, `ExternalID`, `Relationship`) to link to
  GDPR / NIS2 / NIST etc. (See `import_recyf.py` / `import_duaa.py`.)
- **Register a compliance framework** — add its VOCABULARY name to `DOC_FRAMEWORKS` in
  `client/ts/app.ts` so it appears in the framework picker.
- **ASCII-only `print`** — the worker/console may be cp1252; non-ASCII output crashes it.
- **Verify on a copy:** `XORCISM_DB_DIR="/tmp/copy" python xorcism_python/importers/import_myframework.py`,
  run it **twice** to prove idempotency.

---

## Conventions & PR checklist

- **Tenant scope:** demo/seed data goes to **tenant 3** only; insert directly (no side effects).
- **Version:** a release bump touches **three** sync points — `xorcism_ts/package.json`,
  `server/openapi.ts`, `server/routes/v1.ts` (`VERSION`).
- **Docs:** new modules get a line in `RELEASE_NOTES.md` and (if user-facing) the `README.md` feature list.
- **SQL scripts:** every new table added in `db.ts`/a module's `ensure*` also goes into the matching
  `databases/*_sqlite.sql` (before `COMMIT;`).

Before opening a PR:
- [ ] `npm run build` is clean (server `tsc` 0 errors, client esbuild OK).
- [ ] DB-writing code verified on a **copy** (never the live DBs).
- [ ] Connector smoke test prints clean JSON / importer is idempotent (run it twice).
- [ ] New table mirrored into `databases/*_sqlite.sql`; new tool in `toolsSeed.ts`.
- [ ] No secrets committed; secrets read from env only.

Questions? Open a discussion or ask on the community forum. Thanks for contributing! 🛡️
