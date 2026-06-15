# XORCISM — Installation Guide

How to install XORCISM end‑to‑end: **the databases** and **the web application**.

For the exact list of dependencies and versions, see [REQUIREMENTS.MD](REQUIREMENTS.MD).

---

## 1. Architecture overview

XORCISM is a cyber exposure / threat / compliance platform. The pieces relevant
to an install:

| Component | Folder | Runtime | Purpose |
|---|---|---|---|
| **Web application** (main) | `xorcism_ts/` | Node.js + TypeScript | Auth (XID/RBAC), Database Explorer, Dashboard, Connectors, Threat models, BIA |
| **Databases** | `databases/` → `DB_DIR` | SQLite (`better-sqlite3`) | 13 SQLite files (see §3) |
| **Python models / importers** | `xorcism_python/` | Python 3.11+ + SQLAlchemy 2.0 | Reference‑data import (CVE, ATT&CK, CAPEC, OVAL…) and scripts |
| **Connectors** (optional) | `connectors/` | Python | Tool‑runners (nmap, nuclei…) and API imports (Caldera, Qualys, Dependency‑Track) |
| **TAXII 2.1 server** (optional) | `taxii/` | Python + Flask | STIX/TAXII feed |
| **Community forum** (optional) | `website/forum/` | PHP 8 + MariaDB | Public forum |

The **web application is the only mandatory component**. Everything else is optional.

---

## 2. Prerequisites

Install these first (see [REQUIREMENTS.MD](REQUIREMENTS.MD) for versions):

- **Node.js 20.x LTS** (or use the bundled portable Node at `tools/nodejs/node.exe`).
- **sqlite3 CLI** — bundled at `tools/sqlite3.exe` (used by the DB creation script).
- **Python 3.11+** — only for the importers / connectors / TAXII (optional).
- **PowerShell 5.1+** (Windows) — the setup scripts are PowerShell.
- A modern **browser** (Chrome, Edge, Firefox).
- *(Optional)* **MariaDB 10.6+** and **PHP 8.1+** — only for the forum.

> **Windows / OneDrive warning.** The project tree lives under OneDrive, but the
> **SQLite databases must live OUTSIDE OneDrive**. OneDrive replaces files under
> open handles, which corrupts WAL journals and causes stale reads. The default
> database location is `C:\Users\<you>\XORCISM_databases` (override with the
> `DB_DIR` env var). Keep it out of any synced folder.

---

## 3. Step 1 — Databases (auto‑created)

XORCISM uses **13 SQLite databases**, and **the web app creates all of them
automatically on first start** (§4) if they don't already exist in `DB_DIR`:

- **Schema databases** — `XORCISM`, `XVULNERABILITY`, `XATTACK`, `XMALWARE`,
  `XINCIDENT`, `XTHREAT`, `XOVAL`, `XWINDOWS`: built from the committed
  `databases/<NAME>_sqlite.sql` files.
- **Operational databases** — `XID` (users/RBAC/sessions), `XCOMPLIANCE`
  (audits/GRC/evidence), `XTICKET`, `XJOB` (connector queue), `XAGENT`: created
  in code.

So for a standard setup you can **skip straight to §4** — the first server start
populates `DB_DIR`. The schema DBs start **empty** (structure only); load
reference data later via the importers (§3.3).

> **You only need the steps below (3.1–3.2) if** you want to (re)generate the
> schema SQL from the original T‑SQL sources, or pre‑seed `DB_DIR` before the
> first run.

### 3.1 (Optional) Regenerate the schema databases

`create_databases.ps1` converts the T‑SQL schemas in `XORCISM_repo/MODELS/` to
SQLite, (re)writing both `databases/<NAME>_sqlite.sql` and `databases/<NAME>.db`:

```powershell
cd C:\Users\<you>\OneDrive\Documents\XORCISM
.\create_databases.ps1
```

### 3.2 (Optional) Pre‑seed `DB_DIR` outside OneDrive

The app creates the DBs directly in `DB_DIR` on first start, but if you built
them in `databases/` you can copy them across:

```powershell
$DB = "C:\Users\$env:USERNAME\XORCISM_databases"
New-Item -ItemType Directory -Force $DB | Out-Null
Copy-Item .\databases\*.db $DB -Force
```

> If you place `DB_DIR` somewhere else, set the `DB_DIR` env var for the web app
> (§4) **and** `XORCISM_DB_DIR` for the Python tooling (§6) to the same path.

### 3.3 (Optional) Populate reference data

The schema databases start empty. Load reference data with the importers:

```powershell
# CVE / NVD into XVULNERABILITY
.\import_nvd_cve.ps1
# ATT&CK, CAPEC, CWE, OVAL, etc. — see xorcism_python importers
```

You can skip this initially; the app runs against empty reference tables and you
add your own assets/data through the UI.

---

## 4. Step 2 — Install & run the web application

The web app is in `xorcism_ts/` (Express + `better-sqlite3`, served on port **9292**).

### 4.1 Install dependencies

```powershell
cd xorcism_ts
npm install
```

This installs `express`, `better-sqlite3` (native module — Windows prebuilt
binaries are used automatically for Node 20), `typescript`, `esbuild`, etc.

> No system Node? Use the bundled portable runtime instead of `npm`:
> `..\tools\nodejs\node.exe node_modules\typescript\bin\tsc -p tsconfig.server.json`

### 4.2 Build

```powershell
npm run build          # = build:server (tsc) + build:client (esbuild)
```

- `build:server` → compiles `server/**` to `dist/server/`.
- `build:client` → bundles `client/ts/**` to `dist/client/js/`.

### 4.3 Configure (environment variables)

The defaults work out of the box; override only if needed:

```powershell
$env:DB_DIR = "C:\Users\$env:USERNAME\XORCISM_databases"   # must match §3.2
$env:PORT   = "9292"                                        # default
# $env:XORCISM_ALLOW_REGISTER = "0"  # disable public self‑registration
```

See [REQUIREMENTS.MD](REQUIREMENTS.MD) §6 for the full env‑var table.

### 4.4 Start

```powershell
npm start              # = node dist/server/index.js
```

On first start the server **auto‑creates all 13 databases** inside `DB_DIR` if
missing — the schema DBs (`XORCISM`, `XVULNERABILITY`, `XATTACK`, `XMALWARE`,
`XINCIDENT`, `XTHREAT`, `XOVAL`, `XWINDOWS`, from the `databases/*_sqlite.sql`
files) and the operational DBs (`XID`, `XCOMPLIANCE`, `XTICKET`, `XJOB`,
`XAGENT`) — then seeds the **System** tenant and the **Admin/User** roles and
starts the background loops:

```
[db] base XORCISM créée (schéma depuis XORCISM_sqlite.sql)   ← only on first run
…
[scheduler] démarré (tick 30s)
[riskscore] boucle démarrée (ASSET.RiskScore + EnterpriseRiskScore toutes les 30 s)

  XORCISM TypeScript Server (auth XID activée)
  http://localhost:9292/login
```

> **Run detached (Windows), surviving the terminal:**
> ```powershell
> Start-Process -FilePath ..\tools\nodejs\node.exe `
>   -ArgumentList 'dist\server\index.js' -WorkingDirectory (Get-Location) `
>   -RedirectStandardOutput C:\tmp\xorcism_server.log `
>   -RedirectStandardError  C:\tmp\xorcism_server.err.log -WindowStyle Hidden
> ```

### 4.5 First login

On the **very first** start (no users yet), the server prints a one‑time admin
account to the console:

```
  COMPTE ADMIN INITIAL CRÉÉ
    Email        : admin@xorcism.local
    Mot de passe : <random temp password, shown ONCE>
    (À CHANGER à la première connexion)
```

1. Open `http://localhost:9292/login`.
2. Sign in with `admin@xorcism.local` and the temporary password.
3. You will be forced to set a new password.

> If you missed the password, stop the server, delete `DB_DIR\XID.db`, and
> restart to re‑seed (this wipes all users — only do it on a fresh install).

The Admin belongs to the **System** tenant and is super‑admin (sees all tenants).
New self‑registered users get the **User** role in the first non‑system tenant.

### 4.6 Field encryption vault (optional)

To use encrypted sensitive fields, the admin configures a **vault passphrase**
in the UI (Admin → Vault). The data‑encryption key is wrapped by the passphrase
and stored in `DB_DIR\XVAULT.json`; a one‑time **recovery key** is shown — save
it offline. The server cannot read encrypted fields while the vault is locked.

---

## 5. Background jobs (run automatically inside the web app)

No cron needed — the Node server runs these on its own timers:

- **RiskScore loop** (every 30 s): recomputes `ASSET.RiskScore` for every asset
  and the per‑tenant **EnterpriseRiskScore** (shown first on the Dashboard);
  history is written to `ASSETRISKSCORE` / `RISKSCORE`.
- **Connector scheduler** (every 30 s): fires due scheduled connector jobs
  (cron‑based) into the `XJOB` queue.
- **Session purge** (hourly): removes expired sessions.

---

## 6. Step 3 (optional) — Python tooling / importers

```powershell
cd xorcism_python
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:XORCISM_DB_DIR = "C:\Users\$env:USERNAME\XORCISM_databases"   # same as DB_DIR
python -m pytest tests   # smoke test: models load + DB connectivity
```

The SQLAlchemy models live in `xorcism_python/models/` (one module per database,
`__bind_key__` per DB). DB locations are read from `XORCISM_DB_DIR`
(see `xorcism_python/config.py`).

---

## 7. Step 4 (optional) — Connectors & remote workers

Connectors run security tools and import the results. Each lives in
`connectors/<id>/` with a `connector.json` manifest (auto‑discovered by the web
app under **Connectors**).

- **Tool‑runners** (nmap, nuclei, whatweb, sqlmap…): the named binary must be on
  `PATH` on the host that runs the connector runner.
- **API imports** (Caldera, Qualys, Dependency‑Track): configured **only** via
  environment variables (never typed in the UI) — e.g. `CALDERA_URL` +
  `CALDERA_API_KEY`, `QUALYS_API_URL`/`QUALYS_USER`/`QUALYS_PASSWORD`,
  `DTRACK_URL` + `DTRACK_API_KEY`. API connectors need `pip install requests`.

Local runner (executes `local` jobs and imports results centrally):

```powershell
python connectors\runner.py
```

Remote worker (e.g. a Kali VM — only needs `connectors/` + Python + the tools):

```bash
python connectors/runner.py --remote https://xorcism.host:9292 \
       --token <worker-token> --name kali-01 --capabilities nmap,nuclei
```

Create the worker + token from the UI (**Connectors → Workers**). See
[docs/CONNECTORS.md](docs/CONNECTORS.md) for the full model.

---

## 8. Step 5 (optional) — TAXII 2.1 server

```powershell
cd taxii
pip install flask
python taxii_server.py            # http://127.0.0.1:5000
# Require HTTP Basic auth:
$env:TAXII_AUTH = "1"; python taxii_server.py
```

Initialise its store with `taxii/create_taxii_db.sql` if using the SQLite
backend. See `taxii/README.md` and `taxii/GUIDE.md`.

---

## 9. Step 6 (optional) — Community forum (MariaDB + PHP)

The forum is in `website/forum/` and uses **MariaDB** by default (SQLite
fallback available).

1. **Create the database and user** (as MariaDB root — *you* do this; the app
   never creates DB accounts):

   ```sql
   CREATE DATABASE xorcism_forum CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   CREATE USER 'xorcism_forum'@'localhost' IDENTIFIED BY 'YOUR_PASSWORD';
   GRANT ALL PRIVILEGES ON xorcism_forum.* TO 'xorcism_forum'@'localhost';
   FLUSH PRIVILEGES;
   ```

2. **Configure** — copy the example and fill in your password (this file is
   **not** committed and holds the secret):

   ```powershell
   Copy-Item website\forum\config.local.php.example website\forum\config.local.php
   # edit website\forum\config.local.php → db.pass
   ```

3. **Enable PHP extensions** `pdo_mysql` + `mysqli` (see
   `website/forum/php.ini.sample`), then serve the folder with PHP/Apache/Nginx.
   The forum creates its own tables on first load.

---

## 10. Verifying the install

- `http://localhost:9292/login` returns the login page (HTTP 200).
- After login, the **Dashboard** shows the **Enterprise RiskScore** card first.
- The **Database Explorer** lists the databases and tables (filtered by your
  role; non‑admins do not see admin‑only tables).
- Server log shows both `[scheduler]` and `[riskscore]` lines and no stderr
  errors.

---

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Unknown database: X` | `DB_DIR` is wrong or the `*.db` file isn't there. Confirm §3.2. |
| Stale reads / WAL corruption | The DBs are inside OneDrive/a synced folder. Move `DB_DIR` out (§2). |
| `Cannot POST /api/...` returns HTML | Server is stale — rebuild (`npm run build`) and restart. |
| Port 9292 busy | Set `$env:PORT` to a free port before `npm start`. |
| `better-sqlite3` build error on `npm install` | Use Node 20 LTS (prebuilt binaries) or install MSVC Build Tools + Python for `node-gyp`. |
| Forum: `[1045] Access denied` | The MariaDB DB/user don't exist yet or the password in `config.local.php` is wrong (§9). |
| Lost the seeded admin password | Fresh install only: delete `DB_DIR\XID.db` and restart to re‑seed. |

---

## 12. Quick start (TL;DR)

The web app creates all databases on first start, so a fresh setup is just:

```powershell
cd xorcism_ts
npm install
npm run build
$env:DB_DIR = "C:\Users\$env:USERNAME\XORCISM_databases"
npm start
# → open http://localhost:9292/login  (admin password printed once in the console)
#   first start creates all 13 databases in $env:DB_DIR automatically
```
