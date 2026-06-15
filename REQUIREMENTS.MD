# XORCISM — Requirements

All software needed to install and run XORCISM. Installation steps are in
[SETUP.MD](SETUP.MD).

Only the **System** and **Web application** sections are mandatory. Everything
under *Optional components* is needed only if you use that feature.

---

## 1. System requirements

| Requirement | Version | Notes |
|---|---|---|
| **OS** | Windows 10/11 (primary), Linux/macOS | Setup scripts are PowerShell; the Node app itself is cross‑platform. |
| **Node.js** | **20.x LTS** | Runs the web application. A portable runtime is bundled at `tools/nodejs/node.exe`. |
| **npm** | bundled with Node | Installs web‑app dependencies. |
| **SQLite 3 CLI** | 3.40+ | Bundled at `tools/sqlite3.exe`; used by `create_databases.ps1`. |
| **PowerShell** | 5.1+ (or PowerShell 7) | For `create_databases.ps1`, `generate_models.ps1`, `import_nvd_cve.ps1`. |
| **Browser** | Chrome / Edge / Firefox (current) | Client uses ES2020 + `fetch`. |
| **Disk** | ~1–2 GB free in `DB_DIR` | Reference DBs are large once populated (XVULNERABILITY/XOVAL can reach hundreds of MB). |

> The SQLite databases must live **outside OneDrive / any synced folder**
> (default `C:\Users\<you>\XORCISM_databases`). See SETUP.MD §2.

---

## 2. Web application (mandatory) — `xorcism_ts/`

Node.js + TypeScript (Express + `better-sqlite3`). Install with
`npm install` in `xorcism_ts/`.

### Runtime dependencies (`package.json`)

| Package | Version | Role |
|---|---|---|
| `express` | ^4.18.3 | HTTP server / routing |
| `express-async-errors` | ^3.1.1 | Async error propagation |
| `better-sqlite3` | ^9.4.3 | Synchronous SQLite driver (native module; Windows prebuilt binaries for Node 20) |

### Build / dev dependencies (`package.json`)

| Package | Version | Role |
|---|---|---|
| `typescript` | ^5.3.3 | Compiles `server/**` (`tsc -p tsconfig.server.json`) |
| `esbuild` | ^0.20.1 | Bundles `client/ts/**` → `dist/client/js/` |
| `nodemon` | ^3.0.3 | Dev auto‑restart (`npm run dev`) |
| `concurrently` | ^8.2.2 | Runs the dev watchers together |
| `@types/node` | ^20.11.5 | Node typings |
| `@types/express` | ^4.17.21 | Express typings |
| `@types/better-sqlite3` | ^7.6.8 | Driver typings |

### Client‑side libraries (loaded from CDN — no npm install)

| Library | Version | Used by |
|---|---|---|
| Chart.js | 4.x | Dashboard charts |
| SheetJS (`xlsx`) | 0.20.3 | Excel export in the Database Explorer |

> A native build of `better-sqlite3` is required. On Node 20 LTS a prebuilt
> binary is downloaded automatically. If your platform has no prebuild, you need
> a C/C++ toolchain for `node-gyp` (on Windows: **Visual Studio Build Tools** +
> Python 3).

---

## 3. Databases

13 SQLite databases (no server process — files on disk via `better-sqlite3`).
**The web app auto‑creates ALL of them on first start** if missing — no manual
step is required:

- **Schema databases** — `XORCISM`, `XVULNERABILITY`, `XATTACK`, `XMALWARE`,
  `XINCIDENT`, `XTHREAT`, `XOVAL`, `XWINDOWS`: built from
  `databases/<NAME>_sqlite.sql` (those files are committed; `create_databases.ps1`
  regenerates them from the T‑SQL sources when needed).
- **Operational databases** — `XID`, `XCOMPLIANCE`, `XTICKET`, `XJOB`, `XAGENT`:
  created table‑by‑table in code.

The schema DBs start **empty** (structure only); reference data (CVE, ATT&CK,
CAPEC, OVAL…) is loaded separately by the importers. No external database engine
is required for the core platform (the forum is the only component that needs
MariaDB — §5.4).

---

## 4. Python tooling (optional) — `xorcism_python/`

Needed only for the SQLAlchemy models, importers, and tests.

| Requirement | Version |
|---|---|
| **Python** | 3.11+ (tested on 3.14) |

### `xorcism_python/requirements.txt`

| Package | Version | Role |
|---|---|---|
| `sqlalchemy` | >= 2.0 | ORM / models (one `__bind_key__` per DB) |
| `requests` | >= 2.31 | HTTP for importers and API connectors |
| `lxml` | >= 4.9 | XML parsing (OVAL, CAPEC, Nessus/OpenVAS reports…) |
| `python-dateutil` | >= 2.8 | Date parsing |
| `cryptography` | >= 41.0 | Crypto helpers |

Install:

```powershell
pip install -r xorcism_python/requirements.txt
```

---

## 5. Optional components

### 5.1 Connectors — `connectors/`

- **Python 3.11+**.
- `requests` (already in `requirements.txt`) for API connectors
  (**MITRE Caldera**, **Qualys**, **Dependency‑Track**).
- For **tool‑runner** connectors, the underlying tool must be on `PATH` of the
  host running the runner — e.g. `nmap`, `nuclei`, `whatweb`, `sqlmap`, `w3af`.
  Scanner imports (Nessus, OpenVAS, Qualys, Rapid7, SAINT, Metasploit) consume
  exported report files or APIs.

### 5.2 Remote workers

A worker host (e.g. a **Kali Linux** VM) only needs the `connectors/` folder,
**Python 3.11+**, and the tools it is allowed to run.

### 5.3 TAXII 2.1 server — `taxii/`

| Requirement | Version |
|---|---|
| Python | 3.11+ |
| `flask` | any recent (`pip install flask`) |

### 5.4 Community forum — `website/forum/`

| Requirement | Version | Notes |
|---|---|---|
| **PHP** | 8.1+ | CLI server, Apache, or Nginx + PHP‑FPM |
| PHP ext `pdo_mysql` | — | MariaDB driver (see `php.ini.sample`) |
| PHP ext `mysqli` | — | Required by the DB layer |
| **MariaDB** | 10.6+ (or MySQL 8) | Default backend; SQLite fallback exists |

The DB/user are created by **you** (the app never creates DB accounts); the
password goes in `website/forum/config.local.php` (not committed).

---

## 6. Environment variables

### Web application (`xorcism_ts/`)

| Variable | Default | Purpose |
|---|---|---|
| `DB_DIR` | `C:/Users/jerom/XORCISM_databases` | Folder holding the SQLite `*.db` files (and `XVAULT.json`). **Set this on every host.** |
| `PORT` | `9292` | HTTP port. |
| `XORCISM_ALLOW_REGISTER` | `1` | Set `0` to disable public self‑registration. |
| `XORCISM_REGISTER_TENANT` | *(first non‑system tenant)* | Tenant ID assigned to self‑registered users. |
| `XORCISM_BASE_URL` | *(derived from request)* | Base URL used in password‑reset links. |

### Python tooling (`xorcism_python/`)

| Variable | Default | Purpose |
|---|---|---|
| `XORCISM_DB_DIR` | `C:\Users\jerom\XORCISM_databases` | Same path as `DB_DIR`. |
| `SMTP_SERVER` / `SMTP_PORT` / `SMTP_USERNAME` / `SMTP_PASSWORD` | example / 587 / "" / "" | Outbound mail for importer notifications. |
| `LOG_LEVEL` | `INFO` | Logging verbosity. |

### Connectors (set on the host running the connector/runner)

| Variable | Purpose |
|---|---|
| `CALDERA_URL`, `CALDERA_API_KEY` | MITRE Caldera API (v2) import. |
| `QUALYS_API_URL`, `QUALYS_USER`, `QUALYS_PASSWORD` | Qualys VMDR import. |
| `DTRACK_URL`, `DTRACK_API_KEY` | OWASP Dependency‑Track API mode. |

> **Never** put secrets in the UI, in source, or in committed files. Use
> environment variables (connectors / web app) or the non‑committed
> `config.local.php` (forum). The field‑encryption vault passphrase is set
> interactively by the admin and is never stored in clear.

### TAXII server

| Variable | Purpose |
|---|---|
| `TAXII_AUTH` | `1` = require HTTP Basic auth. |

---

## 7. Summary checklist

- [ ] Node.js 20 LTS (or bundled `tools/nodejs/node.exe`)
- [ ] `npm install` in `xorcism_ts/` (pulls `express`, `better-sqlite3`, `typescript`, `esbuild`)
- [ ] `DB_DIR` set to a folder **outside** OneDrive
- [ ] Databases created (`create_databases.ps1`) and copied into `DB_DIR`
- [ ] *(optional)* Python 3.11+ and `pip install -r xorcism_python/requirements.txt`
- [ ] *(optional)* tools on `PATH` for connectors; `flask` for TAXII; PHP 8.1+ & MariaDB for the forum
