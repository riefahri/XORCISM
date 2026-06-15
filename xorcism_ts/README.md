# XORCISM (TypeScript)

TypeScript/Node.js rewrite of the PowerShell server `xorcism_web.ps1`.

XORCISM is a security data platform: a schema-driven explorer over a family of SQLite
databases (assets, vulnerabilities, threats, incidents, compliance, identities…) plus
purpose-built views — dashboard, Business Impact Analysis, MITRE ATT&CK / ATLAS / D3FEND
matrices, a STIX relationship graph, OCIL questionnaires and threat feeds.

## Stack

| Layer | Technology |
|---|---|
| Server | Node.js + Express 4 + TypeScript (compiled to CommonJS) |
| Database | better-sqlite3 (synchronous, no ORM) |
| Client | TypeScript bundled with esbuild |
| Charts | Chart.js (dashboard) |
| Export | SheetJS (XLSX) |
| Auth | session cookies, passkeys (WebAuthn, ES256/RS256), optional OIDC |
| Runtime | portable Node 20 under `tools/nodejs/` |

## Databases

SQLite files live **outside** OneDrive (default `C:\Users\<user>\XORCISM_databases`,
overridable via `XORCISM_DB_DIR`). The explorer auto-discovers tables, so new tables show
up after a server restart with no code change.

`XORCISM` (core: assets, applications, controls, persons, tags…), `XVULNERABILITY`,
`XCOMPLIANCE` (OCIL questionnaires, regulator notifications), `XTHREAT` (ATT&CK / ATLAS /
D3FEND, IOCs, threat model), `XINCIDENT`, `XOVAL`, `XATTACK` (CAPEC), `XID`, `XWINDOWS`,
`XMALWARE`.

Canonical DDL for the main databases lives in [`databases/`](../databases) (`*_sqlite.sql`).

## Structure

```
xorcism_ts/
├── server/
│   ├── index.ts            # Express entry point (port 9292), page routes, boot-time table setup
│   ├── db.ts               # SQLite connection pool + all query/aggregation logic
│   ├── auth.ts             # sessions, RBAC (userCan), tenant scoping, hidden-table rules
│   ├── routes/
│   │   ├── explorer.ts     # /api/databases, /api/tables, /api/rows, /api/insert, dashboard…
│   │   ├── bia.ts          # /api/bia/*  (Business Impact Analysis)
│   │   ├── ocil.ts         # /api/ocil/* (questionnaires)
│   │   ├── notifications.ts # /api/notifications/*
│   │   ├── auth.ts oidc.ts vault.ts admin.ts connectors.ts feedback.ts
│   │   └── agent.ts circl.ts osv.ts pentest.ts screenshot.ts upload.ts worker_api.ts
│   └── types/index.ts
├── client/
│   ├── index.html          # database explorer        dashboard.html  bia.html
│   ├── attack.html         # MITRE ATT&CK / ATLAS      d3fend.html     stix-graph.html
│   ├── threat-feeds.html   admin.html connectors.html login/register/forgot/reset/vault…
│   ├── css/style.css
│   └── ts/
│       ├── api.ts          # typed fetch client
│       ├── app.ts          # explorer logic (schema-driven forms & grids)
│       ├── dashboard.ts bia.ts attack.ts d3fend.ts stix-graph.ts i18n.ts theme.ts rte.ts …
├── start.ps1               # all-in-one startup script
├── esbuild.config.js       # client bundler config (one entry per page)
├── package.json
├── tsconfig.json           # client config (type-check)
└── tsconfig.server.json    # server config (tsc → dist/server, CommonJS)
```

## Getting started

```powershell
# From xorcism_ts/
.\start.ps1
```

The script:
1. Adds portable Node.js to `PATH`
2. Installs npm dependencies if needed
3. Builds the server (`tsc`) and the client (esbuild)
4. Starts the server at http://localhost:9292

Manual build:

```powershell
npm run build          # build:server (tsc) + build:client (esbuild)
npm run build:server   # tsc -p tsconfig.server.json  → dist/server
npm run build:client   # node esbuild.config.js        → dist/client/js
npm start              # node dist/server/index.js
```

## Pages

| URL | Page |
|---|---|
| `/` | Database explorer |
| `/dashboard` | Dashboard (risk score, vulnerabilities, financial value, **risk exposure = risk × value**, asset tag cloud, incidents) |
| `/bia` | Business Impact Analysis |
| `/attack` | MITRE ATT&CK matrix (Enterprise / Mobile / ICS / **ATLAS**) |
| `/d3fend` | MITRE D3FEND matrix (defensive countermeasures, with ATT&CK mappings) |
| `/stix-graph` | STIX relationship graph (nodes link back to the matching forms) |
| `/threat-feeds` | Threat feeds |
| `/connectors` | Connectors |
| `/admin` | Administration (users, broadcast notifications…) |
| `/login` `/register` | Authentication (password + passkeys/WebAuthn) |

## REST API (selected)

### Explorer
| Method | Route | Description |
|---|---|---|
| GET | `/api/databases` | List databases |
| GET | `/api/tables?db=X` | Tables of a database |
| GET | `/api/schema?db=X&table=Y` | Table schema |
| GET | `/api/rows?db=X&table=Y&limit=N&offset=N&sort=col&dir=asc` | Paginated rows |
| GET | `/api/export?db=X&table=Y` | Export (up to 50,000 rows) |
| POST | `/api/insert` | Insert a row |
| POST | `/api/delete` | Delete by rowid |
| GET | `/api/row-by-id`, `/api/lookup-many` | Resolve FK labels |

### Dashboard
| Method | Route | Description |
|---|---|---|
| GET | `/api/dashboard/asset-risk-exposure` | RiskScore × FinancialValue per asset |
| GET | `/api/dashboard/tag-cloud` | Active asset tags |
| GET | `/api/dashboard/*` | risk score, vulnerabilities, financial, incidents… |

### Matrices
| Method | Route | Description |
|---|---|---|
| GET | `/api/attack/matrix?domain=enterprise\|mobile\|ics\|atlas` | ATT&CK / ATLAS matrix |
| GET | `/api/d3fend/matrix` | D3FEND matrix + ATT&CK mappings |

### BIA
| Method | Route | Description |
|---|---|---|
| GET/POST/PATCH/PUT/DELETE | `/api/bia/audits[/:id]` | BIA audits |
| GET/POST/PUT/DELETE | `/api/bia/entries[/:id]` | BIA entries |
| GET | `/api/bia/asset-names` | Distinct ASSET.AssetName (datalist) |
| GET | `/api/bia/assets?q=` · `/api/bia/persons?q=` | Autocomplete |

Other routers: `auth`, `oidc`, `ocil`, `notifications`, `vault`, `connectors`, `feedback`,
`agent`, `circl`, `osv`, `pentest`, `screenshot`, `upload`, `worker_api`.

## Python importers

Reference-data importers live in [`xorcism_python/importers/`](../xorcism_python/importers)
(stdlib `sqlite3` / SQLAlchemy + `requests`; DB paths from `xorcism_python/config.py`):

| Importer | Source → target |
|---|---|
| `import_attack.py` | MITRE ATT&CK STIX (Enterprise/Mobile/ICS/**ATLAS**) → `XTHREAT.ATTACK*` |
| `import_attack_evals.py` | MITRE ATT&CK Evaluations → OCIL model in `XCOMPLIANCE` |
| `import_d3fend.py` | MITRE D3FEND ontology + inferred mappings → `XTHREAT.D3FEND*` **and** `XORCISM.CONTROL` |
| `import_capec.py` | MITRE CAPEC XML → `XATTACK` (+ `XORCISM` vocabularies) |
| `import_controls.py` `import_iso27001.py` `import_nist800-53.py` `import_cce.py` | Control frameworks → `XORCISM.CONTROL` |
| `import_nvd_cve.py` `import_vulnerabilities.py` `import_KEV.py` `import_cisa_kev.py` | CVE / KEV → `XVULNERABILITY` |
| `import_oval.py` `import_maec.py` `import_threatevent.py` `import_vulnerabilitydomains.py` | OVAL / MAEC / threat events / domains |

Example:

```powershell
py -3 xorcism_python\importers\import_d3fend.py            # downloads + imports D3FEND
py -3 xorcism_python\importers\import_attack.py --domain atlas
```

## Security model

- Session-based auth; passkeys (WebAuthn) verified server-side (ES256/RS256).
- Role-based access control (`userCan`) and per-tenant row scoping.
- Some tables are hidden from non-admin users (see `auth.ts`).
