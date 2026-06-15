# XORCISM — Release Notes

---

## v1.0.0-beta — First public release (beta)

**Release date:** 2026-06-15
**Status:** Public beta · self-hosted · open-source

This is the **first major public release** of **XORCISM**, an open, unified
cybersecurity management platform — *Global Cyber Risk Exposure*. It brings the
whole cyber-exposure lifecycle (assets, configuration, vulnerabilities, threats,
compliance and incidents) into one schema-driven application over a family of
SQLite databases, and turns it into a single, continuously-recomputed
**enterprise risk score**.

Everything in this release is new — there is no prior public version. The notes
below describe the capabilities shipped in `v1.0.0-beta`.

> ⚠️ **Beta software.** XORCISM is feature-complete for an early-adopter
> release but still maturing. Run it in a lab or internal environment, keep
> backups of your `DB_DIR`, and read the [Security notes](#security-notes) and
> [Known limitations](#known-limitations) before any production use.

---

### Highlights

- **One platform, one risk model.** Assets, vulnerabilities and business value
  combine into a per-asset `RiskScore` and a per-tenant `EnterpriseRiskScore`,
  recomputed every 30 seconds.
- **Schema-driven explorer.** Every database table gets a generated form and
  grid; add a table and it shows up in the UI after a restart — no code.
- **Standards built in.** MITRE ATT&CK / ATLAS / D3FEND / CAPEC, STIX/TAXII 2.1,
  OVAL, OCIL, EBIOS Risk Manager, CVE / KEV / CVSS / EPSS, and GRC frameworks.
- **27 security connectors** plus a remote-worker model for distributed scanning.
- **Multi-tenant + RBAC**, passkeys (WebAuthn) and optional OIDC SSO.
- **10 UI languages**, including RTL Arabic.
- **Fully self-hosted** — no SaaS, no telemetry; your data never leaves your
  infrastructure.

---

### What's included

#### Exposure management (VOC / CTEM)
- **Asset Management** — inventory, owners, business/financial value, tags and
  exposure; per-asset risk scoring with history.
- **Configuration Management** — CPE naming and **OVAL** definitions/audits.
- **Vulnerability Management** — CVE with **KEV**, **CVSS** and **EPSS**; CIRCL
  and OSV lookups; SOCRadar IOC-Radar deep-link for CVE references; **bug-bounty**
  program & submission tracking.
- **Executive Dashboard** — enterprise risk score, vulnerability breakdown,
  financial value, **risk exposure = risk × value**, asset tag cloud and incident
  trends (Chart.js).

#### Governance, Risk & Compliance (GRC)
- **Compliance** — policy/standard/procedure lifecycle; audits, evidence,
  readiness; **findings workflow**; **CRQ / FAIR** quantitative risk on the
  register. Frameworks: ISO 27001, NIST CSF, NIST 800-53, CIS Controls, NIS2,
  DORA, CRA, SOC 2.
- **EBIOS Risk Manager** — the full 5-workshop ANSSI method with an **Express
  mode**, business values, supporting assets, feared events (DICT), risk sources,
  and an **ecosystem of stakeholders with auto-computed threat levels & zones**.
- **TPRM** — third-party / supplier risk assessments and questionnaires.
- **OCIL questionnaires** — OCIL 2.0-compatible authoring, XML import/export and
  an optional AI "suggest answer".
- **Business Impact Analysis (BIA)** — audits & entries with editable asset
  datalists.

#### Threat & detection
- **Threat Management (CTI)** — STIX entities (actors, malware, tools, campaigns,
  indicators, observables) with OpenCTI-style common properties (Confidence, TLP,
  Labels, Score), **sightings** and **relationships**; **hunts** and **hypotheses**.
- **MITRE matrices** — **ATT&CK** (Enterprise / Mobile / ICS / **ATLAS**),
  **D3FEND** defensive countermeasures (mapped to ATT&CK and `XORCISM.CONTROL`),
  and **A3M — Agentic AI Attack Matrix**.
- **Adversary emulation (BAS)** — emulation plans, atomic tests & executors, and
  an **ATT&CK coverage heatmap** overlaid on the matrix.
- **STIX relationship graph** — interactive graph linking hunts ↔ techniques ↔
  actors; nodes deep-link back to their forms.
- **Threat Modeling** — STRIDE scope, assets, threats and controls.
- **Incident Management & Ticketing** — alerts, incidents, tasks, comments and
  attachments.

#### Integrations & automation
- **27 connectors** — tool-runners (nmap, nuclei, nikto, sqlmap, whatweb, wpscan,
  w3af, OpenVAS) and API imports (Nessus, Qualys, Rapid7, Caldera,
  Dependency-Track, OSV-Scanner, depx, Wiz, Lacework, Sysdig, Aikido, Burp Suite,
  Metasploit, Splunk, Elastic Security, Microsoft Sentinel, QRadar, SAINT).
- **Remote workers** — run connectors on a separate host (e.g. a Kali VM) over a
  worker token; normalized results import centrally.
- **TAXII 2.1 server** — publish/consume STIX feeds.
- **Local AI (Ollama)** — "Ask the threat model" (RAG over your own data) and OCIL
  answer suggestions, fully offline.
- **Reference-data importers** — ATT&CK, D3FEND, CAPEC, CVE/NVD, KEV, ISO 27001,
  NIST 800-53, CCE, OVAL, MAEC, Atomic Red Team, A3M, hunts.

#### Security & identity
- Session-based auth; **passkeys (WebAuthn)** verified server-side (ES256/RS256);
  optional **OIDC** SSO.
- **RBAC** (`userCan`) and **per-tenant row scoping** (multi-tenant by design).
- **Field-encryption vault** (passphrase-wrapped data key, one-time recovery key).
- **Anti-automation** guard on the authenticated app; hidden admin-only tables.

#### UX & accessibility
- **10 UI languages** with strict key parity — English, Français, Deutsch,
  Italiano, Español, Português, 中文, 日本語, العربية (RTL), Русский.
- Theme system (CSS variables + `data-theme`), dark themes.
- Schema-driven forms with FK pickers, inline "+ create" records, date pickers,
  static datalists, checkbox columns, Excel import and rich-text fields.

---

### Platform & technology

| Layer | Technology |
|---|---|
| Server | Node.js 20 + Express 4 + TypeScript (CommonJS) |
| Database | better-sqlite3 (synchronous, no ORM) — a family of SQLite files |
| Client | TypeScript bundled with esbuild (one entry per page) |
| Tooling | Python 3.11 + SQLAlchemy 2 (importers), Flask (TAXII), PHP 8 (forum) |
| Local AI | Ollama (optional, offline) |
| Deployment | Docker + Compose, or portable Node 20 |

Default HTTP port: **9292**. Databases auto-created on first start in `DB_DIR`.

---

### Getting started

```powershell
cd xorcism_ts
npm install
npm run build
$env:DB_DIR = "C:\Users\$env:USERNAME\XORCISM_databases"   # keep DB outside OneDrive
npm start
# → http://localhost:9292/login  (one-time admin password printed in the console)
```

Or with Docker:

```bash
docker compose up -d --build      # → http://localhost:9292/login
```

See **[SETUP.MD](SETUP.MD)** for the full guide and **[REQUIREMENTS.MD](REQUIREMENTS.MD)**
for dependency versions. The first start creates all databases and prints a
one-time admin account you must change at first login.

---

### Security notes

- **Do not expose the authenticated app directly to the internet.** Put it behind
  an HTTPS reverse proxy and restrict access; the in-app anti-automation guard and
  the showcase website's controls are not a substitute for network hardening.
- **Keep `DB_DIR` outside OneDrive / any synced folder.** Sync tools replace files
  under open handles and corrupt SQLite WAL journals.
- **Connector credentials are configured via environment variables only**, never
  typed into the UI.
- **Only run offensive/scanning connectors against systems you are authorized to
  test.**
- Change the seeded admin password at first login; back up the vault recovery key
  offline if you enable field encryption.

---

### Known limitations

- **Beta quality** — expect rough edges; APIs and schemas may change before
  `v1.0.0` final.
- **Windows-first.** Primary development and testing target is Windows; Docker
  provides a Linux runtime but has had lighter testing.
- **Node 20 required at runtime** — `better-sqlite3` is a native module and its
  ABI breaks on Node 23+/24. Use Node 20 LTS (or the bundled portable runtime).
- **SQLite single-node** — great for a team/instance; not designed for
  high-concurrency clustering.
- **Reference data is not bundled.** Schema databases start empty; load standards
  (ATT&CK, CVE, CAPEC, OVAL…) with the importers, which download large datasets.
- **AI features require a local Ollama instance.**
- **No `LICENSE` file yet** — licensing terms are published at
  [xorcism.ai](https://xorcism.ai); a `LICENSE` file will be added.

---

### Standards & frameworks integrated

MITRE ATT&CK® · ATLAS · D3FEND™ · CAPEC™ · EBIOS Risk Manager (ANSSI) ·
STIX/TAXII 2.1 (OASIS) · OVAL · OCIL · CVE / KEV / CVSS / EPSS ·
ISO 27001 · NIST CSF · NIST 800-53 · CIS Controls · NIS2 · DORA · CRA · SOC 2.

> XORCISM is **not affiliated with, endorsed by, or sponsored by** MITRE, ANSSI,
> OASIS or any framework owner. All trademarks belong to their respective holders.

---

### Links

- 🌐 Website — https://xorcism.ai
- ▶ YouTube channel — https://www.youtube.com/channel/UCk6OWxMBg1H4gHTZdpZGAhA
- 📖 Installation — [SETUP.MD](SETUP.MD) · 🧩 Requirements — [REQUIREMENTS.MD](REQUIREMENTS.MD)
- 📦 Release packaging — [Github.txt](Github.txt)

---

*Thank you for trying XORCISM. Feedback and issues are welcome — they shape the
road to `v1.0.0`.*
