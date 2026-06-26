# XORCISM Connectors — Architecture & Tool Catalog

Goal: turn XORCISM into an offensive/defensive **TDIR / XTM-style platform** where
the web UI can **launch security tools** (with chosen parameters), **parse** their
results, and **import** them into the XORCISM databases — through a pluggable
**connector (integration)** model inspired by **OpenCTI connectors** and
**Filigran's XTM Hub / XTM One**.

> ⚠️ **Authorized use only.** The tool-runner connectors execute active security
> tools. They must run only against targets that are **in scope** of an
> authorized engagement (pentest / red team / lab). The framework enforces RBAC,
> per-engagement scope, and full audit. See [§7 Security](#7-security--authorization).

---

## 1. Vision

| Filigran / OpenCTI | XORCISM equivalent |
|---|---|
| **OpenCTI** (CTI knowledge base) | XORCISM databases (assets, vulns, threats, incidents…) |
| **OpenBAS / OpenAEV** (breach & attack simulation) | XORCISM "engagements" + tool-runner connectors |
| **XTM Hub** (catalog of connectors & content) | XORCISM **Connector Registry** (manifests) |
| **XTM One** (managed, integrated XTM) | XORCISM packaged on Kali (web + runner + tools) |
| OpenCTI **connectors** (import / enrichment / stream) | XORCISM **connectors** (import / enrichment / **tool-runner** / export) |

XORCISM already has the building blocks: a database layer, a generic
import/insert API, Python importers, a **STIX/TAXII** server + client, and a
**STIX graph** visualization. Connectors add the "do something, then ingest the
result" loop.

---

## 2. Connector types

Mirroring OpenCTI, plus an active "tool-runner" type:

1. **External Import** — pull data from an external source on a schedule or on
   demand (CVE/NVD, MITRE ATT&CK, MISP, OTX, feeds…). *(XORCISM already has
   importers: CAPEC, CCE, OVAL, MAEC, NVD CVE, NIST 800-30…)*
2. **Internal Enrichment** — enrich an existing entity on demand (right-click an
   ASSET → run nmap/whois/shodan and attach results).
3. **Tool-Runner (active)** — run a Kali tool with parameters, capture output,
   parse, import. *(the focus of this request: nmap, nuclei, nikto, …)*
4. **Stream / Export** — push XORCISM data out (e.g., to the built-in **TAXII**
   server, to MISP, to a SIEM).

All four share the same **manifest + runner + parser + importer** pipeline.

---

## 3. Connector manifest

A connector is declared by a JSON manifest (`connectors/<id>/connector.json`),
validated against `connectors/manifest.schema.json`. The web UI renders a form
from `parameters`; the runner builds an **argv array** from `command` (never a
shell string → no injection).

```jsonc
{
  "id": "nmap",
  "name": "Nmap — Network & service scan",
  "type": "tool-runner",
  "category": "recon",
  "binary": "nmap",
  "intrusive": true,                 // requires confirmation + in-scope target
  "permission": "connector:nmap",    // RBAC permission key
  "parameters": [
    { "name": "target", "type": "target", "required": true, "help": "host / CIDR / range" },
    { "name": "ports",  "type": "string", "default": "top-1000" },
    { "name": "scan",   "type": "enum", "values": ["-sS","-sT","-sV","-A"], "default": "-sV" },
    { "name": "timing", "type": "enum", "values": ["-T2","-T3","-T4"], "default": "-T3" }
  ],
  // argv template; {{param}} substituted with VALIDATED values (array-safe)
  "command": ["nmap", "{{scan}}", "{{timing}}", "-p", "{{ports}}", "-oX", "{{outfile}}", "{{target}}"],
  "output": { "kind": "file", "ext": "xml" },     // or {"kind":"stdout"}
  "parser": "parse_nmap.py",                       // produces a normalized result
  "mapping": "nmap"                                // → XORCISM entities (see §6)
}
```

Parameter `type`s: `string`, `int`, `bool`, `enum` (allowlist), `target`
(host/CIDR/range — validated **and** checked against the engagement scope), `url`
(http(s) URL — the **hostname** is extracted and checked against the scope),
`file` (a report/SBOM path on the worker). Validation is strict; only declared
params are accepted.

### `import` connectors (no shell tool)

Besides `tool-runner` (argv + subprocess), a connector may be `type: "import"`.
Instead of `command`/`parser` it declares `run: "run.py"` exposing
`run(params, workdir) -> normalized result`. Use it for **report file imports**
(`.nessus`, GVM XML, CycloneDX SBOM, Metasploit `db_export`…) and **vendor APIs**
(Dependency-Track, Qualys, Rapid7, Burp). API credentials are read **only** from
environment variables on the worker — never entered in the UI. Both types feed the
same generic mapping (`import_findings`, see §6).

---

## 4. Execution architecture

```
 Web UI (TS)                Web server (Express)            Connector Runner (Python)
 ┌───────────┐   POST /api/connectors/run    ┌──────────┐   job (validated)   ┌─────────────┐
 │ Connectors│ ───────────────────────────▶ │ jobs API │ ─────────────────▶ │  runner     │
 │  page     │   GET  /api/connectors        │ + store  │                    │  - build argv│
 │  (form)   │   GET  /api/jobs/:id (poll)   │ (XJOB db)│ ◀───status/logs─── │  - subprocess│
 │  live log │ ◀──────────────────────────── └──────────┘                    │  - parse     │
 └───────────┘                                                                │  - import → DBs
                                                                              └─────────────┘
```

- **Connector Registry**: server reads manifests → `GET /api/connectors`
  (list + parameter schema). UI renders a "Connectors" page (cards by category)
  and a parameter form per connector.
- **Job store** (`XJOB.db`, or a table in XID): `JobID, connector, params(json),
  status(queued|running|done|failed|canceled), target, started, finished,
  exit_code, stdout_path, result_summary(json), user_id, engagement_id`.
- **Runner** (Python service/worker): polls the job store (or receives a push),
  validates params **again** against the manifest, builds the argv, runs the
  tool with `subprocess` (no shell), streams stdout/stderr to a log file,
  captures the output file, runs the **parser**, then **imports** via the
  existing XORCISM import path. Updates job status + summary.
- **Live feedback**: UI polls `GET /api/jobs/:id` (status + tail of log) — same
  pattern as the TAXII `manager.py` console.

Why a separate Python runner? Tools are CLI, parsers are Python, and XORCISM's
importers/SQLAlchemy models are Python. The TS server orchestrates; Python does
the dirty work — clean separation and reuse.

---

## 5. Result parsing

Each parser turns raw tool output into a **normalized result** (a list of typed
records) that the importer maps to XORCISM rows and/or **STIX objects**:

```python
# parser contract
def parse(path_or_text: str, params: dict) -> dict:
    return {
        "assets":     [ {...} ],   # hosts found
        "services":   [ {...} ],   # open ports / services
        "cpes":       [ "cpe:2.3:..." ],
        "vulns":      [ {"ref": "CVE-…", "severity": "...", "asset": "..."} ],
        "stix":       [ {...} ],   # optional STIX objects (→ TAXII / STIX graph)
        "raw_report": "<path>"     # keep the original artifact
    }
```

Importers reuse what already exists:
- **XORCISM rows** → the generic `/api/import` (or `insertRow`) into ASSET,
  ASSETADDRESS, CPE, CPEFORASSET, VULNERABILITY, ASSETVULNERABILITY, INCIDENT…
- **STIX objects** → the XTHREAT `RELATIONSHIP` table + the TAXII project graph,
  or POST to the TAXII server (`taxii_client.py`).
- The original report file is stored as an **artifact** (linked to the job).

---

## 6. Mapping to the XORCISM schema (examples)

| Tool finding | XORCISM target |
|---|---|
| Host (IP/hostname, OS) | `ASSET`, `ASSETADDRESS`, `ASSETGEOLOCATION` |
| Open port / service / banner | service/port tables, `ASSET` ↔ service |
| CPE (product) | `CPE`, `CPEFORASSET` |
| Vulnerability (CVE / template id) | `VULNERABILITY` (+ `VULReferentialID`, `VULDomain`, `Tier`), `ASSETVULNERABILITY` |
| Credential found | `ACCOUNT` / credential tables |
| Subdomain / DNS / org | `ASSET` (domain), `ORGANISATION` |
| Web finding (path, tech) | `ASSET` + `CPE` (tech), finding tables |
| AD graph (BloodHound) | assets + identities + **STIX relationships** (threat graph) |

Deterministic IDs (as in the TAXII project backend) keep imports idempotent and
correlatable across runs.

---

## 7. Security & authorization

This is the part that must be right.

- **RBAC**: each connector has a `permission` key; running it requires that CRUD
  permission (admin-gated by default). Reuse XORCISM's XPERMISSION model.
- **Engagement scope (authorization)**: a `target`-typed parameter is checked
  against the **in-scope list of the active engagement** (allowed hosts/CIDRs).
  Out-of-scope targets are rejected — prevents arbitrary/unauthorized targeting.
- **No shell**: commands are **argv arrays**; parameters are validated/typed and
  substituted as array elements (no `sh -c`, no string concatenation) → no
  command injection. `enum` params are allowlists.
- **Intrusive flag**: `intrusive: true` connectors require explicit confirmation
  and an in-scope target; rate-limited.
- **Isolation**: run the runner as a low-privilege user; optionally inside a
  container / network namespace; per-job working directory.
- **Audit**: every run logged (user, connector, params, target, exit code) in
  the XORCISM audit log; results linked to the job.
- **Rules of Engagement**: an engagement carries ROE metadata (window, scope,
  client authorization reference). The platform is a **professional pentest
  orchestration tool**, not for unauthorized or mass targeting.

---

## 8. Deployment on Kali Linux

- Package: `xorcism_ts` (web, Node) + `xorcism_python` (models/importers) +
  `connectors/` (manifests, parsers, runner). Tools come from Kali.
- A `systemd` unit (or a launcher script) starts: the web server, the connector
  runner, and (optionally) the TAXII server.
- Databases live **outside** any synced folder (already enforced via `DB_DIR`).
- `manifest`-declared `binary` is resolved on `PATH` (Kali has the tools);
  missing binaries → the connector shows as "unavailable" in the registry.
- Optional `.deb` / install script for one-shot setup on Kali.

---

## 9. Tool catalog (candidates for connectors)

Output column = the machine-readable format the parser consumes.

### Recon / OSINT
| Tool | Invocation (key flags) | Output | → XORCISM |
|---|---|---|---|
| **nmap** | `-sV -oX out.xml` | XML | ASSET, ports/services, CPE, OS |
| **masscan** | `-oJ out.json` | JSON | ASSET, ports |
| **dnsx / dnsrecon** | `-json` / `-x` | JSON/XML | ASSET (domain), DNS |
| **amass** | `enum -json out.json` | JSON | subdomains, infra |
| **theHarvester** | `-f out.xml` | XML/JSON | emails, hosts, ORGANISATION |
| **whois** | stdout | text | ORGANISATION / registrant |
| **subfinder** | `-oJ` | JSONL | subdomains |
| **shodan** (API) | API | JSON | exposed services, CPE |

### Vulnerability scanning
| Tool | Invocation | Output | → XORCISM |
|---|---|---|---|
| **nuclei** | `-jsonl -o out.jsonl` | JSONL | VULNERABILITY (CVE/template), severity, ASSETVULNERABILITY |
| **OpenVAS / Greenbone** | report export | XML | VULNERABILITY (CVE), severity |
| **Nessus** | `.nessus` export | XML | VULNERABILITY *(provider_nessus.py exists)* |
| **nikto** | `-Format json -o out.json` | JSON | web vulns |
| **wpscan** | `--format json` | JSON | WordPress vulns |
| **testssl.sh / sslscan** | `--jsonfile` / `--xml` | JSON/XML | TLS findings |

### Web app
| Tool | Invocation | Output | → XORCISM |
|---|---|---|---|
| **httpx** | `-json` | JSONL | live hosts, tech (CPE) |
| **whatweb** | `--log-json` | JSON | tech fingerprint → CPE |
| **gobuster / ffuf** | `-o out.json` | JSON | discovered paths |
| **sqlmap** | `--results-file` / `-oD` | CSV/dir | SQLi findings |
| **OWASP ZAP** | API / report | JSON/XML | web vulns |
| **Burp** | REST API | JSON | web vulns |

### Network / AD / exploitation (intrusive — strong gating)
| Tool | Invocation | Output | → XORCISM |
|---|---|---|---|
| **netexec (nxc) / crackmapexec** | `--json` | JSON | SMB/AD enum, ACCOUNT |
| **enum4linux-ng** | `-oJ` | JSON | users, shares |
| **hydra** | `-o out.json` | JSON | credentials → ACCOUNT |
| **BloodHound / SharpHound** | `-c All` (JSON) | JSON | AD assets/identities + **STIX relationships** |
| **metasploit** | `msfrpcd` RPC / `db_export` | XML/JSON | sessions, findings |
| **responder** | logs | text | captured hashes *(handle with care)* |

### Adversary emulation (purple team)
| Tool | Invocation | Output | → XORCISM |
|---|---|---|---|
| **MITRE Caldera** | REST API v2 (`CALDERA_URL` + `CALDERA_API_KEY`) | JSON | ASSET (agents), executed abilities → findings (ATT&CK technique linked to host) *(connectors/caldera, read-only)* |

### Import / enrichment (non-active)
MITRE ATT&CK, MISP, OTX, NVD, EPSS, KEV, GreyNoise, VirusTotal, AbuseIPDB…

---

## 10. Phased roadmap

1. **Foundation** — manifest schema, registry API (`GET /api/connectors`), job
   store (`XJOB`), RBAC permission keys, audit. (No execution yet.)
2. **Runner + first connector** — Python runner (argv, subprocess, logs) + the
   **nmap** connector end-to-end (run → parse XML → import ASSET/CPE/services).
   Web "Connectors" page with a parameter form + live job log.
3. **Engagement & scope** — engagements with in-scope target lists; enforce on
   `target` params; ROE metadata.
4. **More connectors** — nuclei (vulns), httpx/whatweb (tech→CPE), Nessus/OpenVAS
   import, BloodHound → STIX graph.
5. **Enrichment hooks** — "right-click an ASSET → enrich with nmap/whois/shodan".
6. **Export/stream** — push to the built-in TAXII server / MISP / SIEM.
7. **Packaging** — Kali `.deb` / installer + `systemd` units.

The **nmap** connector (manifest + parser) is scaffolded under `connectors/nmap/`
as the reference implementation.

---

## 11. Implemented connectors (this build)

All produce the same normalized result and feed `import_findings` (§6). Severity
is carried into `VULDescription`; CVE is used as `VULGUID` when present, otherwise
a tool-specific id (`NESSUS:<pluginID>`, `NVT:<oid>`, `QID:<id>`, `BURP:<name>`…).

| Connector | Type | Category | Input | Notes |
|---|---|---|---|---|
| **nmap** | tool-runner | recon | `-oX` XML | ASSET/services/CPE (+CVE via vulners NSE) |
| **nuclei** | tool-runner | vuln | JSONL | VULNERABILITY + ASSETVULNERABILITY |
| **whatweb** | tool-runner | web | `--log-json` | tech fingerprint → CPE |
| **sqlmap** | tool-runner | web | stdout | SQLi injection points → VULNERABILITY (`url` param) |
| **w3af** | import | web | XML report | web findings |
| **nessus** | import | vuln-scanner | `.nessus` | hosts + findings (CVE/plugin) |
| **openvas** | import | vuln-scanner | GMP XML | results (CVE/NVT) |
| **saint** | import | vuln-scanner | XML report | best-effort (adjust `_field`) |
| **metasploit** | import | exploitation | `db_export -f xml` | hosts/services/vulns (CVE) |
| **dependency-track** | import | sbom | CycloneDX JSON | components→CPE/PURL, vulns; optional DT API |
| **qualys** | import (API) | vuln-management | VMDR API | `QUALYS_API_URL/USER/PASSWORD` |
| **rapid7** | import (API) | vuln-management | InsightVM v3 API | `R7_API_URL/USER/PASSWORD` |
| **burpsuite** | import (API) | web | Burp Pro REST | `BURP_API_URL/API_KEY` |

Each connector ships a `sample.*` file; validate parsing/import without a tool:

```bash
python connectors/runner.py --selftest connectors/nessus/sample.nessus --connector nessus
python connectors/runner.py --selftest connectors/dependency-track/sample.cdx.json --connector dependency-track
```

### SBOM handling

`dependency-track` reads a **CycloneDX** SBOM: `components[]` (name/version/purl/cpe)
become CPE entries linked to the application asset (`metadata.component.name`), and
any `vulnerabilities[]` become VULNERABILITY rows. With `api=true` and
`DTRACK_URL`/`DTRACK_API_KEY` set, it uploads the SBOM to Dependency-Track and pulls
the computed findings instead.

---

## 12. Remote workers (distributed agents)

XORCISM can drive **remote workers** (e.g. Kali VMs) that execute tools where the
tools and the targets live, while the central server keeps the queue, the
engagement scope and the database.

```
 Web UI ──run(worker=kali-01)──▶ XJOB (worker='kali-01', status=queued)
                                        │
 kali-01:  runner.py --remote URL --token T --name kali-01
   └ POST /api/worker/claim  (Bearer token) ──▶ claims queued jobs for kali-01
   └ runs tool LOCALLY (no DB access), parses → normalized result
   └ POST /api/worker/job/:id/result ──▶ status='collected' (+live log)
                                        │
 central runner.py (DB access): claims 'collected' ──▶ import_findings ──▶ status='done'
```

- **Tokens**: an admin creates a worker in the Connectors page → a bearer token is
  shown **once**; it is stored only as a SHA-256 hash (`XWORKER`). The remote runner
  uses it via `--token`. Delete the worker to revoke.
- **Authorization is unchanged**: the engagement scope is still enforced at the API
  when the job is created, and a `target`/`url` job carries its engagement. Remote
  agents never bypass scope — they only run what the server queued for them.
- **Separation**: the local runner claims only unassigned (`worker IS NULL`) or
  `local` jobs and never steals a remote's jobs; a remote claims only jobs assigned
  to its name. Import always happens centrally (single DB writer).
- **Capabilities**: a worker may be restricted to a connector allowlist
  (`--capabilities nmap,nuclei`), enforced server-side at claim time.

### Run on a Kali agent

```bash
# central host
node xorcism_ts/dist/server/index.js          # web + queue + DB writer
python connectors/runner.py                   # local runner (runs 'local' jobs + imports remote results)

# remote Kali VM (only needs the connectors/ folder + python + the tools)
python connectors/runner.py --remote https://xorcism.lab:9292 \
       --token <worker-token> --name kali-01 --capabilities nmap,nuclei,whatweb,sqlmap
```
