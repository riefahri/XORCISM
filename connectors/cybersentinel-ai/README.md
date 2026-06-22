# CyberSentinel AI connector

Imports findings from **[CyberSentinel AI](https://github.com/3sk1nt4n/cybersentinel-ai)** —
an agentic, fully-local AI-driven security platform that orchestrates 33 tools (Nmap, Nuclei,
Nikto, SQLMap, Shodan, VirusTotal…) in a Kali sandbox, analyzes the real results with a local
LLM (Ollama), and maps findings to MITRE ATT&CK in a Neo4j knowledge graph.

## Mapping → XORCISM (`{assets, services, cpes, vulns}` → `import_findings`)

| CyberSentinel output | XORCISM |
| --- | --- |
| scanned target host / URL | `ASSET` (host) |
| discovered service / open port | component / CPE on the asset |
| vulnerability / finding (CVE + severity, ATT&CK-tagged) | `VULNERABILITY` (CVE ref or title + severity; `[T####]` appended) |

## Modes

- **Offline (recommended):** run a scan in the CyberSentinel dashboard, export the results JSON,
  and import it with the `file` parameter.

  ```bash
  python run.py --file cybersentinel_results.json
  ```

- **Live:** set `target` (host/URL) and `api_base` (default `http://localhost:8000`). The connector
  POSTs a scan request to the CyberSentinel FastAPI backend and imports the returned JSON. `api_key`
  is sent as a bearer token when set. Live mode is **active/intrusive** and requires the target to be
  within the engagement scope (ROE), like every active connector.

The JSON is parsed defensively (per-tool sections, nested findings, or a recursive walk that attaches
each finding to the nearest host on its path), so it tolerates schema drift across CyberSentinel
versions. `run.py` performs **no database access** (worker-safe).

## Attack chains

`cybersentinel-ai` is wired into the **Full external pentest** and **Web app assessment** playbooks
(`chain.ts`) as an *AI deep-analysis* step: when a vulnerability is found, CyberSentinel is launched
against the host/URL for AI-driven triage and MITRE ATT&CK mapping.
