# Agentless & offline host scan (credentialed)

A **Cyberwatch-style credentialed agentless scan** for XORCISM. Instead of deploying an agent, an admin
session (**SSH** on Linux/Unix, **WinRM/PowerShell** on Windows) — or an **air-gapped collector** for
segregated networks (*mode déconnecté*) — reads the host into a JSON snapshot, which this connector turns
into an asset + software inventory + detected CVEs + a security-baseline (hardening) result.

This adds the one acquisition method XORCISM didn't have; everything downstream (CVE prioritization with
EPSS/KEV/SSVC/Exploit-DB, patch management, exposure & attack-path) already exists and lights up automatically.

## 1 · Collect (no agent, read-only)
**Linux / Unix** — [`collect.sh`](collect.sh):
```sh
sh collect.sh > snapshot.json                      # locally / on an air-gapped host
ssh user@host 'sh -s' < collect.sh > snapshot.json # over an admin SSH session (agentless)
```
**Windows** — [`collect.ps1`](collect.ps1):
```powershell
powershell -ExecutionPolicy Bypass -File collect.ps1 > snapshot.json          # locally / air-gapped
Invoke-Command -ComputerName host -FilePath collect.ps1 | ConvertTo-Json -Depth 6 > snapshot.json  # WinRM
```
Many hosts: wrap the per-host snapshots as `{"hosts":[ <snap1>, <snap2>, ... ]}`.

The snapshot shape (also writable by your own CMDB/SSH automation):
```json
{ "hostname":"web01", "ip":"10.0.0.20",
  "os":{"family":"linux","name":"ubuntu","version":"22.04","kernel":"5.15.0"},
  "packages":[{"name":"openssl","version":"3.0.2"},{"name":"nginx","version":"1.18.0"}],
  "listening":[{"port":443,"proto":"tcp","service":"nginx"}],
  "checks":[{"id":"sshd-permitrootlogin","title":"SSH root login disabled","result":"fail","severity":"high"}],
  "cves":[] }
```

## 2 · Import & map
`python connectors/runner.py --connector agentless-scan --file snapshot.json`

- host → **ASSET** (key = hostname; tags `agentless` / `host` / `<os family>` / `<os name>`; carries `ip`, `os`)
- OS + each installed package → a **CPE** linked to the asset (emitted as `services[{asset,cpe}]`). The
  platform's **cvematch** runs post-import and detects every affected **CVE** — agentless detection, no probing.
- listening ports → **service facts**
- failed baseline checks → **hardening VULNs** + a per-host **"Hardening level: N%"** summary (Compliance Manager)
- CVEs already in the snapshot → **VULNs** directly

CPEs are built `cpe:2.3:a:<vendor>:<product>:<version>` with a vendor map for common products (openssh→openbsd,
httpd→apache, mysql→oracle, …); unknown packages fall back to `vendor = product` and still match on product tokens.

## 3 · Use
- **Vulnerability Management / Patch Management / Exposure / Attack-path** — populated automatically from the detected CVEs.
- **Attack chain**: the **Agentless host scan → vulnerabilities & hardening** playbook (`/chain`) seeds
  `agentless-scan` and escalates any finding to CyberSentinel AI for ATT&CK mapping.

`run.py` does no live access and no DB write (worker-safe). 100% offline / self-hosted — host data never
leaves your infrastructure. Only scan hosts you are **authorized** to assess.
