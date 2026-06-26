# Xygeni connector (Software Supply Chain Security / ASPM)

Imports [Xygeni](https://xygeni.io) findings and supply-chain posture into XORCISM. Xygeni covers
the whole SDLC: **SAST, SCA/SBOM, secrets, IaC, container, malicious-package (malware) detection,
CI/CD misconfiguration and build/pipeline SLSA provenance**.

## Mapping
- Each Xygeni **project** → the imported project context (an ASSET).
- **SCA** component vulnerabilities → `VULNERABILITY` / `ASSETVULNERABILITY` (CVE-linked where present).
- **secrets / IaC / SAST / malicious-package / CI-CD** issues → findings on the project asset, so
  software-supply-chain risk feeds the attack surface and the Enterprise Risk Score.

## Config (worker environment variables)
- `XYGENI_API_URL` — default `https://api.xygeni.io`
- `XYGENI_API_TOKEN` — API token (Bearer)

## Modes
1. **live** — `XYGENI_API_TOKEN` set → pulls `/v1/findings` (+ project name).
2. **offline** — `file` param → a saved Xygeni export JSON.
3. **demo** — no config → the bundled `sample.json`.

Worker-safe: stdlib only, secrets via env, ASCII-only output, no DB access. Normalized result
(`{project, assets, vulns}`) is consumed by `runner.import_findings`.

```bash
python run.py            # demo (bundled sample)
```
