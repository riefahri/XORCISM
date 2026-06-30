# Security Policy

XORCISM is a security platform, so we hold our own code to the standard we help our users enforce.
We welcome and value reports from the security-research community, and we are committed to working
with researchers in good faith under coordinated disclosure.

This document follows the conventions of [GitHub Security Advisories](https://docs.github.com/en/code-security),
[OWASP / OpenSSF vulnerability disclosure](https://github.com/ossf/oss-vulnerability-guide) and
[RFC 9116 (`security.txt`)](https://www.rfc-editor.org/rfc/rfc9116).

---

## Supported versions

XORCISM ships as a rolling release; security fixes land on `main` and the current minor series.

| Version | Supported |
| :--- | :--- |
| `main` (latest) | ✅ Yes |
| `1.6.x` | ✅ Yes |
| `< 1.6` (pre-release) | ❌ No — please update |

Because XORCISM is **self-hosted**, operators are responsible for deploying fixes once released.
Watch the repository (Releases) to be notified of security updates.

---

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for security vulnerabilities.**

Use one of these private channels:

1. **Preferred — GitHub Private Vulnerability Reporting:** on
   [`XORCISM-AI/XORCISM`](https://github.com/XORCISM-AI/XORCISM) → **Security** tab →
   **Report a vulnerability**. This keeps the report private and lets us collaborate and request a CVE.
2. **Email:** **contact@xorcism.ai** with the subject prefix `[SECURITY]`. If you wish to encrypt,
   ask for our current PGP key in a first (non-sensitive) message and we will provide it.

### What to include

A good report helps us triage faster. Where possible, include:

- A clear description of the issue and its **security impact**.
- The **component** (server / client / connector / importer / agent) and version or commit.
- **Reproduction steps** or a minimal proof-of-concept (no destructive payloads — see Safe Harbor).
- Affected configuration (self-hosted defaults vs. a specific setup), and any logs/screenshots.
- Your assessment of severity (CVSS vector welcome — see below).

---

## Our response commitment

| Stage | Target |
| :--- | :--- |
| Acknowledge receipt | within **3 business days** |
| Initial triage & severity | within **7 business days** |
| Status updates | at least **every 14 days** until resolution |
| Fix for Critical / High | prioritized, typically **≤ 30 days** |
| Fix for Medium / Low | next regular release |

If you do not receive an acknowledgement within 3 business days, please re-send — mail can be lost.

---

## Coordinated disclosure

- We follow **coordinated (responsible) disclosure** with a default embargo of **90 days** from the
  report, or until a fix is released — whichever comes first. We are happy to align with your timeline.
- We will request a **CVE** for confirmed vulnerabilities and publish a **GitHub Security Advisory**.
- With your permission, we will **credit you** in the advisory and release notes. Anonymous credit is fine.
- There is currently **no paid bug-bounty**; we offer public acknowledgement and our sincere thanks.

We ask that you **do not publicly disclose** the issue until a fix is available and the advisory is published.

---

## Severity

We score vulnerabilities with **CVSS v4.0** (falling back to v3.1) to prioritize remediation. A CVSS
vector in your report is appreciated but not required.

---

## Safe harbor

We consider security research conducted in line with this policy to be **authorized**, and we will not
pursue or support legal action against researchers who, in good faith:

- Make a genuine effort to avoid privacy violations, data destruction, and service degradation;
- Only interact with **accounts and data they own** or have explicit permission to test (use your own
  self-hosted instance — XORCISM is self-hostable, so please test there, not on someone else's deployment);
- **Do not** run denial-of-service, spam, social-engineering, or physical attacks;
- Stop and report as soon as they identify a vulnerability, and do not exfiltrate more data than necessary
  to demonstrate the issue;
- Give us reasonable time to remediate before any disclosure.

If in doubt, ask us first — we would rather answer a question than see good research go sideways.

---

## Scope

**In scope** — code maintained in this repository:

- The application server (`xorcism_ts/server`), client bundles (`xorcism_ts/client`), REST API,
  authentication / RBAC, and the public Trust Center.
- First-party **connectors** and **importers** shipped in this repository.
- The endpoint **agent**, the **Agent Policy Firewall**, and tamper-evidence (audit hash chain, signed receipts).

**Out of scope:**

- **Third-party tools catalogued in XORCISM** (report those to their respective maintainers).
- Vulnerabilities requiring a **compromised host, root/admin on the box, or a malicious administrator**.
- Findings only reproducible against **seeded demo data**, missing best-practice hardening on a
  deliberately insecure test deployment, or denial-of-service / volumetric issues.
- Self-XSS, missing security headers without a demonstrated exploit, clickjacking on non-sensitive pages,
  and reports generated solely by automated scanners without a working proof-of-concept.
- The showcase website content and social accounts.

---

## How XORCISM is built to be defensible

XORCISM is designed to keep your data yours and to be inspectable:

- **Self-hosted & data-sovereign** — runs entirely on your infrastructure; **no outbound telemetry**.
- **Local-first AI** — AI features use a local model (Ollama); prompts and raw data never leave the host.
- **Secrets at rest** — sensitive fields are encrypted in the database (application vault); secrets are
  decrypted only for display to authorized users.
- **AuthN/Z** — session auth with RBAC, optional **TOTP 2FA** and **WebAuthn passkeys**.
- **Tamper-evident audit** — the audit log is a **SHA-256 hash chain**; integrity is verifiable at
  `/api/admin/audit/verify`. Agent/automation actions carry **signed receipts** via the Agent Policy Firewall.
- **Supply chain** — MIT-licensed; CycloneDX/SPDX **SBOM** and **CBOM** generation are built in;
  dependencies are tracked and updated.

### Hardening guidance for self-hosters

- **Change the initial admin password** immediately (it is shown once at first boot).
- Terminate **TLS** at a reverse proxy and never expose the app over plain HTTP on an untrusted network.
- Set a strong, unique **session secret** and restrict filesystem permissions on `DB_DIR` (the SQLite
  databases) and the blob store.
- Keep **Node.js** and OS packages patched; run the app as a non-privileged user.
- Restrict network access to administrative endpoints and the local AI/SIEM connectors.
- Review the RBAC roles and the tamper-evident audit log periodically.

---

## `security.txt`

Operators are encouraged to publish a [`/.well-known/security.txt`](https://www.rfc-editor.org/rfc/rfc9116)
on their deployment, e.g.:

```
Contact: mailto:contact@xorcism.ai
Policy: https://github.com/XORCISM-AI/XORCISM/blob/main/SECURITY.md
Preferred-Languages: en, fr
```

---

Thank you for helping keep XORCISM and its users safe. 🛡️
