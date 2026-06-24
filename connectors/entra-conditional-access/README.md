# Microsoft Entra ID — Conditional Access policies (Zero Trust policy register)

Inbound connector. Ingests Entra Conditional Access policies into `XCOMPLIANCE.ZTPOLICY` — the
**Zero Trust policy register** (NIST SP 800-207 Policy Engine view) behind the **/zero-trust
Automation & Governance pillars**. XORCISM *models and measures* the policy; the IdP enforces it.

```bash
# demo (no credentials)
python connectors/runner.py --connector entra-conditional-access

# from an exported policies file (Graph value[] JSON)
python connectors/runner.py --connector entra-conditional-access --param file=ca_policies.json

# live — Microsoft Graph /identity/conditionalAccess/policies
GRAPH_TOKEN=… python connectors/runner.py --connector entra-conditional-access
```

Each policy is normalized to **subject × resource × conditions × grant controls** — `displayName`,
`state` (enabled / disabled / report-only), included users/groups/roles, applications, client/risk/
location conditions, and the built-in controls (→ `require_mfa`, `require_compliant_device`, `block`).
Read-only; idempotent by policy id; stdlib only; token via env `GRAPH_TOKEN`.
