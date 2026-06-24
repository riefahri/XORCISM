# Okta — sign-on / access policy rules (Zero Trust policy register)

Inbound connector. Ingests Okta sign-on / authentication policy rules into `XCOMPLIANCE.ZTPOLICY` —
the **Zero Trust policy register** (NIST SP 800-207 Policy Engine view) behind the **/zero-trust
Automation & Governance pillars**. The Okta counterpart of `entra-conditional-access`.

```bash
# demo (no credentials)
python connectors/runner.py --connector okta-policy

# from an exported policy-rules file (JSON array of rule objects)
python connectors/runner.py --connector okta-policy --param file=okta_rules.json

# live — Okta /api/v1/policies + /rules
OKTA_URL=https://acme.okta.com OKTA_TOKEN=… python connectors/runner.py --connector okta-policy --param type=OKTA_SIGN_ON
```

Each rule is normalized to **subject × resource × conditions × grant controls** — the policy/rule
name, status (ACTIVE→enabled), included groups/users, network/zone conditions, and the sign-on action
(`requireFactor`→`require_mfa`, `access:DENY`→`block`). Read-only; idempotent by rule id; stdlib only;
token via env `OKTA_TOKEN` (SSWS).
