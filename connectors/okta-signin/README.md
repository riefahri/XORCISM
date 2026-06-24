# Okta — System Log sign-ins (UEBA / Zero Trust)

Inbound connector. Ingests Okta System Log authentication events into `XORCISM.IDENTITYSIGNIN` — the
continuous-verification telemetry behind the **/zero-trust Identity pillar** and the **UEBA
session-risk**.

```bash
# demo (no credentials)
python connectors/runner.py --connector okta-signin

# from an exported System Log (JSON array)
python connectors/runner.py --connector okta-signin --param file=okta_logs.json

# live — Okta /api/v1/logs
OKTA_URL=https://acme.okta.com OKTA_TOKEN=… python connectors/runner.py --connector okta-signin --param limit=500
```

Normalizes `actor.alternateId`, `published`, `client.ipAddress`, `geographicalContext`,
`outcome.result` (→ success/failure) and an MFA heuristic from the event type / credential type.
Read-only; idempotent by Okta event uuid; stdlib only; token via env `OKTA_TOKEN` (SSWS).
