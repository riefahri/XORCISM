# Microsoft Entra ID — sign-in logs (UEBA / Zero Trust)

Inbound connector. Ingests Entra sign-in events into `XORCISM.IDENTITYSIGNIN` — the
continuous-verification telemetry behind the **/zero-trust Identity pillar** and the **UEBA
session-risk** (`zerotrust.ts sessionRisk`: MFA-less sign-ins, failed bursts, impossible travel,
Entra risk level).

```bash
# demo (no credentials) — proves the import chain
python connectors/runner.py --connector entra-signin

# from an exported sign-in log (Graph value[] JSON)
python connectors/runner.py --connector entra-signin --param file=signins.json

# live — Microsoft Graph /auditLogs/signIns
GRAPH_TOKEN=… python connectors/runner.py --connector entra-signin --param top=500
```

Normalizes `userPrincipalName`, `createdDateTime`, `ipAddress`, `location`, `deviceDetail`,
`authenticationRequirement` (→ MFA), `status` (→ success/failure), `riskLevelDuringSignIn`. Read-only;
idempotent by Entra sign-in id; stdlib only; token via env `GRAPH_TOKEN`.
