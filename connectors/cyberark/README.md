# CyberArk connector

Imports the **CyberArk Privileged Access Management** vault (Self-Hosted PVWA or Privilege Cloud)
into XORCISM as **identities** (the IAM inventory):

| CyberArk object | → XORCISM IDENTITY |
|---|---|
| Account (`/API/Accounts`) | non-human · `privileged-account` — target `address` → Environment, `platformId`/`safeName` → Description, `secretType` → CredentialType, last secret change → LastUsedDate, PrivilegeLevel = `privileged` |
| Vault user (`/API/Users`) | human (or non-human for component/app users) · `user` — `enableUser` → Status |

Idempotent by `(Provider="CyberArk", ExternalID)` — re-running updates in place. Feeds the
**Identity & IAM** inventory (`/identities`) for orphaned-NHI, stale-secret (rotation age via
`LastRotatedDate`/`LastUsedDate`) and privileged-account detection.

## Auth (worker environment only — never the UI)

```
CYBERARK_BASE_URL     https://pvwa.example.com         # PVWA / Privilege Cloud base
CYBERARK_USERNAME     xorcism_svc                      # vault service account
CYBERARK_PASSWORD     ********
CYBERARK_AUTH_METHOD  CyberArk                         # or LDAP | RADIUS | Windows (optional)
CYBERARK_INSECURE     0                                # set 1 only to skip TLS verify (internal CA)
```

The service account needs **list/read** membership on the safes to inventory. The connector logs
on (`/API/Auth/<method>/Logon`), pages accounts + users, then logs off. No credentials/secrets
values are ever read — only account metadata.

## Run

```bash
# live
python run.py
# offline (no API): parse a saved REST export
python run.py --file sample.json
```

Output: `{"identities": [...], "source": "CyberArk"}`. Stdlib only, no DB access (runs on a remote worker).
