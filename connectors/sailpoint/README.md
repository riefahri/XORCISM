# SailPoint connector

Imports **SailPoint Identity Security Cloud** (formerly IdentityNow) — the IGA system of record —
into XORCISM as **identities** (the IAM inventory):

| SailPoint object | → XORCISM IDENTITY |
|---|---|
| Identity (`/v3/public-identities`) | human · `identity` — `lifecycleState`/`status` → Status, manager + identity profile → Description, `isManager` → PrivilegeLevel |
| Account (`/v3/accounts`, optional) | non-human · `account` — `sourceName` → Environment, uncorrelated → RiskLevel `High` |

Idempotent by `(Provider="SailPoint", ExternalID)` — re-running updates in place. Feeds the
**Identity & IAM** inventory (`/identities`) for uncorrelated/orphaned-account, inactive-lifecycle
and governance-coverage detection.

## Auth (worker environment only — never the UI)

```
SAILPOINT_BASE_URL      https://tenant.api.identitynow.com   # tenant API base
SAILPOINT_CLIENT_ID     <personal-access-token client id>
SAILPOINT_CLIENT_SECRET <client secret>
```

OAuth2 **client-credentials** — the token needs the read scopes for identities (and accounts if
`include=accounts`). Pulls are paged (`limit`/`offset`).

## Run

```bash
# live (identities only by default)
python run.py
# include source accounts too
python run.py --include identities,accounts
# offline (no API): parse a saved REST export
python run.py --file sample.json
```

Output: `{"identities": [...], "source": "SailPoint"}`. Stdlib only, no DB access (runs on a remote worker).
