# AWS Compliance Checker (CIS AWS Foundations)

Runs the CIS AWS Foundations Benchmark subset XORCISM ships against an **AWS posture snapshot** and
maps each failing check to a compliance finding (VULN) on the AWS account asset. Same checks as the
in-app checker (`POST /api/cloud-security/aws-check`, surfaced on **/cloud-security**).

## Checks
- IAM password policy: minimum length ≥ 14, reuse prevention ≥ 24, all character classes (CIS 1.7–1.9)
- Root account: MFA enabled (1.5), no access keys (1.4)
- IAM users: MFA on all console users (1.10), no users inactive > 90 days (1.12), access keys rotated ≤ 90 days (1.14)
- CloudTrail: multi-region trail logging (3.1), log-file validation (3.2), CloudWatch Logs (3.4), KMS encryption (3.7)
- AWS Config: an all-regions recorder is recording (3.5)

## Building the snapshot from the AWS CLI

```bash
ACC=$(aws sts get-caller-identity --query Account --output text)
aws iam get-account-password-policy            > pp.json
aws iam generate-credential-report >/dev/null; aws iam get-credential-report --query Content --output text | base64 -d > cred.csv
aws cloudtrail describe-trails                 > trails.json
aws configservice describe-configuration-recorders > config.json
```

Then assemble a single `snapshot.json` matching the schema in `run.py` (account, `password_policy`,
`root_account`, `users[]`, `cloudtrail.trails[]`, `config.recorders[]`). The `users[]` array is derived
from the IAM **credential report** (`cred.csv`): `mfa_active`, `password_last_used`, `access_key_N_active`,
`access_key_N_last_rotated`, `access_key_N_last_used_date` → `last_rotated_days` / `last_used_days`.

## Run

- **Connector** (file-based, runner-ingestible → assets + compliance VULNs):
  `python connectors/runner.py --connector aws-compliance --file snapshot.json`
- **In-app** (richer per-check pass/fail view stored in CLOUDFINDING): upload `snapshot.json` via the
  **🔍 AWS compliance check** button on `/cloud-security`, or `POST /api/cloud-security/aws-check` with
  `{ "snapshot": { ... } }`.

Read-only: `run.py` does no DB access and is worker-safe.
