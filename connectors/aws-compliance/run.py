"""run.py - XORCISM connector: AWS posture snapshot -> CIS AWS Foundations compliance findings.

Loads an AWS posture snapshot (JSON) and runs the CIS AWS Foundations Benchmark subset XORCISM ships
(IAM password policy, MFA for IAM users, root account access keys & MFA, inactive users (90 days),
access-key rotation, CloudTrail enablement/validation/CloudWatch/KMS, AWS Config all-regions recorder).
Each FAIL becomes a VULN finding (ref = CIS-AWS-<id>) on the AWS account asset; the account (and any
listed resources) become ASSETs. This is the connector counterpart of the in-app checker
(POST /api/cloud-security/aws-check). No DB access (worker-safe).

Snapshot schema (build it with the AWS CLI -- see README.md):
  {
    "account": "123456789012",
    "password_policy": { "MinimumPasswordLength": 14, "RequireSymbols": true, ... },
    "root_account": { "mfa_enabled": true, "access_keys": 0 },
    "users": [ { "user": "alice", "console_access": true, "mfa": true,
                 "access_keys": [ { "active": true, "last_rotated_days": 30, "last_used_days": 2 } ],
                 "password_last_used_days": 2 } ],
    "cloudtrail": { "trails": [ { "name": "t", "is_multi_region": true, "is_logging": true,
                                  "log_file_validation": true, "cloudwatch_logs": true, "kms_encrypted": true } ] },
    "config": { "recorders": [ { "name": "default", "recording": true, "all_regions": true } ] }
  }
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

INACTIVE_DAYS = 90
KEY_ROTATE_DAYS = 90


def _check(findings: List[Dict[str, Any]], account: str, cid: str, title: str, service: str,
           severity: str, ok: bool, resource: str, detail: str) -> None:
    if not ok:
        findings.append({
            "asset": account, "ref": "CIS-AWS-%s" % cid, "name": "[%s] %s" % (cid, title),
            "severity": severity, "service": service, "detail": detail,
        })


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file")
    if not path:
        raise RuntimeError("aws-compliance: provide a 'file' (AWS posture snapshot .json)")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        snap = json.load(fh)
    account = str(snap.get("account") or "aws-account")
    vulns: List[Dict[str, Any]] = []

    pp = snap.get("password_policy", "missing")
    if pp != "missing":
        if not pp:
            _check(vulns, account, "1.8", "IAM password policy is set", "IAM", "medium", False, account, "No account password policy.")
        else:
            _check(vulns, account, "1.8", "Password minimum length >= 14", "IAM", "medium", (pp.get("MinimumPasswordLength") or 0) >= 14, account, "MinimumPasswordLength=%s" % pp.get("MinimumPasswordLength"))
            _check(vulns, account, "1.9", "Password reuse prevention >= 24", "IAM", "low", (pp.get("PasswordReusePrevention") or 0) >= 24, account, "PasswordReusePrevention=%s" % pp.get("PasswordReusePrevention"))
            _check(vulns, account, "1.7", "Password requires all character classes", "IAM", "low",
                   bool(pp.get("RequireSymbols") and pp.get("RequireNumbers") and pp.get("RequireUppercaseCharacters") and pp.get("RequireLowercaseCharacters")), account, "character-class requirements incomplete")

    root = snap.get("root_account")
    if root:
        _check(vulns, account, "1.5", "Root account MFA enabled", "IAM", "critical", bool(root.get("mfa_enabled")), "root", "Root MFA missing")
        _check(vulns, account, "1.4", "No root account access keys", "IAM", "critical", (root.get("access_keys") or 0) == 0, "root", "Root access keys=%s" % root.get("access_keys"))

    users = snap.get("users")
    if isinstance(users, list):
        for u in users:
            if u.get("console_access") or u.get("password_enabled"):
                _check(vulns, account, "1.10", "MFA enabled for IAM console user", "IAM", "high", bool(u.get("mfa")), u.get("user", "?"), "Console user without MFA")
            key_used = min([k.get("last_used_days", 1e9) for k in (u.get("access_keys") or []) if k.get("active")] or [1e9])
            p_used = u.get("password_last_used_days")
            last = min(1e9 if p_used is None else p_used, key_used)
            if INACTIVE_DAYS < last < 1e9:
                _check(vulns, account, "1.12", "IAM user inactive > %dd" % INACTIVE_DAYS, "IAM", "medium", False, u.get("user", "?"), "Inactive for %s days" % int(last))
            for k in (u.get("access_keys") or []):
                if k.get("active") and (k.get("last_rotated_days") or 0) > KEY_ROTATE_DAYS:
                    _check(vulns, account, "1.14", "Access key older than %dd" % KEY_ROTATE_DAYS, "IAM", "medium", False, u.get("user", "?"), "Key age %s days" % k.get("last_rotated_days"))

    ct = snap.get("cloudtrail")
    if ct is not None:
        trails = ct.get("trails") or []
        _check(vulns, account, "3.1", "CloudTrail enabled in all regions", "CloudTrail", "high",
               any(t.get("is_multi_region") and t.get("is_logging", True) for t in trails), account, "No logging multi-region trail")
        _check(vulns, account, "3.2", "CloudTrail log file validation enabled", "CloudTrail", "medium",
               any(t.get("log_file_validation") for t in trails), account, "Log file validation off")
        _check(vulns, account, "3.4", "CloudTrail to CloudWatch Logs", "CloudTrail", "low",
               any(t.get("cloudwatch_logs") for t in trails), account, "Not integrated with CloudWatch Logs")
        _check(vulns, account, "3.7", "CloudTrail logs KMS-encrypted", "CloudTrail", "low",
               any(t.get("kms_encrypted") for t in trails), account, "Trails not KMS-encrypted")

    cfg = snap.get("config")
    if cfg is not None:
        rec = cfg.get("recorders") or []
        _check(vulns, account, "3.5", "AWS Config enabled in all regions", "AWS Config", "high",
               any(r.get("recording") and (r.get("all_regions") or r.get("all_supported")) for r in rec), account, "No all-regions Config recorder")

    assets = [{"name": account, "tags": ["aws", "cloud", "account"]}]
    for r in (snap.get("resources") or []):
        n = r.get("name") or r.get("id")
        if n:
            assets.append({"name": str(n), "tags": ["aws", "cloud", str(r.get("type") or "resource")]})
    return {"assets": assets, "vulns": vulns}
