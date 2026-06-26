"""import_atlas.py - import the MITRE ATLAS matrix (Adversarial Threat Landscape for AI Systems) into
XORCISM (XTHREAT.ATLASTACTIC + ATLASTECHNIQUE).

MITRE ATLAS (https://atlas.mitre.org) is the "ATT&CK for AI/ML" — adversary tactics & techniques
against machine-learning systems. This importer seeds the matrix (14 tactics + a curated set of
techniques, IDs AML.TA#### / AML.T####) and maps each LLM-relevant technique to its OWASP-LLM-Top-10
category, so the AI-BAS / AI-runtime detections can be rolled up into an "ATLAS coverage" view
(a Threat-Informed-Defense lens for AI). Titles + short descriptions only.

Idempotent: get-or-create by AtlasID. Raw SQL; DB path = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_atlas.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

# (AtlasID, Name) — ATLAS tactics
TACTICS = [
    ("AML.TA0002", "Reconnaissance"), ("AML.TA0003", "Resource Development"),
    ("AML.TA0004", "Initial Access"), ("AML.TA0000", "ML Model Access"),
    ("AML.TA0005", "Execution"), ("AML.TA0006", "Persistence"),
    ("AML.TA0012", "Privilege Escalation"), ("AML.TA0007", "Defense Evasion"),
    ("AML.TA0013", "Credential Access"), ("AML.TA0008", "Discovery"),
    ("AML.TA0009", "Collection"), ("AML.TA0001", "ML Attack Staging"),
    ("AML.TA0010", "Exfiltration"), ("AML.TA0011", "Impact"),
]

# (AtlasID, Name, TacticAtlasID, OWASP-LLM tag or "", description)
TECHNIQUES = [
    ("AML.T0002", "Acquire Public ML Artifacts", "AML.TA0002", "", "Obtain target models, datasets or code from public sources."),
    ("AML.T0016", "Obtain Capabilities", "AML.TA0003", "", "Acquire adversarial tools / ML capabilities for the operation."),
    ("AML.T0010", "ML Supply Chain Compromise", "AML.TA0004", "LLM05", "Compromise a model, dataset, or dependency in the ML supply chain."),
    ("AML.T0012", "Valid Accounts", "AML.TA0004", "", "Use legitimate credentials to access ML systems."),
    ("AML.T0051", "LLM Prompt Injection", "AML.TA0004", "LLM01", "Craft inputs that override system instructions / safety filters (direct or indirect)."),
    ("AML.T0040", "ML Model Inference API Access", "AML.TA0000", "", "Interact with the model only via its inference API."),
    ("AML.T0044", "Full ML Model Access", "AML.TA0000", "", "Obtain white-box access to model weights / architecture."),
    ("AML.T0053", "LLM Plugin Compromise", "AML.TA0005", "LLM08", "Abuse connected tools/plugins for excessive agency / code execution."),
    ("AML.T0018", "Backdoor ML Model", "AML.TA0006", "LLM03", "Implant a hidden trigger in the model that persists across use."),
    ("AML.T0054", "LLM Jailbreak", "AML.TA0012", "LLM01", "Bypass guardrails to elevate the model's effective permissions/behavior."),
    ("AML.T0015", "Evade ML Model", "AML.TA0007", "", "Craft inputs that evade detection / classification."),
    ("AML.T0055", "Unsecured Credentials", "AML.TA0013", "LLM06", "Recover credentials exposed in prompts, logs or model outputs."),
    ("AML.T0056", "LLM Meta Prompt Extraction", "AML.TA0008", "LLM07", "Extract the hidden system prompt / instructions (system-prompt leakage)."),
    ("AML.T0035", "ML Artifact Collection", "AML.TA0009", "", "Collect ML artifacts (models, datasets, configs) of interest."),
    ("AML.T0043", "Craft Adversarial Data", "AML.TA0001", "", "Stage adversarial examples for a downstream attack."),
    ("AML.T0020", "Poison Training Data", "AML.TA0001", "LLM03", "Inject tainted samples so the retrained model learns attacker logic."),
    ("AML.T0057", "LLM Data Leakage", "AML.TA0010", "LLM06", "Cause the model to reveal sensitive/memorized data (PII, secrets, proprietary)."),
    ("AML.T0024", "Exfiltration via ML Inference API", "AML.TA0010", "LLM06", "Systematically query the inference API to extract memorized/training data."),
    ("AML.T0025", "Exfiltration via Cyber Means", "AML.TA0010", "", "Exfiltrate ML data/artifacts using conventional means."),
    ("AML.T0031", "Erode ML Model Integrity", "AML.TA0011", "LLM03", "Degrade model accuracy/trust (e.g. via poisoning) to cause harm."),
    ("AML.T0029", "Denial of ML Service", "AML.TA0011", "LLM10", "Exhaust resources so the ML service becomes unavailable."),
    ("AML.T0034", "Cost Harvesting", "AML.TA0011", "LLM10", "Drive up inference cost (unbounded consumption / economic DoS)."),
    ("AML.T0048", "External Harms", "AML.TA0011", "LLM09", "Cause societal / financial / reputational harm via the ML system."),
]


def _db_path() -> str:
    d = os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, "XTHREAT.db")


def main() -> int:
    con = sqlite3.connect(_db_path())
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cur.execute("""CREATE TABLE IF NOT EXISTS ATLASTACTIC (
        TacticID INTEGER PRIMARY KEY, AtlasID TEXT, Name TEXT, GUID TEXT, CreatedDate TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS ATLASTECHNIQUE (
        TechniqueID INTEGER PRIMARY KEY, AtlasID TEXT, Name TEXT, TacticAtlasID TEXT,
        OwaspLlm TEXT, Description TEXT, GUID TEXT, CreatedDate TEXT)""")

    n_ta = n_te = 0
    nid = (cur.execute("SELECT COALESCE(MAX(TacticID),0) FROM ATLASTACTIC").fetchone()[0] or 0) + 1
    for aid, name in TACTICS:
        if cur.execute("SELECT 1 FROM ATLASTACTIC WHERE AtlasID=?", (aid,)).fetchone():
            cur.execute("UPDATE ATLASTACTIC SET Name=? WHERE AtlasID=?", (name, aid))
            continue
        cur.execute("INSERT INTO ATLASTACTIC (TacticID,AtlasID,Name,GUID,CreatedDate) VALUES (?,?,?,?,?)", (nid, aid, name, str(uuid.uuid4()), now)); nid += 1; n_ta += 1

    tid = (cur.execute("SELECT COALESCE(MAX(TechniqueID),0) FROM ATLASTECHNIQUE").fetchone()[0] or 0) + 1
    for aid, name, ta, owasp, desc in TECHNIQUES:
        if cur.execute("SELECT 1 FROM ATLASTECHNIQUE WHERE AtlasID=?", (aid,)).fetchone():
            cur.execute("UPDATE ATLASTECHNIQUE SET Name=?,TacticAtlasID=?,OwaspLlm=?,Description=? WHERE AtlasID=?", (name, ta, owasp, desc, aid))
            continue
        cur.execute("INSERT INTO ATLASTECHNIQUE (TechniqueID,AtlasID,Name,TacticAtlasID,OwaspLlm,Description,GUID,CreatedDate) VALUES (?,?,?,?,?,?,?,?)",
                    (tid, aid, name, ta, owasp, desc, str(uuid.uuid4()), now)); tid += 1; n_te += 1

    con.commit(); con.close()
    print(f"[atlas] MITRE ATLAS: {len(TACTICS)} tactics ({n_ta} new), {len(TECHNIQUES)} techniques ({n_te} new); "
          f"{sum(1 for t in TECHNIQUES if t[3])} OWASP-LLM-mapped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
