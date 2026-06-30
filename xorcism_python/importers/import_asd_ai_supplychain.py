"""import_asd_ai_supplychain.py - import the ASD/ACSC "AI and ML: Supply chain risks and mitigations"
guidance (Commonwealth of Australia 2025, co-sealed by CCCS, CSA-SG, NIS-KR, NCO-JP, NCSC-NZ, NCSC-UK,
NSA; CC BY 4.0) into XORCISM as a selectable control framework.

  XORCISM.CONTROL -> VOCABULARY "ASD AI/ML Supply Chain (2025)"; one CONTROL per mitigation, grouped by
  the five supply-chain components (AI data, ML models, AI software, AI infrastructure/hardware,
  third-party services) + cross-cutting supply-chain risk management. CIS = a component-prefixed id
  (e.g. DATA-02), ControlName = id + title, ControlDescription = the component + the risk it mitigates,
  Statement = a concise summary of the mitigation with NIST AML / MITRE ATLAS mappings where the source
  provides them.

Data is EMBEDDED below (the guidance is CC BY 4.0; the Statements are concise summaries, not verbatim
reproductions). Idempotent (delete-then-insert by VocabularyID). DB dir = XORCISM_DB_DIR env or default.

    python xorcism_python/importers/import_asd_ai_supplychain.py
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "ASD AI/ML Supply Chain (2025)"
SOURCE = "https://www.cyber.gov.au/ (ASD/ACSC: AI and ML - Supply chain risks and mitigations, 2025, CC BY 4.0)"
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "asd_ai_supplychain.json")

# (prefix, component, [ (id, title, statement) ]) — mitigations grouped by supply-chain component.
CATEGORIES = [
    ("SCRM", "Supply chain risk management (cross-cutting)", [
        ("SCRM-01", "Supply chain integrity assessment", "Assess the AI/ML supply chain (sensitivity, ownership, technical TTPs) as part of a comprehensive supply-chain assessment across the AI product/service lifecycle."),
        ("SCRM-02", "Supply chain visibility and inventory", "Maintain full visibility of AI/ML systems and their supply chain: identify suppliers, manufacturers, distributors, retailers and subcontractors."),
        ("SCRM-03", "Security best practices and control review", "Ensure systems follow security best practices before AI/ML integration; obtain suppliers' security controls and policy, and assess how new AI/ML functionality affects cyber risk management."),
        ("SCRM-04", "Communication and staff training", "Establish clear communication channels for AI/ML supply-chain concerns and educate all staff who develop, deploy, use or maintain AI/ML systems on the cyber risks and best practices."),
    ]),
    ("DATA", "AI data", [
        ("DATA-01", "Standardised data collection and generation", "Use a standardised, documented methodology for collecting or generating data; prefer and weight real data over synthetic to reduce bias and inaccuracy. Mitigates low-quality / biased data."),
        ("DATA-02", "Quarantine and test external data", "Quarantine externally sourced data on dedicated isolated systems and run automated tests for malicious content, poisoning and watermarks before migrating it internally. Mitigates data poisoning (NIST AML.012/.013/.021/.023/.024; MITRE ATLAS AI Supply Chain Compromise)."),
        ("DATA-03", "Data review and preprocessing", "Review data for obvious errors and preprocess it (missing features, duplicates, uneven sample distribution) to ensure quality without introducing new bias."),
        ("DATA-04", "Data sanitisation", "Refine data via filtering, sampling and normalisation to reduce noise, outliers and poisoned content. Mitigates data poisoning."),
        ("DATA-05", "Trusted data sources", "Source data from trusted, reputable providers and avoid unknown sources to reduce the risk of poisoned or maliciously modified data."),
        ("DATA-06", "Data verification and provenance", "Verify data integrity with checksums, hashes and digital signatures, and adopt lineage tracking / data provenance with chain-of-custody to detect maliciously modified or poisoned data early."),
        ("DATA-07", "Ensemble methods (data)", "Train multiple datasets/subsets and models on the same problem and compare outputs for consistency, so a compromised or low-quality dataset is flagged for investigation."),
        ("DATA-08", "Training data obfuscation", "Remove unnecessary/sensitive features and apply anonymisation, differential privacy or synthetic data so exposed training data causes less damage. Mitigates training-data exposure (NIST AML.031-.038: model inversion, membership inference, training-data extraction)."),
    ]),
    ("MODEL", "Machine learning models", [
        ("MODEL-01", "Secure model file formats", "Use non-executable, weight-only or immutable-graph model formats and safe-loading flags (e.g. weights-only) to prevent serialisation attacks. Mitigates model serialisation attacks (part of NIST AML.05)."),
        ("MODEL-02", "Trusted, transparent sources and AIBOM", "Use models from trusted providers with transparency (training-data sources/categories, safety evaluations, bias testing); prefer models that ship an AIBOM or equivalent documentation. Treat web-sourced content as untrusted. Mitigates model poisoning (NIST AML.011/.026/.051)."),
        ("MODEL-03", "Model performance testing", "Perform initial and periodic testing against expected/known-good baselines (with verified reference data) to detect model poisoning or drift, especially for continuous-learning / fine-tuned models."),
        ("MODEL-04", "Model explainability and transparency", "Improve explainability via model simplification, visualisation, feature-importance analysis and inbuilt reasoning, giving better insight into a model's integrity and making poisoning easier to detect."),
        ("MODEL-05", "Model verification, provenance and registry", "Verify model integrity with checksums/hashes/digital signatures and maintain a model registry of verified, tested and approved versions; verify and test each new version before approval."),
        ("MODEL-06", "Ensemble methods (models)", "Compare multiple models on the same problem for performance and consistency so a compromised model produces divergent outputs that prompt investigation."),
        ("MODEL-07", "Reproducible builds (ML-BOM)", "Release model components plus build instructions (an ML-BOM) so users can rebuild the model and verify it with a checksum, and interrogate sub-components to reduce poisoning or embedded malware."),
        ("MODEL-08", "Model minimisation / obfuscation", "Apply transformations that disrupt malware embedded in a model's weights or metadata (at some performance cost) before use. Mitigates model-based malware embedding / stegomalware (part of NIST AML.05)."),
        ("MODEL-09", "ML-specific security tools", "Incorporate ML security tooling into the supply chain: model scanners (malicious content / stegomalware), adversarial emulators (evasion / extraction resilience) and performance evaluators. Mitigates evasion attacks (NIST AML.022/.025)."),
    ]),
    ("SW", "AI software", [
        ("SW-01", "Software integrity validation", "Validate the integrity of AI software and dependencies with checksums, digital signatures or provenance tracking on retrieval; use reproducible builds for sub-component visibility."),
        ("SW-02", "Malware scanning and SAST/DAST", "Analyse AI software with malware scanning and static and dynamic application testing to ensure it is malware-free and behaves as expected. Mitigates typosquatting / name-confusion and compromised libraries."),
        ("SW-03", "SBOM and component audit", "Audit software components and maintain an SBOM so known vulnerabilities are mitigated at deployment and throughout the lifecycle."),
        ("SW-04", "Secure deployment (least privilege)", "Deploy AI software with least privilege, granting only the minimum permissions required for its task."),
        ("SW-05", "Ongoing monitoring and patching", "Plan ongoing monitoring and maintenance to keep AI software and dependencies up to date with security patches."),
    ]),
    ("INFRA", "AI infrastructure and hardware", [
        ("INFRA-01", "Signed drivers/firmware and verified boot", "Enforce signed drivers and firmware and enable verified boot to reduce the attack surface introduced by GPUs and AI accelerator devices."),
        ("INFRA-02", "Network segmentation and management networks", "Appropriately segment AI hardware within the network and use separate management networks with their own authentication and auditing."),
        ("INFRA-03", "Hardware integrity and logging", "Ensure AI hardware is free of malicious content and enable logging, following existing security processes for integrated technology."),
    ]),
    ("TPS", "Third-party services", [
        ("TPS-01", "Third-party security assessment", "Perform thorough assessments of third-party AI/ML vendors, including their security practices, vulnerability-management processes and track record."),
        ("TPS-02", "Ongoing third-party monitoring", "Continuously monitor third-party providers' adherence to strong security practices and their commitment to security and transparency."),
        ("TPS-03", "Contractual security requirements", "Set cyber-security requirements for third parties early and in contracts: restrict use of your data for training, define cloud residencies, grant audit rights, set continuity requirements and establish a shared-responsibility model."),
    ]),
]


def _db(n: str) -> str:
    d = os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, f"{n}.db")


def _cols(cur: sqlite3.Cursor, t: str) -> set:
    return {r[1] for r in cur.execute(f'PRAGMA table_info("{t}")').fetchall()}


def _ins(cur: sqlite3.Cursor, t: str, rec: dict, present: set) -> None:
    keys = [k for k in rec if k in present]
    cur.execute(f"INSERT INTO {t} ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])


def _ensure_vocab(cur: sqlite3.Cursor, name: str, version: str, ref: str, desc: str) -> int:
    cols = _cols(cur, "VOCABULARY")
    nc = "VocabularyName" if "VocabularyName" in cols else "Name"
    now = datetime.now(timezone.utc).isoformat()
    row = cur.execute(f"SELECT VocabularyID FROM VOCABULARY WHERE {nc}=?", (name,)).fetchone()
    if row:
        vid = int(row[0])
        for col, val in (("VocabularyVersion", version), ("VocabularyReference", ref), ("VocabularyDescription", desc)):
            if val and col in cols:
                cur.execute(f"UPDATE VOCABULARY SET {col}=? WHERE VocabularyID=?", (val, vid))
        return vid
    vid = (cur.execute("SELECT COALESCE(MAX(VocabularyID),0) FROM VOCABULARY").fetchone()[0] or 0) + 1
    _ins(cur, "VOCABULARY", {"VocabularyID": vid, "VocabularyGUID": str(uuid.uuid4()), "CreatedDate": now,
                             nc: name, "VocabularyVersion": version, "VocabularyReference": ref,
                             "VocabularyDescription": desc}, cols)
    return vid


def main() -> int:
    controls = []
    for prefix, component, items in CATEGORIES:
        for cid, title, stmt in items:
            controls.append({"id": cid, "title": title, "component": component, "statement": stmt})
    os.makedirs(os.path.dirname(DATA), exist_ok=True)
    json.dump({"meta": {"title": "AI and ML: Supply chain risks and mitigations",
                        "publisher": "Australian Signals Directorate (ASD/ACSC) + co-sealing agencies",
                        "version": "2025", "license": "CC BY 4.0", "source": SOURCE,
                        "components": len(CATEGORIES), "controls": len(controls)},
               "controls": controls}, open(DATA, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    now = datetime.now(timezone.utc).isoformat()
    xo = sqlite3.connect(_db("XORCISM")); xo.execute("PRAGMA busy_timeout=20000"); cur = xo.cursor()
    vid = _ensure_vocab(cur, VOCAB, "2025", SOURCE,
                        "ASD/ACSC (Australia) + co-sealed (CCCS, CSA-SG, NIS-KR, NCO-JP, NCSC-NZ, NCSC-UK, NSA) "
                        "guidance: AI/ML supply-chain risks and mitigations across five components (AI data, ML "
                        "models, AI software, AI infrastructure/hardware, third-party services), mapped to the "
                        "NIST Adversarial ML taxonomy and MITRE ATLAS (AI Supply Chain Compromise). CC BY 4.0.")
    ccols = _cols(cur, "CONTROL")
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))
    nid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    for c in controls:
        _ins(cur, "CONTROL", {
            "ControlID": nid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{c['id']} {c['title']}"[:300],
            "ControlDescription": f"ASD AI/ML Supply Chain (2025) / {c['component']}"[:600],
            "VocabularyID": vid, "CIS": c["id"], "Statement": c["statement"][:2000],
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }, ccols)
        nid += 1
    xo.commit(); xo.close()
    print(f"[asd-ai-sc] VocabularyID={vid}: {len(controls)} controls imported under '{VOCAB}' "
          f"({len(CATEGORIES)} components).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
