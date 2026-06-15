"""
import_attack_evals.py — Integrates MITRE ATT&CK Evaluations into XORCISM by REUSING
the OCIL model (XCOMPLIANCE). Jerome Athias - XORCISM

Mapping:
    Evaluation round           → QUESTIONNAIRE   (one per round)
    Step / sub-step            → QUESTION        (linked via QUESTIONFORQUESTIONNAIRE)
    Participating vendor       → ANSWER          (one per vendor)
    Vendor/step result         → ANSWERFORQUESTION.Result  (None/Telemetry/Analytic…)

Idempotent: get-or-create by deterministic OcilId (round / round:step / round:vendor)
and by pair for the link tables → re-runnable without duplicates.

Input (--file): JSON of results in the format documented below. The exact structure
of the MITRE exports varies by round; convert to this schema, or indicate the
real format to add a native parser. --sample inserts a demonstration round.

    {
      "round": "Enterprise 2023",
      "adversary": "Turla",
      "vendors": ["VendorA", "VendorB"],            # optional (deduced from the steps otherwise)
      "steps": [
        { "step": "1.A.1", "name": "Initial Compromise", "tactic": "Execution",
          "technique": "T1059.001", "procedure": "PowerShell stager…",
          "detections": [
            { "vendor": "VendorA", "category": "Analytic", "notes": "…" },
            { "vendor": "VendorB", "category": "Telemetry" }
          ] }
      ]
    }

Usage:
    python import_attack_evals.py --file results.json
    python import_attack_evals.py --sample
"""
import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from uuid import uuid4

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

DB_PATH = os.path.join(config.DB_DIR, "XCOMPLIANCE.db")
OCIL_PREFIX = "attack-eval"  # namespace for the OcilId values created by this importer

# Windows console in cp1252: forces UTF-8 output (accented characters/arrows).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
except Exception:
    pass


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportEvals] {msg}", flush=True)


def maxid(cur, table, col) -> int:
    return cur.execute(f"SELECT COALESCE(MAX({col}),0) FROM {table}").fetchone()[0]


def get_or_create_questionnaire(cur, ocil_id, name, desc):
    row = cur.execute("SELECT QuestionnaireID FROM QUESTIONNAIRE WHERE OcilId=?", (ocil_id,)).fetchone()
    if row:
        return row[0]
    qid = maxid(cur, "QUESTIONNAIRE", "QuestionnaireID") + 1
    cur.execute(
        "INSERT INTO QUESTIONNAIRE (QuestionnaireID, QuestionnaireName, QuestionnaireDescription, CreatedDate, OcilId) VALUES (?,?,?,?,?)",
        (qid, name, desc, now(), ocil_id),
    )
    return qid


def get_or_create_question(cur, ocil_id, name, text, qtype):
    row = cur.execute("SELECT QuestionID FROM QUESTION WHERE OcilId=?", (ocil_id,)).fetchone()
    if row:
        return row[0]
    qid = maxid(cur, "QUESTION", "QuestionID") + 1
    cur.execute(
        "INSERT INTO QUESTION (QuestionID, QuestionGUID, QuestionName, QuestionDescription, QuestionText, QuestionType, OcilId, CreatedDate) VALUES (?,?,?,?,?,?,?,?)",
        (qid, str(uuid4()), name, text, text, qtype, ocil_id, now()),
    )
    return qid


def get_or_create_answer(cur, ocil_id, answer, notes):
    row = cur.execute("SELECT AnswerID FROM ANSWER WHERE OcilId=?", (ocil_id,)).fetchone()
    if row:
        return row[0]
    aid = maxid(cur, "ANSWER", "AnswerID") + 1
    cur.execute(
        "INSERT INTO ANSWER (AnswerID, AnswerGUID, Answer, AnswerNotes, OcilId, CreatedDate) VALUES (?,?,?,?,?,?)",
        (aid, str(uuid4()), answer, notes, ocil_id, now()),
    )
    return aid


def link_q_to_qn(cur, qn_id, q_id, order):
    if cur.execute("SELECT 1 FROM QUESTIONFORQUESTIONNAIRE WHERE QuestionnaireID=? AND QuestionID=?", (qn_id, q_id)).fetchone():
        return
    rid = maxid(cur, "QUESTIONFORQUESTIONNAIRE", "QuestionForQuestionnaireID") + 1
    cur.execute(
        "INSERT INTO QUESTIONFORQUESTIONNAIRE (QuestionForQuestionnaireID, QuestionnaireID, QuestionID, DisplayOrder, CreatedDate) VALUES (?,?,?,?,?)",
        (rid, qn_id, q_id, order, now()),
    )


def link_a_to_q(cur, q_id, a_id, result, order):
    row = cur.execute("SELECT AnswerForQuestionID FROM ANSWERFORQUESTION WHERE QuestionID=? AND AnswerID=?", (q_id, a_id)).fetchone()
    if row:
        cur.execute("UPDATE ANSWERFORQUESTION SET Result=? WHERE AnswerForQuestionID=?", (result, row[0]))
        return
    rid = maxid(cur, "ANSWERFORQUESTION", "AnswerForQuestionID") + 1
    cur.execute(
        "INSERT INTO ANSWERFORQUESTION (AnswerForQuestionID, QuestionID, AnswerID, Result, DisplayOrder, CreatedDate) VALUES (?,?,?,?,?,?)",
        (rid, q_id, a_id, result, order, now()),
    )


SAMPLE = {
    "round": "Enterprise 2023",
    "adversary": "Turla (DEMO)",
    "vendors": ["VendorA", "VendorB"],
    "steps": [
        {"step": "1.A.1", "name": "Initial Access", "tactic": "Execution", "technique": "T1059.001",
         "procedure": "PowerShell download cradle",
         "detections": [{"vendor": "VendorA", "category": "Analytic", "notes": "PS script block log"},
                        {"vendor": "VendorB", "category": "Telemetry"}]},
        {"step": "2.A.1", "name": "Discovery", "tactic": "Discovery", "technique": "T1082",
         "procedure": "System information discovery",
         "detections": [{"vendor": "VendorA", "category": "Telemetry"},
                        {"vendor": "VendorB", "category": "None"}]},
    ],
}


def import_round(cur, data: dict) -> None:
    rnd = str(data.get("round") or "Unknown round").strip()
    adv = str(data.get("adversary") or "").strip()
    label = f"ATT&CK Evaluations: {rnd}" + (f" ({adv})" if adv else "")
    qn_ocil = f"{OCIL_PREFIX}:{rnd}"
    qn_id = get_or_create_questionnaire(cur, qn_ocil, label, f"MITRE ATT&CK Evaluations — round {rnd}" + (f", adversaire {adv}" if adv else "") + ".")

    # ANSWER per vendor (reused across all the steps of the round).
    vendors = {}
    for v in data.get("vendors", []) or []:
        vendors[str(v)] = get_or_create_answer(cur, f"{OCIL_PREFIX}:{rnd}:vendor:{v}", str(v), f"Participant ATT&CK Evaluations {rnd}.")

    steps = data.get("steps", []) or []
    for i, st in enumerate(steps, start=1):
        step_id = str(st.get("step") or f"step-{i}")
        qname = step_id + (f" — {st['name']}" if st.get("name") else "")
        parts = []
        if st.get("tactic"):    parts.append(f"Tactique: {st['tactic']}")
        if st.get("technique"): parts.append(f"Technique: {st['technique']}")
        if st.get("procedure"): parts.append(str(st["procedure"]))
        q_id = get_or_create_question(cur, f"{OCIL_PREFIX}:{rnd}:{step_id}", qname, " — ".join(parts), "attack-eval-step")
        link_q_to_qn(cur, qn_id, q_id, i)
        for j, det in enumerate(st.get("detections", []) or [], start=1):
            vname = str(det.get("vendor") or "?")
            if vname not in vendors:
                vendors[vname] = get_or_create_answer(cur, f"{OCIL_PREFIX}:{rnd}:vendor:{vname}", vname, f"Participant ATT&CK Evaluations {rnd}.")
            result = str(det.get("category") or det.get("result") or "")
            if det.get("notes"):
                result = (result + " — " + str(det["notes"]))[:200]
            link_a_to_q(cur, q_id, vendors[vname], result, j)
    log(f"Round « {rnd} » : {len(steps)} étapes, {len(vendors)} éditeurs -> QUESTIONNAIRE #{qn_id}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Importe MITRE ATT&CK Evaluations dans le modèle OCIL (XCOMPLIANCE)")
    ap.add_argument("--file", help="JSON de résultats (format documenté en tête de fichier)")
    ap.add_argument("--sample", action="store_true", help="Insère un round de démonstration")
    args = ap.parse_args()

    if not args.file and not args.sample:
        ap.error("Fournissez --file <results.json> ou --sample")

    if args.sample:
        rounds = [SAMPLE]
    else:
        with open(args.file, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        rounds = data if isinstance(data, list) else [data]

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA busy_timeout = 5000")
    cur = conn.cursor()
    for rnd in rounds:
        if isinstance(rnd, dict):
            import_round(cur, rnd)
    conn.commit()
    conn.close()
    log(f"Terminé ({now()}). Visible dans XCOMPLIANCE.QUESTIONNAIRE / QUESTION / ANSWER.")


if __name__ == "__main__":
    main()
