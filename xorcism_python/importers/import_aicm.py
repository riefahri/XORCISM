"""import_aicm.py - import the CSA AI Controls Matrix (AICM) v1.1 (everything) into XORCISM.

The AICM is the Cloud Security Alliance's AI-specific controls framework - the AI counterpart to the
CCM. This importer loads the WHOLE spreadsheet (bundled as aicm_v1.1.json, parsed from the official
v1.1.0 xlsx) into the relevant XORCISM databases:

  1. Controls  -> XORCISM.CONTROL              (VOCABULARY "CSA AI Controls Matrix (AICM) v1.1",
                                                247 controls / 18 domains; CIS=id, Statement=spec)
  2. Mappings  -> XORCISM.CONTROLMAPPING       (Framework = BSI AI C4 / EU AI Act / ISO/IEC 42001:2023;
                                                Source='CSA AICM v1.1 mapping')
  3. AI-CAIQ   -> XCOMPLIANCE.QUESTIONNAIRE/QUESTION/QUESTIONFORQUESTIONNAIRE
                                                (questionnaire "CSA AI-CAIQ v1.1", 320 questions)
  4. LLM taxo  -> XTHREAT.LLMLIFECYCLE          (lifecycle phases x components; table auto-created)

Everything is idempotent (delete-then-insert by a stable key/Source). Raw SQL; DB dir = XORCISM_DB_DIR
env or the default. No schema change to existing tables (CONTROL/CONTROLMAPPING/QUESTIONNAIRE/QUESTION
already exist); XTHREAT.LLMLIFECYCLE is created if missing.

    python xorcism_python/importers/import_aicm.py
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "CSA AI Controls Matrix (AICM) v1.1"
QNAME = "CSA AI-CAIQ v1.1"
MAP_SOURCE = "CSA AICM v1.1 mapping"
QMODEL = "CSA AI-CAIQ v1.1"
LLM_SOURCE = "CSA AICM v1.1 LLM taxonomy"
BUNDLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aicm_v1.1.json")


def _db(name: str) -> str:
    d = os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, f"{name}.db")


def _cols(cur: sqlite3.Cursor, table: str) -> set:
    return {r[1] for r in cur.execute(f'PRAGMA table_info("{table}")').fetchall()}


def _ins(cur: sqlite3.Cursor, table: str, rec: dict, present: set) -> None:
    keys = [k for k in rec if k in present]
    cur.execute(f"INSERT INTO {table} ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])


def _ensure_vocab(cur: sqlite3.Cursor, name: str) -> int:
    cols = _cols(cur, "VOCABULARY")
    namecol = "VocabularyName" if "VocabularyName" in cols else ("Name" if "Name" in cols else None)
    if namecol:
        row = cur.execute(f"SELECT VocabularyID FROM VOCABULARY WHERE {namecol}=?", (name,)).fetchone()
        if row:
            return int(row[0])
    nid = (cur.execute("SELECT COALESCE(MAX(VocabularyID),0) FROM VOCABULARY").fetchone()[0] or 0) + 1
    rec = {"VocabularyID": nid, "VocabularyGUID": str(uuid.uuid4()), "CreatedDate": datetime.now(timezone.utc).isoformat()}
    if namecol:
        rec[namecol] = name
    _ins(cur, "VOCABULARY", rec, cols)
    return nid


def main() -> int:
    with open(BUNDLE, encoding="utf-8") as fh:
        cat = json.load(fh)
    now = datetime.now(timezone.utc).isoformat()
    controls, mappings, caiq, llm = cat["controls"], cat.get("mappings", []), cat.get("caiq", []), cat.get("llmTaxonomy", [])

    # ── 1) + 2) Controls + mappings → XORCISM ──
    xo = sqlite3.connect(_db("XORCISM")); xo.execute("PRAGMA busy_timeout=15000"); cur = xo.cursor()
    vid = _ensure_vocab(cur, VOCAB)
    ccols = _cols(cur, "CONTROL")
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))
    next_cid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    cis2id: dict[str, int] = {}
    for c in controls:
        cid = str(c.get("id") or "").strip()
        cis2id[cid] = next_cid
        _ins(cur, "CONTROL", {
            "ControlID": next_cid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{cid} {c.get('title', '')}".strip()[:300],
            "ControlDescription": f"CSA AICM v1.1 - {c.get('domain', '')}",
            "VocabularyID": vid, "CIS": cid, "Statement": (c.get("spec") or None),
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }, ccols)
        next_cid += 1

    n_map = 0
    has_map = cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLMAPPING'").fetchone() is not None
    if has_map:
        mcols = _cols(cur, "CONTROLMAPPING")
        cur.execute("DELETE FROM CONTROLMAPPING WHERE Source=?", (MAP_SOURCE,))
        next_mid = (cur.execute("SELECT COALESCE(MAX(MappingID),0) FROM CONTROLMAPPING").fetchone()[0] or 0) + 1
        for m in mappings:
            cid = cis2id.get(str(m.get("controlId") or "").strip())
            if cid is None:
                continue
            ext = str(m.get("mapping") or "").replace("\n", ", ").strip()
            if not ext:
                continue
            gap = str(m.get("gap") or "").strip()
            _ins(cur, "CONTROLMAPPING", {
                "MappingID": next_mid, "MappingGUID": str(uuid.uuid4()), "ControlID": cid,
                "Framework": str(m.get("framework") or ""), "ExternalID": ext[:1000],
                "ExternalName": gap or None, "Relationship": "maps-to", "Source": MAP_SOURCE, "CreatedDate": now,
            }, mcols)
            next_mid += 1; n_map += 1
    xo.commit(); xo.close()

    # ── 3) AI-CAIQ → XCOMPLIANCE questionnaire ──
    n_q = 0
    xc = sqlite3.connect(_db("XCOMPLIANCE")); xc.execute("PRAGMA busy_timeout=15000"); qcur = xc.cursor()
    if qcur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='QUESTIONNAIRE'").fetchone():
        qncols, qcols, jcols = _cols(qcur, "QUESTIONNAIRE"), _cols(qcur, "QUESTION"), _cols(qcur, "QUESTIONFORQUESTIONNAIRE")
        row = qcur.execute("SELECT QuestionnaireID FROM QUESTIONNAIRE WHERE QuestionnaireName=?", (QNAME,)).fetchone()
        if row:
            qid = int(row[0])
        else:
            qid = (qcur.execute("SELECT COALESCE(MAX(QuestionnaireID),0) FROM QUESTIONNAIRE").fetchone()[0] or 0) + 1
            _ins(qcur, "QUESTIONNAIRE", {
                "QuestionnaireID": qid, "QuestionnaireName": QNAME,
                "QuestionnaireDescription": "CSA AI Controls Matrix - Consensus Assessment Initiative Questionnaire (AI-CAIQ) v1.1.",
                "OcilId": "csa-aicm-aicaiq-1.1", "Language": "en", "CreatedDate": now,
            }, qncols)
        # idempotent: drop this questionnaire's prior CAIQ questions + links, re-insert
        qcur.execute("DELETE FROM QUESTIONFORQUESTIONNAIRE WHERE QuestionnaireID=?", (qid,))
        qcur.execute("DELETE FROM QUESTION WHERE Model=?", (QMODEL,))
        next_qid = (qcur.execute("SELECT COALESCE(MAX(QuestionID),0) FROM QUESTION").fetchone()[0] or 0) + 1
        next_jid = (qcur.execute("SELECT COALESCE(MAX(QuestionForQuestionnaireID),0) FROM QUESTIONFORQUESTIONNAIRE").fetchone()[0] or 0) + 1
        for i, q in enumerate(caiq, 1):
            qqid = str(q.get("questionId") or "").strip()
            _ins(qcur, "QUESTION", {
                "QuestionID": next_qid, "QuestionGUID": str(uuid.uuid4()), "QuestionName": qqid,
                "QuestionText": (q.get("question") or ""), "QuestionDescription": f"AICM control {q.get('controlId', '')}",
                "QuestionType": "Boolean", "OcilId": qqid, "Model": QMODEL, "CreatedDate": now,
            }, qcols)
            _ins(qcur, "QUESTIONFORQUESTIONNAIRE", {
                "QuestionForQuestionnaireID": next_jid, "QuestionnaireID": qid, "QuestionID": next_qid,
                "DisplayOrder": i, "CreatedDate": now,
            }, jcols)
            next_qid += 1; next_jid += 1; n_q += 1
        xc.commit()
    xc.close()

    # ── 4) LLM lifecycle taxonomy → XTHREAT.LLMLIFECYCLE (auto-created) ──
    n_llm = 0
    xt = sqlite3.connect(_db("XTHREAT")); xt.execute("PRAGMA busy_timeout=15000"); tcur = xt.cursor()
    tcur.execute("""CREATE TABLE IF NOT EXISTS LLMLIFECYCLE (
        LLMLifecycleID INTEGER PRIMARY KEY, LLMLifecycleGUID TEXT, StepOrder INTEGER,
        Phase TEXT, PhaseDescription TEXT, Component TEXT, Detail TEXT,
        Source TEXT, CreatedDate TEXT, TenantID INTEGER)""")
    tcur.execute("DELETE FROM LLMLIFECYCLE WHERE Source=?", (LLM_SOURCE,))
    lcols = _cols(tcur, "LLMLIFECYCLE")
    next_lid = (tcur.execute("SELECT COALESCE(MAX(LLMLifecycleID),0) FROM LLMLIFECYCLE").fetchone()[0] or 0) + 1
    for e in llm:
        _ins(tcur, "LLMLIFECYCLE", {
            "LLMLifecycleID": next_lid, "LLMLifecycleGUID": str(uuid.uuid4()), "StepOrder": e.get("order"),
            "Phase": e.get("phase"), "PhaseDescription": e.get("phaseDescription"),
            "Component": e.get("component"), "Detail": e.get("detail"), "Source": LLM_SOURCE, "CreatedDate": now,
        }, lcols)
        next_lid += 1; n_llm += 1
    xt.commit(); xt.close()

    print(f"[aicm] VocabularyID={vid}: {len(controls)} controls, {n_map} CONTROLMAPPING rows "
          f"(BSI AI C4 / EU AI Act / ISO 42001), {n_q} AI-CAIQ questions, {n_llm} LLM-taxonomy entries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
