/**
 * ocil.ts — OCIL 2.0 interoperability (NIST IR 7692) for XCOMPLIANCE
 * questionnaires. Generates and reads OCIL 2.0 XML from the
 * QUESTIONNAIRE / QUESTION / ANSWER / QUESTIONFORQUESTIONNAIRE / ANSWERFORQUESTION tables.
 *
 * No external dependency (string building + mini XML parser). Fully covers
 * OCIL "boolean" and "choice" questions (the usual cases of a compliance
 * checklist); "numeric"/"string" types are exported with a default
 * handler.
 *
 *   Schema: http://scap.nist.gov/schema/ocil/2.0
 */
import { getDb } from "./db";

const OCIL_NS = "http://scap.nist.gov/schema/ocil/2.0";
const ID_NS = "org.xorcism"; // "namespace" of ocil:NS:type:index identifiers
const RESULTS = new Set(["PASS", "FAIL", "ERROR", "UNKNOWN", "NOT_TESTED", "NOT_APPLICABLE"]);

const nowTs = (): string => new Date().toISOString().replace(/\.\d+Z$/, "Z");
const esc = (s: unknown): string =>
  String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const ocilId = (type: string, id: number | string): string => `ocil:${ID_NS}:${type}:${id}`;
const result = (r: unknown, fallback: string): string => {
  const v = String(r ?? "").trim().toUpperCase();
  return RESULTS.has(v) ? v : fallback;
};
const qType = (t: unknown): string => {
  const v = String(t ?? "").trim().toLowerCase();
  return ["boolean", "choice", "numeric", "string"].includes(v) ? v : "boolean";
};
const boolLit = (v: unknown): string => {
  const s = String(v ?? "").trim().toLowerCase();
  return s === "true" || s === "yes" || s === "1" ? "true" : "false";
};

interface QnRow { QuestionnaireID: number; QuestionnaireName: string | null; QuestionnaireDescription: string | null; OcilId: string | null; Revision: string | null; Operator: string | null; }
interface QRow { QuestionID: number; QuestionName: string | null; QuestionDescription: string | null; QuestionText: string | null; OcilId: string | null; Revision: string | null; QuestionType: string | null; DefaultAnswer: string | null; Model: string | null; ResultWhenTrue: string | null; ResultWhenFalse: string | null; }
interface ChoiceRow { AnswerID: number; Answer: string | null; OcilId: string | null; Result: string | null; }

// ── EXPORT ──────────────────────────────────────────────────────────────────────
export function exportOcil(questionnaireIds?: number[]): string {
  const db = getDb("XCOMPLIANCE");
  const qns = (questionnaireIds && questionnaireIds.length
    ? db.prepare(`SELECT * FROM QUESTIONNAIRE WHERE QuestionnaireID IN (${questionnaireIds.map(() => "?").join(",")})`).all(...questionnaireIds)
    : db.prepare("SELECT * FROM QUESTIONNAIRE ORDER BY QuestionnaireID").all()) as QnRow[];

  const qLink = db.prepare(
    `SELECT q.*, l.DisplayOrder AS _ord, l.QuestionForQuestionnaireID AS _lid
     FROM QUESTIONFORQUESTIONNAIRE l JOIN QUESTION q ON q.QuestionID = l.QuestionID
     WHERE l.QuestionnaireID = ? ORDER BY COALESCE(l.DisplayOrder, 999999), l.QuestionForQuestionnaireID`
  );
  const choicesOf = db.prepare(
    `SELECT a.AnswerID, a.Answer, a.OcilId, afq.Result
     FROM ANSWERFORQUESTION afq JOIN ANSWER a ON a.AnswerID = afq.AnswerID
     WHERE afq.QuestionID = ? ORDER BY COALESCE(afq.DisplayOrder, 999999), afq.AnswerForQuestionID`
  );

  const qById = new Map<number, QRow>();      // referenced questions (deduplicated)
  const qnActions = new Map<number, QRow[]>(); // questionnaireID → ordered questions
  for (const qn of qns) {
    const qs = qLink.all(qn.QuestionnaireID) as (QRow & { _ord: number })[];
    qnActions.set(qn.QuestionnaireID, qs);
    for (const q of qs) qById.set(q.QuestionID, q);
  }

  const qnIdOf = (qn: QnRow) => qn.OcilId || ocilId("questionnaire", qn.QuestionnaireID);
  const qIdOf = (q: QRow) => q.OcilId || ocilId("question", q.QuestionID);
  const taIdOf = (q: QRow) => ocilId("testaction", q.QuestionID);
  const choiceIdOf = (c: { AnswerID: number; OcilId: string | null }) => c.OcilId || ocilId("choice", c.AnswerID);

  const lines: string[] = [];
  lines.push('<?xml version="1.0" encoding="UTF-8"?>');
  lines.push(`<ocil xmlns="${OCIL_NS}">`);
  lines.push("  <generator>");
  lines.push("    <product_name>XORCISM</product_name>");
  lines.push("    <product_version>1.0</product_version>");
  lines.push("    <schema_version>2.0</schema_version>");
  lines.push(`    <timestamp>${nowTs()}</timestamp>`);
  lines.push("  </generator>");

  // — questionnaires —
  lines.push("  <questionnaires>");
  for (const qn of qns) {
    lines.push(`    <questionnaire id="${esc(qnIdOf(qn))}">`);
    if (qn.QuestionnaireName) lines.push(`      <title>${esc(qn.QuestionnaireName)}</title>`);
    if (qn.QuestionnaireDescription) lines.push(`      <description>${esc(qn.QuestionnaireDescription)}</description>`);
    const op = String(qn.Operator || "AND").toUpperCase() === "OR" ? "OR" : "AND";
    lines.push(`      <actions operator="${op}">`);
    for (const q of qnActions.get(qn.QuestionnaireID) || [])
      lines.push(`        <test_action_ref>${esc(taIdOf(q))}</test_action_ref>`);
    lines.push("      </actions>");
    lines.push("    </questionnaire>");
  }
  lines.push("  </questionnaires>");

  // — test_actions (one per question: maps answers to a result) —
  lines.push("  <test_actions>");
  for (const q of qById.values()) {
    const t = qType(q.QuestionType);
    const id = esc(taIdOf(q)), qref = esc(qIdOf(q));
    if (t === "choice") {
      lines.push(`    <choice_question_test_action id="${id}" question_ref="${qref}">`);
      for (const c of choicesOf.all(q.QuestionID) as ChoiceRow[]) {
        lines.push("      <when_choice>");
        lines.push(`        <choice_ref>${esc(choiceIdOf(c))}</choice_ref>`);
        lines.push(`        <result>${result(c.Result, "PASS")}</result>`);
        lines.push("      </when_choice>");
      }
      lines.push("    </choice_question_test_action>");
    } else if (t === "numeric") {
      lines.push(`    <numeric_question_test_action id="${id}" question_ref="${qref}">`);
      lines.push(`      <when_range><result>${result(q.ResultWhenTrue, "PASS")}</result></when_range>`);
      lines.push("    </numeric_question_test_action>");
    } else if (t === "string") {
      lines.push(`    <string_question_test_action id="${id}" question_ref="${qref}">`);
      lines.push(`      <when_pattern><pattern>.*</pattern><result>${result(q.ResultWhenTrue, "PASS")}</result></when_pattern>`);
      lines.push("    </string_question_test_action>");
    } else {
      lines.push(`    <boolean_question_test_action id="${id}" question_ref="${qref}">`);
      lines.push(`      <when_true><result>${result(q.ResultWhenTrue, "PASS")}</result></when_true>`);
      lines.push(`      <when_false><result>${result(q.ResultWhenFalse, "FAIL")}</result></when_false>`);
      lines.push("    </boolean_question_test_action>");
    }
  }
  lines.push("  </test_actions>");

  // — questions —
  lines.push("  <questions>");
  for (const q of qById.values()) {
    const t = qType(q.QuestionType);
    const id = esc(qIdOf(q));
    const text = esc(q.QuestionText || q.QuestionDescription || q.QuestionName || "");
    if (t === "choice") {
      const choices = choicesOf.all(q.QuestionID) as ChoiceRow[];
      const def = q.DefaultAnswer ? ` default_answer_ref="${esc(q.DefaultAnswer)}"` : "";
      lines.push(`    <choice_question id="${id}"${def}>`);
      lines.push(`      <question_text>${text}</question_text>`);
      for (const c of choices)
        lines.push(`      <choice id="${esc(choiceIdOf(c))}">${esc(c.Answer)}</choice>`);
      lines.push("    </choice_question>");
    } else if (t === "numeric") {
      const def = q.DefaultAnswer ? ` default_answer="${esc(q.DefaultAnswer)}"` : "";
      lines.push(`    <numeric_question id="${id}"${def}><question_text>${text}</question_text></numeric_question>`);
    } else if (t === "string") {
      const def = q.DefaultAnswer ? ` default_answer="${esc(q.DefaultAnswer)}"` : "";
      lines.push(`    <string_question id="${id}"${def}><question_text>${text}</question_text></string_question>`);
    } else {
      const model = (q.Model || "MODEL_YES_NO").toUpperCase() === "MODEL_TRUE_FALSE" ? "MODEL_TRUE_FALSE" : "MODEL_YES_NO";
      const def = q.DefaultAnswer ? ` default_answer="${boolLit(q.DefaultAnswer)}"` : "";
      lines.push(`    <boolean_question id="${id}"${def} model="${model}"><question_text>${text}</question_text></boolean_question>`);
    }
  }
  lines.push("  </questions>");
  lines.push("</ocil>");
  return lines.join("\n");
}

// ── Mini XML parser (no dependency) ───────────────────────────────────────────
export interface XmlNode { name: string; attrs: Record<string, string>; children: XmlNode[]; text: string }
const localName = (n: string): string => { const c = n.indexOf(":"); return c >= 0 ? n.slice(c + 1) : n; };
function decodeEntities(s: string): string {
  return s.replace(/&(#x?[0-9a-fA-F]+|amp|lt|gt|quot|apos);/g, (m, e: string) => {
    if (e[0] === "#") {
      const code = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : m;
    }
    return ({ amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" } as Record<string, string>)[e] ?? m;
  });
}
export function parseXml(src: string): XmlNode {
  const root: XmlNode = { name: "#root", attrs: {}, children: [], text: "" };
  const stack: XmlNode[] = [root];
  let i = 0;
  const n = src.length;
  while (i < n) {
    if (src[i] === "<") {
      if (src.startsWith("<?", i)) { const e = src.indexOf("?>", i); i = e < 0 ? n : e + 2; continue; }
      if (src.startsWith("<!--", i)) { const e = src.indexOf("-->", i); i = e < 0 ? n : e + 3; continue; }
      if (src.startsWith("<![CDATA[", i)) {
        const e = src.indexOf("]]>", i);
        stack[stack.length - 1].text += src.slice(i + 9, e < 0 ? n : e); i = e < 0 ? n : e + 3; continue;
      }
      if (src.startsWith("<!", i)) { const e = src.indexOf(">", i); i = e < 0 ? n : e + 1; continue; }
      const gt = src.indexOf(">", i);
      if (gt < 0) break;
      if (src[i + 1] === "/") { stack.pop(); i = gt + 1; continue; } // closing
      let tag = src.slice(i + 1, gt);
      i = gt + 1;
      const selfClose = tag.endsWith("/");
      if (selfClose) tag = tag.slice(0, -1);
      const nm = tag.match(/^\s*([^\s/>]+)/);
      const name = nm ? nm[1] : tag.trim();
      const attrs: Record<string, string> = {};
      const attrRe = /([^\s=]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
      let am: RegExpExecArray | null;
      const rest = tag.slice(nm ? nm[0].length : 0);
      while ((am = attrRe.exec(rest))) attrs[localName(am[1])] = decodeEntities(am[3] ?? am[4] ?? "");
      const node: XmlNode = { name: localName(name), attrs, children: [], text: "" };
      stack[stack.length - 1].children.push(node);
      if (!selfClose) stack.push(node);
    } else {
      const next = src.indexOf("<", i);
      const txt = src.slice(i, next < 0 ? n : next);
      if (txt.trim()) stack[stack.length - 1].text += decodeEntities(txt);
      i = next < 0 ? n : next;
    }
  }
  return root;
}
const kids = (node: XmlNode | undefined, name: string): XmlNode[] => node ? node.children.filter((c) => c.name === name) : [];
const kid = (node: XmlNode | undefined, name: string): XmlNode | undefined => kids(node, name)[0];
const deepFind = (node: XmlNode, name: string): XmlNode | undefined => {
  for (const c of node.children) { if (c.name === name) return c; const d = deepFind(c, name); if (d) return d; }
  return undefined;
};

// ── OCIL 2.0 VALIDATION (structural + referential, without an XSD engine) ──────────
// Checks the OCIL 2.0 schema rules for the supported subset: required elements
// and attributes, enumerations (ResultType, operator, model), format of the
// ocil:… identifiers, and integrity of the references (test_action_ref → test_action
// → question_ref → question ; choice_ref → choice).
const OCIL_ID_RE = /^ocil:[A-Za-z0-9_.\-]+:(questionnaire|question|choice|testaction|artifact|variable):[1-9][0-9]*$/;
const Q_ELEMENTS = ["boolean_question", "choice_question", "numeric_question", "string_question"];
const TA_ELEMENTS = ["boolean_question_test_action", "choice_question_test_action", "numeric_question_test_action", "string_question_test_action"];

export function validateOcil(xml: string): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  let root: XmlNode;
  try { root = parseXml(xml); } catch (e) { return { ok: false, errors: ["XML mal formé : " + (e as Error).message] }; }
  const ocil = deepFind(root, "ocil");
  if (!ocil) return { ok: false, errors: ["Élément racine <ocil> introuvable."] };
  if (ocil.attrs.xmlns && ocil.attrs.xmlns !== OCIL_NS)
    errors.push(`Namespace inattendu « ${ocil.attrs.xmlns} » (attendu « ${OCIL_NS} »).`);

  const gen = kid(ocil, "generator");
  if (!gen) errors.push("<generator> manquant.");
  else {
    if (!kid(gen, "schema_version")) errors.push("<generator>/<schema_version> manquant.");
    if (!kid(gen, "timestamp")) errors.push("<generator>/<timestamp> manquant.");
  }

  const checkResult = (node: XmlNode | undefined, where: string): void => {
    const r = (kid(node, "result")?.text || "").trim().toUpperCase();
    const hasRef = !!kid(node, "test_action_ref");
    if (!r && !hasRef) errors.push(`${where} : <result> ou <test_action_ref> requis.`);
    else if (r && !RESULTS.has(r)) errors.push(`${where} : résultat « ${r} » invalide (attendu ${[...RESULTS].join("/")}).`);
  };

  // — Questions + choices —
  const questionIds = new Set<string>(), choiceIds = new Set<string>();
  for (const cont of kids(ocil, "questions")) for (const q of cont.children) {
    if (!Q_ELEMENTS.includes(q.name)) { errors.push(`<questions> : élément <${q.name}> inattendu.`); continue; }
    const id = q.attrs.id || "";
    if (!id) errors.push(`<${q.name}> sans attribut id.`);
    else { if (!OCIL_ID_RE.test(id)) errors.push(`Identifiant de question « ${id} » non conforme (ocil:NS:question:N).`); questionIds.add(id); }
    if (!kid(q, "question_text")) errors.push(`<${q.name} id="${id}"> sans <question_text>.`);
    if (q.name === "boolean_question" && q.attrs.model && !["MODEL_YES_NO", "MODEL_TRUE_FALSE"].includes(q.attrs.model))
      errors.push(`boolean_question « ${id} » : model « ${q.attrs.model} » invalide.`);
    if (q.name === "choice_question") {
      const ch = kids(q, "choice");
      if (!ch.length) errors.push(`choice_question « ${id} » sans <choice>.`);
      for (const c of ch) {
        if (!c.attrs.id) errors.push(`<choice> sans id (question ${id}).`);
        else choiceIds.add(c.attrs.id);
      }
    }
  }

  // — Test actions —
  const taIds = new Set<string>();
  for (const cont of kids(ocil, "test_actions")) for (const ta of cont.children) {
    if (!TA_ELEMENTS.includes(ta.name)) { errors.push(`<test_actions> : élément <${ta.name}> inattendu.`); continue; }
    const id = ta.attrs.id || "";
    if (!id) errors.push(`<${ta.name}> sans attribut id.`); else taIds.add(id);
    const qref = ta.attrs.question_ref || "";
    if (!qref) errors.push(`<${ta.name} id="${id}"> sans question_ref.`);
    else if (!questionIds.has(qref)) errors.push(`test_action « ${id} » référence une question inconnue « ${qref} ».`);
    if (ta.name === "boolean_question_test_action") {
      if (!kid(ta, "when_true")) errors.push(`boolean test_action « ${id} » sans <when_true>.`); else checkResult(kid(ta, "when_true"), `when_true (${id})`);
      if (!kid(ta, "when_false")) errors.push(`boolean test_action « ${id} » sans <when_false>.`); else checkResult(kid(ta, "when_false"), `when_false (${id})`);
    } else if (ta.name === "choice_question_test_action") {
      const wc = kids(ta, "when_choice");
      if (!wc.length) errors.push(`choice test_action « ${id} » sans <when_choice>.`);
      for (const w of wc) {
        const cref = (kid(w, "choice_ref")?.text || "").trim();
        if (!cref) errors.push(`when_choice (${id}) sans <choice_ref>.`);
        else if (!choiceIds.has(cref)) errors.push(`when_choice (${id}) référence un choix inconnu « ${cref} ».`);
        checkResult(w, `when_choice (${id})`);
      }
    } else if (ta.name === "numeric_question_test_action") {
      if (!kid(ta, "when_equals") && !kid(ta, "when_range")) errors.push(`numeric test_action « ${id} » sans <when_equals>/<when_range>.`);
    } else if (ta.name === "string_question_test_action") {
      if (!kid(ta, "when_pattern")) errors.push(`string test_action « ${id} » sans <when_pattern>.`);
    }
  }

  // — Questionnaires —
  const qnContainers = kids(ocil, "questionnaires");
  if (!qnContainers.some((c) => kids(c, "questionnaire").length))
    errors.push("Aucun <questionnaire> dans <questionnaires>.");
  for (const cont of qnContainers) for (const qn of kids(cont, "questionnaire")) {
    const id = qn.attrs.id || "";
    if (!id) errors.push("<questionnaire> sans attribut id.");
    else if (!OCIL_ID_RE.test(id)) errors.push(`Identifiant de questionnaire « ${id} » non conforme (ocil:NS:questionnaire:N).`);
    const actions = kid(qn, "actions");
    if (!actions) errors.push(`questionnaire « ${id} » sans <actions>.`);
    else {
      const op = actions.attrs.operator;
      if (op && !["AND", "OR"].includes(op)) errors.push(`questionnaire « ${id} » : operator « ${op} » invalide (AND/OR).`);
      for (const ref of kids(actions, "test_action_ref")) {
        const taId = (ref.text || "").trim();
        if (!taId) errors.push(`questionnaire « ${id} » : <test_action_ref> vide.`);
        else if (!taIds.has(taId)) errors.push(`questionnaire « ${id} » référence un test_action inconnu « ${taId} ».`);
      }
    }
  }
  return { ok: errors.length === 0, errors };
}

// ── IMPORT ──────────────────────────────────────────────────────────────────────
export interface ImportResult { questionnaires: number; questions: number; choices: number; links: number }

export function importOcil(xml: string, tenantId: number | null = null): ImportResult {
  const check = validateOcil(xml);
  if (!check.ok) throw new Error("OCIL invalide :\n• " + check.errors.join("\n• "));
  const root = parseXml(xml);
  const ocil = deepFind(root, "ocil");
  if (!ocil) throw new Error("Document OCIL invalide (élément <ocil> introuvable)");
  const db = getDb("XCOMPLIANCE");

  const out: ImportResult = { questionnaires: 0, questions: 0, choices: 0, links: 0 };
  const tx = db.transaction(() => {
    const nextId = (table: string, col: string): number =>
      (db.prepare(`SELECT COALESCE(MAX(${col}),0)+1 AS n FROM ${table}`).get() as { n: number }).n;
    const findBy = (table: string, idCol: string, ocil: string): number | undefined => {
      const r = db.prepare(`SELECT ${idCol} AS id FROM ${table} WHERE OcilId = ?`).get(ocil) as { id: number } | undefined;
      return r?.id;
    };

    const qIdByOcil = new Map<string, number>();      // ocil question id → QuestionID
    const choiceIdByOcil = new Map<string, number>(); // ocil choice id → AnswerID
    const taToQOcil = new Map<string, string>();      // test_action id → ocil question id

    // 1) Questions (+ choices)
    for (const qContainer of kids(ocil, "questions")) {
      for (const qn of qContainer.children) {
        const type = qn.name.replace(/_question$/, ""); // boolean|choice|numeric|string
        if (!["boolean", "choice", "numeric", "string"].includes(type)) continue;
        const oid = qn.attrs.id || ocilId("question", nextId("QUESTION", "QuestionID"));
        const text = (kid(qn, "question_text")?.text || "").trim();
        let qid = findBy("QUESTION", "QuestionID", oid);
        const model = qn.attrs.model || null;
        const def = qn.attrs.default_answer || qn.attrs.default_answer_ref || null;
        if (qid == null) {
          qid = nextId("QUESTION", "QuestionID");
          db.prepare(`INSERT INTO QUESTION (QuestionID, QuestionName, QuestionDescription, QuestionText, OcilId, QuestionType, DefaultAnswer, Model, CreatedDate, TenantID)
                      VALUES (?,?,?,?,?,?,?,?,?,?)`).run(qid, text.slice(0, 120) || oid, text, text, oid, type, def, model, nowTs(), tenantId);
          out.questions++;
        } else {
          db.prepare(`UPDATE QUESTION SET QuestionText=?, QuestionType=?, DefaultAnswer=?, Model=?, ModifiedDate=? WHERE QuestionID=?`)
            .run(text, type, def, model, nowTs(), qid);
        }
        qIdByOcil.set(oid, qid);

        // choices (choice_question)
        for (const ch of kids(qn, "choice")) {
          const choid = ch.attrs.id || ocilId("choice", nextId("ANSWER", "AnswerID"));
          const label = (ch.text || "").trim();
          let aid = findBy("ANSWER", "AnswerID", choid);
          if (aid == null) {
            aid = nextId("ANSWER", "AnswerID");
            db.prepare("INSERT INTO ANSWER (AnswerID, Answer, OcilId, CreatedDate, TenantID) VALUES (?,?,?,?,?)").run(aid, label, choid, nowTs(), tenantId);
            out.choices++;
          } else {
            db.prepare("UPDATE ANSWER SET Answer=?, ModifiedDate=? WHERE AnswerID=?").run(label, nowTs(), aid);
          }
          choiceIdByOcil.set(choid, aid);
        }
      }
    }

    // 2) test_actions → results (boolean: when_true/when_false ; choice: when_choice)
    for (const taContainer of kids(ocil, "test_actions")) {
      for (const ta of taContainer.children) {
        const qref = ta.attrs.question_ref;
        if (ta.attrs.id && qref) taToQOcil.set(ta.attrs.id, qref);
        const qid = qref ? qIdByOcil.get(qref) : undefined;
        if (qid == null) continue;
        if (ta.name === "boolean_question_test_action") {
          const rt = (kid(kid(ta, "when_true"), "result")?.text || "PASS").trim().toUpperCase();
          const rf = (kid(kid(ta, "when_false"), "result")?.text || "FAIL").trim().toUpperCase();
          db.prepare("UPDATE QUESTION SET ResultWhenTrue=?, ResultWhenFalse=? WHERE QuestionID=?").run(rt, rf, qid);
        } else if (ta.name === "choice_question_test_action") {
          let ord = 0;
          for (const wc of kids(ta, "when_choice")) {
            const cref = (kid(wc, "choice_ref")?.text || "").trim();
            const res = (kid(wc, "result")?.text || "PASS").trim().toUpperCase();
            const aid = choiceIdByOcil.get(cref);
            if (aid == null) continue;
            const existing = db.prepare("SELECT AnswerForQuestionID AS id FROM ANSWERFORQUESTION WHERE QuestionID=? AND AnswerID=?").get(qid, aid) as { id: number } | undefined;
            if (existing) db.prepare("UPDATE ANSWERFORQUESTION SET Result=?, DisplayOrder=? WHERE AnswerForQuestionID=?").run(res, ord, existing.id);
            else db.prepare("INSERT INTO ANSWERFORQUESTION (AnswerForQuestionID, QuestionID, AnswerID, Result, DisplayOrder, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?)")
              .run(nextId("ANSWERFORQUESTION", "AnswerForQuestionID"), qid, aid, res, ord, nowTs(), tenantId);
            ord++;
          }
        }
      }
    }

    // 3) Questionnaires (+ ordered links via the test_action_ref)
    for (const qnContainer of kids(ocil, "questionnaires")) {
      for (const qn of kids(qnContainer, "questionnaire")) {
        const oid = qn.attrs.id || ocilId("questionnaire", nextId("QUESTIONNAIRE", "QuestionnaireID"));
        const title = (kid(qn, "title")?.text || "").trim();
        const desc = (kid(qn, "description")?.text || "").trim();
        const actions = kid(qn, "actions");
        const op = String(actions?.attrs.operator || "AND").toUpperCase() === "OR" ? "OR" : "AND";
        let qnid = findBy("QUESTIONNAIRE", "QuestionnaireID", oid);
        if (qnid == null) {
          qnid = nextId("QUESTIONNAIRE", "QuestionnaireID");
          db.prepare(`INSERT INTO QUESTIONNAIRE (QuestionnaireID, QuestionnaireName, QuestionnaireDescription, OcilId, Operator, CreatedDate, TenantID)
                      VALUES (?,?,?,?,?,?,?)`).run(qnid, title || oid, desc, oid, op, nowTs(), tenantId);
          out.questionnaires++;
        } else {
          db.prepare("UPDATE QUESTIONNAIRE SET QuestionnaireName=?, QuestionnaireDescription=?, Operator=? WHERE QuestionnaireID=?")
            .run(title || oid, desc, op, qnid);
        }
        // rebuilds the links in the order of the <test_action_ref>
        db.prepare("DELETE FROM QUESTIONFORQUESTIONNAIRE WHERE QuestionnaireID=?").run(qnid);
        let ord = 0;
        for (const ref of kids(actions, "test_action_ref")) {
          const taId = (ref.text || "").trim();
          const qOcil = taToQOcil.get(taId);
          const qid = qOcil ? qIdByOcil.get(qOcil) : undefined;
          if (qid == null) continue;
          db.prepare(`INSERT INTO QUESTIONFORQUESTIONNAIRE (QuestionForQuestionnaireID, QuestionnaireID, QuestionID, DisplayOrder, CreatedDate, TenantID)
                      VALUES (?,?,?,?,?,?)`).run(nextId("QUESTIONFORQUESTIONNAIRE", "QuestionForQuestionnaireID"), qnid, qid, ord, nowTs(), tenantId);
          out.links++; ord++;
        }
      }
    }
  });
  tx();
  return out;
}
