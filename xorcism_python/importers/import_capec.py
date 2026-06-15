"""
import_capec.py — Full conversion of Import_capec/Program.cs (C# .NET)
Jerome Athias - XORCISM

Downloads or reads the MITRE CAPEC XML and imports all the data into XATTACK.db
(and partially XORCISM.db for VOCABULARY, KILLCHAIN, OSILAYER, CWE, REFERENCE...).

Supported XML format : CAPEC v3 (namespace http://capec.mitre.org/capec-3)
Official URL         : https://capec.mitre.org/data/xml/capec_latest.xml

Imported sections:
  VOCABULARY, KILLCHAIN, OSILAYER
  Views        → ATTACKPATTERNVIEW, ATTACKPATTERNVIEWRELATIONSHIP
  Categories   → ATTACKPATTERN (category=True)
  Attack_Patterns →
    ATTACKPATTERN, ATTACKPHASE, ATTACKPHASEFORATTACKPATTERN
    ATTACKSTEP, ATTACKSTEPTECHNIQUE, ATTACKSTEPOUTCOME
    ATTACKPREREQUISITE, ATTACKPREREQUISITEFORATTACKPATTERN
    ATTACKRESOURCE,     ATTACKRESOURCEFORATTACKPATTERN
    ATTACKMETHOD,       ATTACKMETHODFORATTACKPATTERN
    ATTACKEXAMPLE,      ATTACKEXAMPLEFORATTACKPATTERN
    ATTACKPURPOSE,      ATTACKPURPOSEFORATTACKPATTERN
    ATTACKPAYLOAD,      ATTACKPAYLOADFORATTACKPATTERN
    ATTACKPAYLOADIMPACT, ATTACKPAYLOADIMPACTFORATTACKPATTERN
    ATTACKPATTERNCWE
    ATTACKPATTERNRELATIONSHIP
    ATTACKPATTERNINDICATORWARNING
    ATTACKPATTERNMITIGATION
    ATTACKCONSEQUENCE, ATTACKPATTERNATTACKCONSEQUENCE
    ATTACKPATTERNATTACKCONSEQUENCESCOPE
    ATTACKTECHNICALIMPACT, ATTACKPATTERNATTACKTECHNICALIMPACT
    ATTACKPATTERNOBFUSCATIONTECHNIQUE
    ATTACKPATTERNNOTE, ATTACKPATTERNNOTES
    ATTACKPATTERNREFERENCE, REFERENCE, AUTHOR, REFERENCEAUTHOR
    ORGANISATION, CWE

Usage:
    python import_capec.py [--xml capec_latest.xml] [--download]
"""

import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

import requests
from sqlalchemy import event, text, Integer, BigInteger, SmallInteger
from sqlalchemy.orm import Mapper

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python.models.base import session_scope
from xorcism_python.utils import log

MODULE = "ImportCAPEC"
CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"

# ─── Auto-increment of integer primary keys ──────────────────────────────────
# The XORCISM.db / XATTACK.db tables were created with columns
# "<Id> INTEGER NOT NULL" WITHOUT a PRIMARY KEY clause -> SQLite does not
# auto-increment them (they are not rowid aliases). SQLAlchemy then omits the
# column at INSERT time, which triggers a NOT NULL IntegrityError.
#
# This listener assigns MAX(<col>)+1 to any single-column integer PK left empty,
# right before the INSERT. An in-memory counter (per connection + table) ensures
# uniqueness even when several rows of the same table are inserted in the same
# flush (MAX() does not yet "see" the rows of the in-progress flush).

_pk_counters: dict = {}
_INT_TYPES = (Integer, BigInteger, SmallInteger)


def _auto_pk(mapper, connection, target) -> None:
    pk_cols = mapper.primary_key
    if len(pk_cols) != 1:
        return
    col = pk_cols[0]
    if not isinstance(col.type, _INT_TYPES):
        return  # textual PK (e.g. CWEID): provided explicitly

    attr = mapper.get_property_by_column(col).key
    if getattr(target, attr, None) is not None:
        return  # value already set

    tbl = mapper.local_table.name
    # Key stable per database (and not per id(connection), which is recycled
    # after batch commits -> ID range collisions).
    key = (str(connection.engine.url), tbl)

    # Current MAX in DB (also sees the INSERTs of the in-progress flush on this
    # same connection). We take the max with the in-memory counter to stay
    # strictly monotonic whatever happens (commits, recycling...).
    db_max = connection.execute(
        text(f'SELECT COALESCE(MAX("{col.name}"), 0) FROM "{tbl}"')
    ).scalar()
    nxt = max(_pk_counters.get(key, 0), int(db_max or 0)) + 1
    _pk_counters[key] = nxt
    setattr(target, attr, nxt)


# Registered once for ALL mappers (propagates to subclasses)
event.listen(Mapper, "before_insert", _auto_pk)

# CAPEC v3 namespace
NS = "http://capec.mitre.org/capec-3"

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _tag(name: str) -> str:
    return f"{{{NS}}}{name}"


def _text(el: Optional[ET.Element]) -> str:
    """Extract all the text of an element (recursive)."""
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def _clean(s: str) -> str:
    """Equivalent of the C# CleaningCAPECString()."""
    s = s.replace("<capec:Text>", "").replace("</capec:Text>", "")
    s = s.replace("<capec:text>", "").replace("</capec:text>", "")
    s = s.replace("\r\n", " ").replace("\n", " ").replace("\t", " ")
    while "  " in s:
        s = s.replace("  ", " ")
    return s.strip()


def _trunc(s: Optional[str], n: int) -> Optional[str]:
    if not s:
        return None
    return s[:n]


def _now() -> datetime:
    # UTC timezone-aware then made naive: keeps exactly the stored format
    # (without offset) while avoiding datetime.utcnow() (deprecated).
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _get_or_create(session, model_cls, filter_kwargs: dict, create_kwargs: dict):
    """Look up a record; create it if it does not exist. Returns the object."""
    obj = session.query(model_cls).filter_by(**filter_kwargs).first()
    if obj is None:
        obj = model_cls(**{**filter_kwargs, **create_kwargs})
        session.add(obj)
        session.flush()
    return obj


def _org_known_as(name: str) -> str:
    mapping = {
        "GFI": "GFI", "MITRE": "MITRE", "SCAP.com": "SCAP",
        "ThreatGuard": "ThreatGuard", "Hewlett-Packard": "HP",
        "Symantec": "Symantec", "SecPod": "SecPod", "Gideon": "Gideon",
        "Secure Elements": "Secure Elements", "Lumension": "Lumension",
        "McAfee": "McAfee", "BigFix": "BigFix",
        "National Institute of Standards and Technology": "NIST",
        "SAINT": "SAINT", "Pivotal": "Pivotal", "BAE": "BAE",
    }
    for key, alias in mapping.items():
        if key in name:
            return alias
    return name[:50]


# ─── Download ────────────────────────────────────────────────────────────────

def download_capec(dest: str) -> None:
    log(MODULE, f"Downloading {CAPEC_URL}")
    resp = requests.get(CAPEC_URL, timeout=120)
    resp.raise_for_status()
    with open(dest, "wb") as f:
        f.write(resp.content)
    log(MODULE, f"File saved: {dest}")


# ─── Phase 1: VOCABULARY / KILLCHAIN / OSILAYER ──────────────────────────────

def _setup_vocabulary(xorcism_session) -> int:
    """Returns the VocabularyID for CAPEC."""
    from xorcism_python.models.xorcism import VOCABULARY
    vocab = xorcism_session.query(VOCABULARY).filter_by(
        VocabularyName="CAPEC"
    ).first()
    if vocab is None:
        vocab = VOCABULARY(
            VocabularyName="CAPEC",
            VocabularyVersion="3",
            CreatedDate=_now(),
        )
        xorcism_session.add(vocab)
        xorcism_session.flush()
        log(MODULE, f"VOCABULARY CAPEC created (ID={vocab.VocabularyID})")
    return vocab.VocabularyID


def _setup_killchain(xorcism_session, vocab_id: int) -> int:
    """Returns the KillChainID for CAPEC."""
    from xorcism_python.models.xorcism import KILLCHAIN
    kc = xorcism_session.query(KILLCHAIN).filter_by(
        KillChainName="CAPEC", VocabularyID=vocab_id
    ).first()
    if kc is None:
        kc = KILLCHAIN(
            KillChainName="CAPEC",
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        )
        xorcism_session.add(kc)
        xorcism_session.flush()
        log(MODULE, f"KILLCHAIN CAPEC created (ID={kc.KillChainID})")
    return kc.KillChainID


def _setup_osilayers(xorcism_session, vocab_id: int) -> None:
    from xorcism_python.models.xorcism import OSILAYER
    layers = [
        "Physical Layer", "Data Link Layer", "Network Layer",
        "Transport Layer", "Session Layer", "Presentation Layer", "Application Layer",
    ]
    for i, name in enumerate(layers, start=1):
        exists = xorcism_session.query(OSILAYER).filter_by(OSILayerName=name).first()
        if exists is None:
            xorcism_session.add(OSILAYER(
                OSILayerID=i,
                OSILayerName=name,
                VocabularyID=vocab_id,
            ))
    xorcism_session.flush()


# ─── Phase 2: Views ──────────────────────────────────────────────────────────

def _import_views(root: ET.Element, attack_session, vocab_id: int) -> None:
    from xorcism_python.models.xattack import ATTACKPATTERNVIEW, ATTACKPATTERNVIEWRELATIONSHIP, ATTACKPATTERN

    views = root.findall(f".//{_tag('View')}")
    log(MODULE, f"Views found: {len(views)}")

    for view_el in views:
        view_vocab_id = int(view_el.get("ID", 0))
        view_name = view_el.get("Name", "")
        view_status = view_el.get("Type", "") or view_el.get("Status", "")

        apv = attack_session.query(ATTACKPATTERNVIEW).filter_by(
            ViewVocabularyID=view_vocab_id
        ).first()
        if apv is None:
            apv = ATTACKPATTERNVIEW(
                ViewVocabularyID=view_vocab_id,
                CreatedDate=_now(),
            )
            attack_session.add(apv)

        apv.AttackPatternViewName = _trunc(view_name, 255)
        apv.ViewStatus = _trunc(view_status, 50)
        apv.VocabularyID = vocab_id

        # Objective / Filter / Structure
        obj_el = view_el.find(_tag("Objective"))
        if obj_el is not None:
            apv.AttackPatternViewDescription = _trunc(_clean(_text(obj_el)), 4000)
        filter_el = view_el.find(_tag("Filter"))
        if filter_el is not None:
            apv.View_Filter = _trunc(_text(filter_el), 255)

        attack_session.flush()

        # Members / Relationships
        members_el = view_el.find(_tag("Members"))
        if members_el is None:
            members_el = view_el.find(_tag("Relationships"))
        if members_el is not None:
            for member_el in members_el:
                capec_ref_id = None
                nature = member_el.get("Nature", "HasMember")
                target_form = member_el.get("Type", "")
                # ID attribute or CAPEC_ID child
                capec_ref_id_str = member_el.get("CAPEC_ID") or member_el.get("CAPEC-ID")
                if capec_ref_id_str:
                    try:
                        capec_ref_id = int(capec_ref_id_str)
                    except ValueError:
                        pass

                if capec_ref_id is None:
                    continue

                capec_id_str = f"CAPEC-{capec_ref_id}"
                ap = attack_session.query(ATTACKPATTERN).filter_by(
                    capec_id=capec_id_str
                ).first()
                if ap is None:
                    ap = ATTACKPATTERN(
                        capec_id=capec_id_str,
                        VocabularyID=vocab_id,
                        CreatedDate=_now(),
                    )
                    attack_session.add(ap)
                    attack_session.flush()

                rel = attack_session.query(ATTACKPATTERNVIEWRELATIONSHIP).filter_by(
                    AttackPatternViewID=apv.AttackPatternViewID,
                    AttackPatternID=ap.AttackPatternID,
                ).first()
                if rel is None:
                    attack_session.add(ATTACKPATTERNVIEWRELATIONSHIP(
                        AttackPatternViewID=apv.AttackPatternViewID,
                        AttackPatternID=ap.AttackPatternID,
                        Relationship_Nature=_trunc(nature, 50),
                        Relationship_Target_Form=_trunc(target_form, 50),
                        VocabularyID=vocab_id,
                        CreatedDate=_now(),
                    ))

    attack_session.flush()


# ─── Phase 3: Categories ─────────────────────────────────────────────────────

def _import_categories(root: ET.Element, attack_session, xorcism_session, vocab_id: int) -> None:
    from xorcism_python.models.xattack import ATTACKPATTERN, ATTACKPATTERNRELATIONSHIP
    from xorcism_python.models.xorcism import CWE
    from xorcism_python.models.xattack import ATTACKPATTERNCWE

    cats = root.findall(f".//{_tag('Category')}")
    log(MODULE, f"Categories found: {len(cats)}")

    for cat_el in cats:
        capec_id_str = f"CAPEC-{cat_el.get('ID')}"
        name = _clean(cat_el.get("Name", ""))
        status = cat_el.get("Status", "")

        desc_el = cat_el.find(f".//{_tag('Summary')}") or cat_el.find(_tag("Description"))
        description = _clean(_text(desc_el)) if desc_el is not None else ""

        ap = attack_session.query(ATTACKPATTERN).filter_by(capec_id=capec_id_str).first()
        if ap is None:
            ap = ATTACKPATTERN(capec_id=capec_id_str, CreatedDate=_now())
            attack_session.add(ap)

        ap.category = True
        ap.AttackPatternName = _trunc(name, 255)
        ap.PatternStatus = _trunc(status, 50)
        ap.AttackPatternDescription = _trunc(description, 4000)
        ap.VocabularyID = vocab_id
        attack_session.flush()

        # Related Weaknesses
        for rw_el in cat_el.findall(f".//{_tag('Related_Weakness')}"):
            cwe_id_str = f"CWE-{rw_el.get('CWE_ID')}"
            relationship = rw_el.get("Nature", "")
            _ensure_cwe(xorcism_session, cwe_id_str, vocab_id)
            _ensure_attackpatterncwe(attack_session, ap.AttackPatternID, cwe_id_str, relationship, vocab_id)

        # Relationships
        for rel_el in cat_el.findall(f".//{_tag('Related_Attack_Pattern')}"):
            _import_relationship(attack_session, ap, rel_el, vocab_id)

    attack_session.flush()
    xorcism_session.flush()


# ─── Phase 4: Attack_Patterns ────────────────────────────────────────────────

def _import_attack_patterns(root: ET.Element, attack_session, xorcism_session, vocab_id: int) -> None:
    from xorcism_python.models.xattack import ATTACKPATTERN

    patterns = root.findall(f".//{_tag('Attack_Pattern')}")
    log(MODULE, f"Attack Patterns found: {len(patterns)}")

    for i, ap_el in enumerate(patterns):
        capec_id_str = f"CAPEC-{ap_el.get('ID')}"
        name = _clean(ap_el.get("Name", ""))
        abstraction = ap_el.get("Abstraction", "")
        status = ap_el.get("Status", "")

        desc_el = ap_el.find(_tag("Description"))
        description = _clean(_text(desc_el)) if desc_el is not None else ""

        likelihood_el = ap_el.find(_tag("Likelihood_Of_Attack"))
        likelihood = _clean(_text(likelihood_el)) if likelihood_el is not None else ""

        severity_el = ap_el.find(_tag("Typical_Severity"))
        severity = _clean(_text(severity_el)) if severity_el is not None else ""

        ap = attack_session.query(ATTACKPATTERN).filter_by(capec_id=capec_id_str).first()
        if ap is None:
            ap = ATTACKPATTERN(capec_id=capec_id_str, CreatedDate=_now())
            attack_session.add(ap)

        ap.AttackPatternName = _trunc(name, 255)
        ap.AttackPatternDescription = _trunc(description, 4000)
        ap.PatternAbstraction = _trunc(abstraction, 50)
        ap.PatternStatus = _trunc(status, 50)
        ap.TypicalSeverity = _trunc(severity, 50)
        ap.VocabularyID = vocab_id
        attack_session.flush()

        pat_id = ap.AttackPatternID

        # — Execution_Flow (phases, steps, techniques) —
        exec_flow_el = ap_el.find(_tag("Execution_Flow"))
        if exec_flow_el is not None:
            _import_execution_flow(attack_session, pat_id, exec_flow_el, vocab_id)

        # — Prerequisites —
        prereqs_el = ap_el.find(_tag("Prerequisites"))
        if prereqs_el is not None:
            _import_prerequisites(attack_session, pat_id, prereqs_el, vocab_id)

        # — Skills_Required (stored as a prerequisite) —
        skills_el = ap_el.find(_tag("Skills_Required"))
        if skills_el is not None:
            _import_skills(attack_session, pat_id, skills_el, vocab_id)

        # — Resources_Required —
        res_el = ap_el.find(_tag("Resources_Required"))
        if res_el is not None:
            _import_resources(attack_session, pat_id, res_el, vocab_id)

        # — Consequences —
        cons_el = ap_el.find(_tag("Consequences"))
        if cons_el is not None:
            _import_consequences(attack_session, pat_id, cons_el, vocab_id)

        # — Mitigations —
        mit_el = ap_el.find(_tag("Mitigations"))
        if mit_el is not None:
            _import_mitigations(attack_session, pat_id, mit_el, vocab_id)

        # — Indicators —
        ind_el = ap_el.find(_tag("Indicators"))
        if ind_el is not None:
            _import_indicators(attack_session, pat_id, ind_el, vocab_id)

        # — Example_Instances —
        ex_el = ap_el.find(_tag("Example_Instances"))
        if ex_el is not None:
            _import_examples(attack_session, pat_id, capec_id_str, ex_el, vocab_id)

        # — Taxonomy_Mappings (Purposes) —
        tax_el = ap_el.find(_tag("Taxonomy_Mappings"))
        if tax_el is not None:
            _import_purposes(attack_session, pat_id, tax_el, vocab_id)

        # — Payload (Injection_Vector / Payload) —
        payload_el = ap_el.find(_tag("Payload"))
        if payload_el is not None:
            _import_payload(attack_session, pat_id, payload_el, vocab_id)

        # — Related_Weaknesses —
        rw_el = ap_el.find(_tag("Related_Weaknesses"))
        if rw_el is not None:
            for rw in rw_el.findall(_tag("Related_Weakness")):
                cwe_id_str = f"CWE-{rw.get('CWE_ID')}"
                relationship = rw.get("Nature", "")
                _ensure_cwe(xorcism_session, cwe_id_str, vocab_id)
                _ensure_attackpatterncwe(attack_session, pat_id, cwe_id_str, relationship, vocab_id)

        # — Related_Attack_Patterns —
        rap_el = ap_el.find(_tag("Related_Attack_Patterns"))
        if rap_el is not None:
            for rel_el in rap_el.findall(_tag("Related_Attack_Pattern")):
                _import_relationship(attack_session, ap, rel_el, vocab_id)

        # — References —
        refs_el = ap_el.find(_tag("References"))
        if refs_el is not None:
            _import_references(attack_session, xorcism_session, pat_id, refs_el, vocab_id)

        # — Other_Notes —
        notes_el = ap_el.find(_tag("Notes"))
        if notes_el is not None:
            _import_notes(attack_session, pat_id, notes_el, vocab_id)

        # Batch commit every 50 to avoid OutOfMemory
        if (i + 1) % 50 == 0:
            attack_session.commit()
            xorcism_session.commit()
            log(MODULE, f"  {i+1} patterns processed...")

    attack_session.flush()
    xorcism_session.flush()


# ─── Sub-importers ────────────────────────────────────────────────────────────

def _import_execution_flow(attack_session, pat_id: int, el: ET.Element, vocab_id: int) -> None:
    from xorcism_python.models.xattack import (
        ATTACKPHASE, ATTACKPHASEFORATTACKPATTERN,
        ATTACKSTEP, ATTACKSTEPTECHNIQUE,
    )

    phase_order = 0
    for attack_phase_el in el.findall(_tag("Attack_Phase")):
        phase_order += 1
        phase_name = _clean(attack_phase_el.get("Phase", "") or _text(attack_phase_el.find(_tag("Phase"))) if attack_phase_el.find(_tag("Phase")) is not None else "")
        if not phase_name:
            phase_name = attack_phase_el.get("Name", "") or f"Phase {phase_order}"
        phase_name = _clean(phase_name)

        # ATTACKPHASE (lookup/create par nom)
        ap_phase = attack_session.query(ATTACKPHASE).filter_by(
            AttackPhaseName=phase_name
        ).first()
        if ap_phase is None:
            ap_phase = ATTACKPHASE(
                AttackPhaseName=phase_name,
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            attack_session.add(ap_phase)
            attack_session.flush()

        # ATTACKPHASEFORATTACKPATTERN
        phase_for_pat = attack_session.query(ATTACKPHASEFORATTACKPATTERN).filter_by(
            AttackPatternID=pat_id,
            AttackPhaseOrder=phase_order,
            VocabularyID=vocab_id,
        ).first()
        if phase_for_pat is None:
            phase_for_pat = ATTACKPHASEFORATTACKPATTERN(
                AttackPatternID=pat_id,
                AttackPhaseID=ap_phase.AttackPhaseID,
                AttackPhaseOrder=phase_order,
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            attack_session.add(phase_for_pat)
            attack_session.flush()
        else:
            phase_for_pat.AttackPhaseID = ap_phase.AttackPhaseID

        attack_phase_for_pat_id = phase_for_pat.AttackPatternAttackPhaseID

        # Steps
        step_order = 0
        for step_el in attack_phase_el.findall(_tag("Attack_Step")):
            step_order += 1
            step_title = _clean(_text(step_el.find(_tag("Step_Attack_Title")) or step_el.find(_tag("Attack_Step_Title"))))
            step_desc = _clean(_text(step_el.find(_tag("Step_Attack_Description")) or step_el.find(_tag("Attack_Step_Description"))))

            step = attack_session.query(ATTACKSTEP).filter_by(
                AttackPatternAttackPhaseID=attack_phase_for_pat_id,
                AttackStepOrder=step_order,
            ).first()
            if step is None:
                step = ATTACKSTEP(
                    AttackPatternAttackPhaseID=attack_phase_for_pat_id,
                    AttackStepOrder=step_order,
                    VocabularyID=vocab_id,
                    CreatedDate=_now(),
                )
                attack_session.add(step)

            step.Attack_Step_Title = _trunc(step_title, 255)
            step.Attack_Step_Description = _trunc(step_desc, 4000)
            attack_session.flush()

            # Techniques (Attack_Step_Technique)
            tech_order = 0
            for tech_el in step_el.findall(f".//{_tag('Attack_Step_Technique')}"):
                tech_order += 1
                tech_desc = _clean(_text(tech_el))
                # Stored in ATTACKSTEPTECHNIQUE without an ATTACKTECHNIQUE reference (free text)
                exist = attack_session.query(ATTACKSTEPTECHNIQUE).filter_by(
                    AttackStepID=step.AttackStepID,
                    AttackStepTechniqueOrder=tech_order,
                ).first()
                if exist is None:
                    attack_session.add(ATTACKSTEPTECHNIQUE(
                        AttackStepID=step.AttackStepID,
                        AttackStepTechniqueOrder=tech_order,
                        VocabularyID=vocab_id,
                        CreatedDate=_now(),
                    ))

    attack_session.flush()


def _import_prerequisites(attack_session, pat_id: int, el: ET.Element, vocab_id: int) -> None:
    from xorcism_python.models.xattack import ATTACKPREREQUISITE, ATTACKPREREQUISITEFORATTACKPATTERN

    for prereq_el in el.findall(_tag("Prerequisite")):
        text = _clean(_text(prereq_el))
        if not text:
            continue

        prereq = attack_session.query(ATTACKPREREQUISITE).filter_by(
            PrerequisiteText=text[:4000]
        ).first()
        if prereq is None:
            prereq = ATTACKPREREQUISITE(
                PrerequisiteText=_trunc(text, 4000),
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            attack_session.add(prereq)
            attack_session.flush()

        link = attack_session.query(ATTACKPREREQUISITEFORATTACKPATTERN).filter_by(
            AttackPatternID=pat_id,
            AttackPrerequisiteID=prereq.AttackPrerequisiteID,
        ).first()
        if link is None:
            attack_session.add(ATTACKPREREQUISITEFORATTACKPATTERN(
                AttackPatternID=pat_id,
                AttackPrerequisiteID=prereq.AttackPrerequisiteID,
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            ))

    attack_session.flush()


def _import_skills(attack_session, pat_id: int, el: ET.Element, vocab_id: int) -> None:
    """Skills_Required -> stored as a prerequisite."""
    from xorcism_python.models.xattack import ATTACKPREREQUISITE, ATTACKPREREQUISITEFORATTACKPATTERN

    for skill_el in el.findall(_tag("Skill")):
        level = skill_el.get("Level", "")
        text = _clean(_text(skill_el))
        combined = f"[{level}] {text}".strip(" []") if level else text
        if not combined:
            continue

        prereq = attack_session.query(ATTACKPREREQUISITE).filter_by(
            PrerequisiteText=combined[:4000]
        ).first()
        if prereq is None:
            prereq = ATTACKPREREQUISITE(
                PrerequisiteText=_trunc(combined, 4000),
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            attack_session.add(prereq)
            attack_session.flush()

        link = attack_session.query(ATTACKPREREQUISITEFORATTACKPATTERN).filter_by(
            AttackPatternID=pat_id,
            AttackPrerequisiteID=prereq.AttackPrerequisiteID,
        ).first()
        if link is None:
            attack_session.add(ATTACKPREREQUISITEFORATTACKPATTERN(
                AttackPatternID=pat_id,
                AttackPrerequisiteID=prereq.AttackPrerequisiteID,
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            ))

    attack_session.flush()


def _import_resources(attack_session, pat_id: int, el: ET.Element, vocab_id: int) -> None:
    from xorcism_python.models.xattack import ATTACKRESOURCE, ATTACKRESOURCEFORATTACKPATTERN

    for res_el in el.findall(_tag("Resource")):
        text = _clean(_text(res_el))
        if not text:
            continue

        res = attack_session.query(ATTACKRESOURCE).filter_by(
            AttackResourceText=text[:4000]
        ).first()
        if res is None:
            res = ATTACKRESOURCE(
                AttackResourceText=_trunc(text, 4000),
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            attack_session.add(res)
            attack_session.flush()

        link = attack_session.query(ATTACKRESOURCEFORATTACKPATTERN).filter_by(
            AttackPatternID=pat_id,
            AttackResourceID=res.AttackResourceID,
        ).first()
        if link is None:
            attack_session.add(ATTACKRESOURCEFORATTACKPATTERN(
                AttackPatternID=pat_id,
                AttackResourceID=res.AttackResourceID,
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            ))

    attack_session.flush()


def _import_consequences(attack_session, pat_id: int, el: ET.Element, vocab_id: int) -> None:
    from xorcism_python.models.xattack import (
        ATTACKCONSEQUENCE, ATTACKPATTERNATTACKCONSEQUENCE,
        ATTACKPATTERNATTACKCONSEQUENCESCOPE, ATTACKSCOPE,
        ATTACKTECHNICALIMPACT, ATTACKPATTERNATTACKTECHNICALIMPACT,
    )

    order = 0
    for cons_el in el.findall(_tag("Consequence")):
        order += 1
        note = _clean(_text(cons_el.find(_tag("Note")))) if cons_el.find(_tag("Note")) is not None else ""
        scopes = [_clean(_text(s)) for s in cons_el.findall(_tag("Scope")) if _text(s)]
        impacts = [_clean(_text(i)) for i in cons_el.findall(_tag("Impact")) if _text(i)]

        # ATTACKCONSEQUENCE (texte = scopes + impacts)
        consequence_text = "; ".join(scopes + impacts)
        if not consequence_text:
            continue

        cons = attack_session.query(ATTACKCONSEQUENCE).filter_by(
            Consequence=consequence_text[:500]
        ).first()
        if cons is None:
            cons = ATTACKCONSEQUENCE(
                Consequence=_trunc(consequence_text, 500),
                ConsequenceNote=_trunc(note, 2000),
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            attack_session.add(cons)
            attack_session.flush()

        ap_cons = attack_session.query(ATTACKPATTERNATTACKCONSEQUENCE).filter_by(
            AttackPatternID=pat_id,
            AttackConsequenceID=cons.AttackConsequenceID,
        ).first()
        if ap_cons is None:
            ap_cons = ATTACKPATTERNATTACKCONSEQUENCE(
                AttackPatternID=pat_id,
                AttackConsequenceID=cons.AttackConsequenceID,
                CAPECAttackConsequenceOrder=order,
                Consequence_Note=_trunc(note, 2000),
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            attack_session.add(ap_cons)
            attack_session.flush()

        # Scopes → ATTACKPATTERNATTACKCONSEQUENCESCOPE
        for scope_name in scopes:
            scope = attack_session.query(ATTACKSCOPE).filter_by(
                ConsequenceScope=scope_name
            ).first()
            if scope is None:
                scope = ATTACKSCOPE(
                    ConsequenceScope=_trunc(scope_name, 100),
                    VocabularyID=vocab_id,
                    CreatedDate=_now(),
                )
                attack_session.add(scope)
                attack_session.flush()

            scope_link = attack_session.query(ATTACKPATTERNATTACKCONSEQUENCESCOPE).filter_by(
                AttackPatternAttackConsequenceID=ap_cons.AttackPatternAttackConsequenceID,
                AttackScopeID=scope.AttackScopeID,
            ).first()
            if scope_link is None:
                attack_session.add(ATTACKPATTERNATTACKCONSEQUENCESCOPE(
                    AttackPatternAttackConsequenceID=ap_cons.AttackPatternAttackConsequenceID,
                    AttackScopeID=scope.AttackScopeID,
                    VocabularyID=vocab_id,
                    CreatedDate=_now(),
                ))

        # Technical impacts
        for impact_name in impacts:
            ti = attack_session.query(ATTACKTECHNICALIMPACT).filter_by(
                ConsequenceTechnicalImpact=impact_name
            ).first()
            if ti is None:
                ti = ATTACKTECHNICALIMPACT(
                    ConsequenceTechnicalImpact=_trunc(impact_name, 100),
                    VocabularyID=vocab_id,
                    CreatedDate=_now(),
                )
                attack_session.add(ti)
                attack_session.flush()

            ti_link = attack_session.query(ATTACKPATTERNATTACKTECHNICALIMPACT).filter_by(
                AttackPatternAttackConsequenceID=ap_cons.AttackPatternAttackConsequenceID,
                AttackTechnicalImpactID=ti.AttackTechnicalImpactID,
            ).first()
            if ti_link is None:
                attack_session.add(ATTACKPATTERNATTACKTECHNICALIMPACT(
                    AttackPatternAttackConsequenceID=ap_cons.AttackPatternAttackConsequenceID,
                    AttackTechnicalImpactID=ti.AttackTechnicalImpactID,
                    VocabularyID=vocab_id,
                    CreatedDate=_now(),
                ))

    attack_session.flush()


def _import_mitigations(attack_session, pat_id: int, el: ET.Element, vocab_id: int) -> None:
    # ATTACKPATTERNMITIGATION requires MitigationID (FK to a MITIGATION table absent from the XML)
    # We only log the text for future processing
    for mit_el in el.findall(_tag("Mitigation")):
        text = _clean(_text(mit_el))
        if text:
            log(MODULE, f"  [TODO] Mitigation for pat_id={pat_id}: {text[:80]}")


def _import_indicators(attack_session, pat_id: int, el: ET.Element, vocab_id: int) -> None:
    from xorcism_python.models.xattack import ATTACKPATTERNINDICATORWARNING

    order = 0
    for ind_el in el.findall(_tag("Indicator")):
        order += 1
        text = _clean(_text(ind_el))
        if not text:
            continue
        exist = attack_session.query(ATTACKPATTERNINDICATORWARNING).filter_by(
            AttackPatternID=pat_id,
            AttackPatternIndicatorWarningOrder=order,
        ).first()
        if exist is None:
            attack_session.add(ATTACKPATTERNINDICATORWARNING(
                AttackPatternID=pat_id,
                AttackPatternIndicatorWarningOrder=order,
                IndicatorWarningAttack=_trunc(text, 4000),
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            ))

    attack_session.flush()


def _import_examples(attack_session, pat_id: int, capec_id_str: str, el: ET.Element, vocab_id: int) -> None:
    from xorcism_python.models.xattack import ATTACKEXAMPLE, ATTACKEXAMPLEFORATTACKPATTERN

    order = 0
    for ex_el in el.findall(_tag("Example")):
        order += 1
        text = _clean(_text(ex_el))
        if not text:
            continue

        ex = attack_session.query(ATTACKEXAMPLE).filter_by(
            AttackExampleDescription=text[:4000]
        ).first()
        if ex is None:
            ex = ATTACKEXAMPLE(
                AttackExampleDescription=_trunc(text, 4000),
                AttackExampleVocabularyID=order,
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            attack_session.add(ex)
            attack_session.flush()

        link = attack_session.query(ATTACKEXAMPLEFORATTACKPATTERN).filter_by(
            AttackPatternID=pat_id,
            AttackExampleID=ex.AttackExampleID,
        ).first()
        if link is None:
            attack_session.add(ATTACKEXAMPLEFORATTACKPATTERN(
                AttackPatternID=pat_id,
                AttackExampleID=ex.AttackExampleID,
                capec_id=capec_id_str,
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            ))

    attack_session.flush()


def _import_purposes(attack_session, pat_id: int, el: ET.Element, vocab_id: int) -> None:
    from xorcism_python.models.xattack import ATTACKPURPOSE, ATTACKPURPOSEFORATTACKPATTERN

    for tax_el in el.findall(_tag("Taxonomy_Mapping")):
        tax_name = tax_el.get("Taxonomy_Name", "")
        entry_name_el = tax_el.find(_tag("Entry_Name"))
        entry_name = _clean(_text(entry_name_el)) if entry_name_el is not None else ""
        if not entry_name:
            continue

        purpose_name = f"{tax_name}: {entry_name}" if tax_name else entry_name

        purpose = attack_session.query(ATTACKPURPOSE).filter_by(
            AttackPurposeName=purpose_name[:255]
        ).first()
        if purpose is None:
            purpose = ATTACKPURPOSE(
                AttackPurposeName=_trunc(purpose_name, 255),
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            attack_session.add(purpose)
            attack_session.flush()

        link = attack_session.query(ATTACKPURPOSEFORATTACKPATTERN).filter_by(
            AttackPatternID=pat_id,
            AttackPurposeID=purpose.AttackPurposeID,
        ).first()
        if link is None:
            attack_session.add(ATTACKPURPOSEFORATTACKPATTERN(
                AttackPatternID=pat_id,
                AttackPurposeID=purpose.AttackPurposeID,
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            ))

    attack_session.flush()


def _import_payload(attack_session, pat_id: int, el: ET.Element, vocab_id: int) -> None:
    from xorcism_python.models.xattack import ATTACKPAYLOAD, ATTACKPAYLOADFORATTACKPATTERN

    text = _clean(_text(el))
    if not text:
        return

    payload = attack_session.query(ATTACKPAYLOAD).filter_by(
        PayloadText=text[:4000]
    ).first()
    if payload is None:
        payload = ATTACKPAYLOAD(
            PayloadText=_trunc(text, 4000),
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        )
        attack_session.add(payload)
        attack_session.flush()

    link = attack_session.query(ATTACKPAYLOADFORATTACKPATTERN).filter_by(
        AttackPatternID=pat_id,
        AttackPayloadID=payload.AttackPayloadID,
    ).first()
    if link is None:
        attack_session.add(ATTACKPAYLOADFORATTACKPATTERN(
            AttackPatternID=pat_id,
            AttackPayloadID=payload.AttackPayloadID,
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        ))

    attack_session.flush()


def _ensure_cwe(xorcism_session, cwe_id_str: str, vocab_id: int) -> None:
    from xorcism_python.models.xorcism import CWE
    exists = xorcism_session.query(CWE).filter_by(CWEID=cwe_id_str).first()
    if exists is None:
        xorcism_session.add(CWE(
            CWEID=cwe_id_str,
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        ))
        xorcism_session.flush()


def _ensure_attackpatterncwe(attack_session, pat_id: int, cwe_id_str: str, relationship: str, vocab_id: int) -> None:
    from xorcism_python.models.xattack import ATTACKPATTERNCWE
    link = attack_session.query(ATTACKPATTERNCWE).filter_by(
        AttackPatternID=pat_id, CWEID=cwe_id_str
    ).first()
    if link is None:
        attack_session.add(ATTACKPATTERNCWE(
            AttackPatternID=pat_id,
            CWEID=cwe_id_str,
            WeaknessRelationship=_trunc(relationship, 50),
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        ))
        attack_session.flush()


def _import_relationship(attack_session, ap, rel_el: ET.Element, vocab_id: int) -> None:
    from xorcism_python.models.xattack import ATTACKPATTERN, ATTACKPATTERNRELATIONSHIP

    nature = rel_el.get("Nature", "")
    target_id = rel_el.get("CAPEC_ID") or rel_el.get("CAPEC-ID") or ""
    if not target_id:
        return

    target_capec_id = f"CAPEC-{target_id}"
    target_ap = attack_session.query(ATTACKPATTERN).filter_by(capec_id=target_capec_id).first()
    if target_ap is None:
        target_ap = ATTACKPATTERN(
            capec_id=target_capec_id,
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        )
        attack_session.add(target_ap)
        attack_session.flush()

    rel = attack_session.query(ATTACKPATTERNRELATIONSHIP).filter_by(
        AttackPatternRefID=ap.AttackPatternID,
        AttackPatternSubjectID=target_ap.AttackPatternID,
        RelationshipName=nature,
    ).first()
    if rel is None:
        attack_session.add(ATTACKPATTERNRELATIONSHIP(
            AttackPatternRefID=ap.AttackPatternID,
            AttackPatternSubjectID=target_ap.AttackPatternID,
            RelationshipName=_trunc(nature, 100),
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        ))
        attack_session.flush()


def _import_references(attack_session, xorcism_session, pat_id: int, el: ET.Element, vocab_id: int) -> None:
    from xorcism_python.models.xattack import ATTACKPATTERNREFERENCE
    from xorcism_python.models.xorcism import REFERENCE, AUTHOR, REFERENCEAUTHOR, ORGANISATION

    for ref_el in el.findall(_tag("Reference")):
        ref_id = ref_el.get("External_Reference_ID", "")

        apref = attack_session.query(ATTACKPATTERNREFERENCE).filter_by(
            AttackPatternID=pat_id, Reference_ID=ref_id
        ).first()
        if apref is None:
            apref = ATTACKPATTERNREFERENCE(
                AttackPatternID=pat_id,
                Reference_ID=_trunc(ref_id, 100),
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            attack_session.add(apref)
            attack_session.flush()


def _import_notes(attack_session, pat_id: int, el: ET.Element, vocab_id: int) -> None:
    from xorcism_python.models.xattack import ATTACKPATTERNNOTE, ATTACKPATTERNNOTES

    order = 0
    for note_el in el.findall(_tag("Note")):
        order += 1
        text = _clean(_text(note_el))
        if not text:
            continue

        note = attack_session.query(ATTACKPATTERNNOTE).filter_by(
            NoteText=text[:4000]
        ).first()
        if note is None:
            note = ATTACKPATTERNNOTE(
                NoteText=_trunc(text, 4000),
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            attack_session.add(note)
            attack_session.flush()

        link = attack_session.query(ATTACKPATTERNNOTES).filter_by(
            AttackPatternID=pat_id,
            AttackPatternNoteID=note.AttackPatternNoteID,
        ).first()
        if link is None:
            attack_session.add(ATTACKPATTERNNOTES(
                AttackPatternID=pat_id,
                AttackPatternNoteID=note.AttackPatternNoteID,
                NoteOrder=order,
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            ))

    attack_session.flush()


# ─── Main orchestration ───────────────────────────────────────────────────────

def parse_capec_xml(xml_path: str) -> None:
    log(MODULE, f"Parsing {xml_path}")
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Supports both the v2 and v3 namespaces in the same pass
    # (the modern file uses capec-3)
    global NS
    tag_test = root.tag
    if "capec-2" in tag_test:
        NS = "http://capec.mitre.org/capec-2"
        log(MODULE, "CAPEC v2 format detected")
    else:
        NS = "http://capec.mitre.org/capec-3"
        log(MODULE, "CAPEC v3 format detected")

    with session_scope("XORCISM") as xorcism_session:
        vocab_id = _setup_vocabulary(xorcism_session)
        _setup_killchain(xorcism_session, vocab_id)
        _setup_osilayers(xorcism_session, vocab_id)
        xorcism_session.commit()

    with session_scope("XATTACK") as attack_session, \
         session_scope("XORCISM") as xorcism_session:

        _import_views(root, attack_session, vocab_id)
        attack_session.commit()
        log(MODULE, "Views imported.")

        _import_categories(root, attack_session, xorcism_session, vocab_id)
        attack_session.commit()
        xorcism_session.commit()
        log(MODULE, "Categories imported.")

        _import_attack_patterns(root, attack_session, xorcism_session, vocab_id)
        attack_session.commit()
        xorcism_session.commit()
        log(MODULE, "Attack Patterns imported.")

    log(MODULE, "CAPEC import finished.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Import CAPEC (XML v3) into XATTACK.db")
    parser.add_argument(
        "--xml", default="capec_latest.xml",
        help="Path to the CAPEC XML file (default: capec_latest.xml)"
    )
    parser.add_argument(
        "--download", action="store_true",
        help="Download the XML from capec.mitre.org if missing"
    )
    args = parser.parse_args()

    if args.download or not os.path.exists(args.xml):
        download_capec(args.xml)

    parse_capec_xml(args.xml)


if __name__ == "__main__":
    main()
