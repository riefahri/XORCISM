"""
import_cce.py — Full conversion of Import_cce/Program.cs (C# .NET)
Jerome Athias - XORCISM

Parses the MITRE CCE XML file (COMBINED "cce_list" format, e.g.
cce-COMBINED-5.20130214.xml — https://cce.mitre.org / NVD archive) and imports
the values into XORCISM.db (+ XOVAL.db for the referenced OVAL definitions).

XML namespaces:
  http://cce.mitre.org              (CCE elements, default prefix)
  http://purl.org/dc/terms/        (dcterms:title, publisher, issued, …)

Structure handled:
  cce_list
    cces
      cce (cce_id, platform, modified)
        description
        parameters/parameter
        technical_mechanisms/technical_mechanism
        references/reference (resource_id)        → OVAL parsing (oval:…:def:N)
    resources
      resource (resource_id, modified)
        dcterms:title | dcterms:publisher | dcterms:issued
        version | dcterms:format | dcterms:creator

Tables populated:
  XORCISM : VOCABULARY, CCE, PLATFORM, PLATFORMFORCCE,
            CCEPARAMETER, CCEPARAMETERFORCCE,
            CCETECHNICALMECHANISM, CCETECHNICALMECHANISMFORCCE,
            CCEREFERENCE, CCEREFERENCEFORCCE,
            CCERESOURCE, CCERESOURCEFORCCEREFERENCE,
            CCERESOURCEAUTHOR, AUTHOR
  XOVAL   : OVALDEFINITION, OVALDEFINITIONCCE

Usage:
    python import_cce.py --xml cce-COMBINED-5.20130214.xml
    python import_cce.py --download           # attempts the download
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

MODULE = "ImportCCE"
# CCE is archived; historical URL (may no longer respond — provide the local
# file with --xml in that case).
CCE_URL = "https://cce.mitre.org/lists/data/downloads/cce-COMBINED-5.20130214.xml"

# Namespaces
CCE_NS = "http://cce.mitre.org"

# Regex to detect OVAL definitions in the references' text
# (e.g. "oval:org.mitre.oval:def:824", "oval:gov.nist.usgcb.windowsseven:def:147")
RE_OVAL_DEF = re.compile(r"oval:.*?:def:[0-9]+")


# ─── Auto-increment of integer primary keys ──────────────────────────────
# Identical to the other importers: the XORCISM.db / XOVAL.db tables have
# "<Id> INTEGER NOT NULL" columns WITHOUT a declared PRIMARY KEY → SQLite does not
# auto-increment them. This listener assigns MAX(<col>)+1 before each INSERT.

_pk_counters: dict = {}
_INT_TYPES = (Integer, BigInteger, SmallInteger)


def _auto_pk(mapper, connection, target) -> None:
    pk_cols = mapper.primary_key
    if len(pk_cols) != 1:
        return
    col = pk_cols[0]
    if not isinstance(col.type, _INT_TYPES):
        return  # PK textuelle : fournie explicitement

    attr = mapper.get_property_by_column(col).key
    if getattr(target, attr, None) is not None:
        return  # value already set

    tbl = mapper.local_table.name
    key = (str(connection.engine.url), tbl)  # stable par base + table

    db_max = connection.execute(
        text(f'SELECT COALESCE(MAX("{col.name}"), 0) FROM "{tbl}"')
    ).scalar()
    nxt = max(_pk_counters.get(key, 0), int(db_max or 0)) + 1
    _pk_counters[key] = nxt
    setattr(target, attr, nxt)


event.listen(Mapper, "before_insert", _auto_pk)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _local(tag: str) -> str:
    """Nom local d'une balise ElementTree (sans l'espace de noms {…})."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _text(el: Optional[ET.Element]) -> str:
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def _clean(s: str) -> str:
    """Whitespace normalization (equivalent of the C# "Cleaning?")."""
    if not s:
        return ""
    s = s.replace("\r\n", " ").replace("\n", " ").replace("\t", " ")
    while "  " in s:
        s = s.replace("  ", " ")
    return s.strip()


def _trunc(s: Optional[str], n: int) -> Optional[str]:
    if not s:
        return None
    return s[:n]


def _now() -> datetime:
    # UTC timezone-aware brought back to naive (avoids deprecated datetime.utcnow()).
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ─── Download ────────────────────────────────────────────────────────────────

def download_cce(dest: str) -> None:
    log(MODULE, f"Téléchargement de {CCE_URL}")
    resp = requests.get(CCE_URL, timeout=180)
    resp.raise_for_status()
    with open(dest, "wb") as f:
        f.write(resp.content)
    log(MODULE, f"Fichier sauvegardé : {dest}")


# ─── Phase 0: "CCE" VOCABULARY ────────────────────────────────────────────

def _setup_vocabulary(xorcism_session) -> int:
    from xorcism_python.models.xorcism import VOCABULARY
    vocab = xorcism_session.query(VOCABULARY).filter_by(VocabularyName="CCE").first()
    if vocab is None:
        vocab = VOCABULARY(
            VocabularyName="CCE",
            VocabularyVersion="5",
            CreatedDate=_now(),
        )
        xorcism_session.add(vocab)
        xorcism_session.flush()
        log(MODULE, f"VOCABULARY CCE créé (ID={vocab.VocabularyID})")
    return vocab.VocabularyID


# ─── Platform linked to a CCE ────────────────────────────────────────────────

def _ensure_platform(xorcism_session, platform_name: str, vocab_id: int) -> Optional[int]:
    """Returns the PlatformID (creation if needed); None if empty name."""
    from xorcism_python.models.xorcism import PLATFORM
    platform_name = (platform_name or "").strip()
    if not platform_name:
        return None
    plat = xorcism_session.query(PLATFORM).filter_by(PlatformName=platform_name).first()
    if plat is None:
        plat = PLATFORM(
            PlatformName=_trunc(platform_name, 4000),
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        )
        xorcism_session.add(plat)
        xorcism_session.flush()
    return plat.PlatformID


def _ensure_platform_for_cce(xorcism_session, platform_id: int, cce_pk: int,
                             cce_id: str, vocab_id: int) -> None:
    from xorcism_python.models.xorcism import PLATFORMFORCCE
    link = xorcism_session.query(PLATFORMFORCCE).filter_by(
        PlatformID=platform_id, cce_id=cce_id
    ).first()
    if link is None:
        xorcism_session.add(PLATFORMFORCCE(
            PlatformID=platform_id,
            CCEID=cce_pk,
            cce_id=cce_id,
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        ))


# ─── Parameters ──────────────────────────────────────────────────────────────

def _import_parameters(xorcism_session, cce_pk: int, params_el: ET.Element, vocab_id: int) -> None:
    from xorcism_python.models.xorcism import CCEPARAMETER, CCEPARAMETERFORCCE

    for param_el in params_el:
        if _local(param_el.tag) != "parameter":
            log(MODULE, f"  [WARN] noeud parameters inattendu : {_local(param_el.tag)}")
            continue
        txt = _clean(_text(param_el))
        if not txt:
            continue

        param = xorcism_session.query(CCEPARAMETER).filter_by(
            CCEParameterText=txt[:4000]
        ).first()
        if param is None:
            param = CCEPARAMETER(
                CCEParameterText=_trunc(txt, 4000),
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            xorcism_session.add(param)
            xorcism_session.flush()

        link = xorcism_session.query(CCEPARAMETERFORCCE).filter_by(
            CCEParameterID=param.CCEParameterID, CCEID=cce_pk
        ).first()
        if link is None:
            xorcism_session.add(CCEPARAMETERFORCCE(
                CCEParameterID=param.CCEParameterID,
                CCEID=cce_pk,
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            ))


# ─── Technical mechanisms ───────────────────────────────────────────────────

def _import_technical_mechanisms(xorcism_session, cce_pk: int, tm_el: ET.Element, vocab_id: int) -> None:
    from xorcism_python.models.xorcism import CCETECHNICALMECHANISM, CCETECHNICALMECHANISMFORCCE

    for mech_el in tm_el:
        if _local(mech_el.tag) != "technical_mechanism":
            log(MODULE, f"  [WARN] noeud technical_mechanisms inattendu : {_local(mech_el.tag)}")
            continue
        txt = _clean(_text(mech_el))
        if not txt:
            continue

        mech = xorcism_session.query(CCETECHNICALMECHANISM).filter_by(
            TechnicalMechanismText=txt[:4000]
        ).first()
        if mech is None:
            mech = CCETECHNICALMECHANISM(
                TechnicalMechanismText=_trunc(txt, 4000),
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            xorcism_session.add(mech)
            xorcism_session.flush()

        link = xorcism_session.query(CCETECHNICALMECHANISMFORCCE).filter_by(
            CCETechnicalMechanismID=mech.CCETechnicalMechanismID, CCEID=cce_pk
        ).first()
        if link is None:
            xorcism_session.add(CCETECHNICALMECHANISMFORCCE(
                CCETechnicalMechanismID=mech.CCETechnicalMechanismID,
                CCEID=cce_pk,
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            ))


# ─── Referenced OVAL definitions (XOVAL database) ───────────────────────────────

def _link_oval_definitions(oval_session, cce_pk: int, ref_text: str, vocab_id: int) -> None:
    from xorcism_python.models.xoval import OVALDEFINITION, OVALDEFINITIONCCE

    for match in RE_OVAL_DEF.findall(ref_text or ""):
        oval_def = oval_session.query(OVALDEFINITION).filter_by(
            OVALDefinitionIDPattern=match
        ).first()
        if oval_def is None:
            oval_def = OVALDEFINITION(
                OVALDefinitionIDPattern=_trunc(match, 4000),
                OVALDefinitionVersion=0,   # NOT NULL — pas de critère ici
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            oval_session.add(oval_def)
            oval_session.flush()
            log(MODULE, f"  OVAL Definition créée : {match}")

        link = oval_session.query(OVALDEFINITIONCCE).filter_by(
            OVALDefinitionID=oval_def.OVALDefinitionID, CCEID=cce_pk
        ).first()
        if link is None:
            oval_session.add(OVALDEFINITIONCCE(
                OVALDefinitionID=oval_def.OVALDefinitionID,
                CCEID=cce_pk,
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            ))


# ─── References ──────────────────────────────────────────────────────────────

def _import_references(xorcism_session, oval_session, cce_pk: int, cce_id: str,
                       refs_el: ET.Element, vocab_id: int) -> None:
    from xorcism_python.models.xorcism import (
        CCEREFERENCE, CCEREFERENCEFORCCE, CCERESOURCE, CCERESOURCEFORCCEREFERENCE,
    )

    for ref_el in refs_el:
        if _local(ref_el.tag) != "reference":
            log(MODULE, f"  [WARN] noeud references inattendu : {_local(ref_el.tag)}")
            continue

        res_id = (ref_el.get("resource_id") or "").strip()
        ref_text = _clean(_text(ref_el))

        # CCEREFERENCE (key: resource_id + text)
        ref = xorcism_session.query(CCEREFERENCE).filter_by(
            resource_id=res_id, ReferenceText=ref_text[:4000]
        ).first()
        if ref is None:
            ref = CCEREFERENCE(
                resource_id=_trunc(res_id, 4000) or "",
                ReferenceText=_trunc(ref_text, 4000) or "",
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            xorcism_session.add(ref)
            xorcism_session.flush()
            # OVAL definitions found in the text (only at creation)
            _link_oval_definitions(oval_session, cce_pk, ref_text, vocab_id)

        # CCEREFERENCEFORCCE (key: CCEReferenceID + cce_id)
        ref_link = xorcism_session.query(CCEREFERENCEFORCCE).filter_by(
            CCEReferenceID=ref.CCEReferenceID, cce_id=cce_id
        ).first()
        if ref_link is None:
            xorcism_session.add(CCEREFERENCEFORCCE(
                CCEReferenceID=ref.CCEReferenceID,
                CCEID=cce_pk,
                cce_id=cce_id,
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            ))

        # CCERESOURCE (key: resource_id) — the resource pointed to by the reference
        if res_id:
            resource = xorcism_session.query(CCERESOURCE).filter_by(
                resource_id=res_id
            ).first()
            if resource is None:
                resource = CCERESOURCE(
                    resource_id=_trunc(res_id, 4000),
                    VocabularyID=vocab_id,
                    CreatedDate=_now(),
                )
                xorcism_session.add(resource)
                xorcism_session.flush()

            # CCERESOURCEFORCCEREFERENCE (key: CCEResourceID + CCEReferenceID)
            rr_link = xorcism_session.query(CCERESOURCEFORCCEREFERENCE).filter_by(
                CCEResourceID=resource.CCEResourceID, CCEReferenceID=ref.CCEReferenceID
            ).first()
            if rr_link is None:
                xorcism_session.add(CCERESOURCEFORCCEREFERENCE(
                    CCEResourceID=resource.CCEResourceID,
                    CCEReferenceID=ref.CCEReferenceID,
                    VocabularyID=vocab_id,
                    CreatedDate=_now(),
                ))


# ─── Section <cces> ──────────────────────────────────────────────────────────

def _import_cces(xorcism_session, oval_session, cces_el: ET.Element, vocab_id: int) -> int:
    from xorcism_python.models.xorcism import CCE

    count = 0
    for cce_el in cces_el:
        if _local(cce_el.tag) != "cce":
            log(MODULE, f"[WARN] noeud cces inattendu : {_local(cce_el.tag)}")
            continue

        cce_id = (cce_el.get("cce_id") or "").strip()
        if not cce_id:
            log(MODULE, "[WARN] cce sans cce_id, ignoré")
            continue
        platform_name = (cce_el.get("platform") or "").strip()
        modified = (cce_el.get("modified") or "").strip()

        # CCE (key: cce_id)
        cce = xorcism_session.query(CCE).filter_by(cce_id=cce_id).first()
        if cce is None:
            cce = CCE(
                cce_id=cce_id,
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            xorcism_session.add(cce)
            xorcism_session.flush()

        cce.platform = _trunc(platform_name, 4000) or None
        cce.modified = _trunc(modified, 50) or None
        cce.VocabularyID = vocab_id
        xorcism_session.flush()
        cce_pk = cce.CCEID

        # PLATFORM + PLATFORMFORCCE
        platform_id = _ensure_platform(xorcism_session, platform_name, vocab_id)
        if platform_id is not None:
            cce.PlatformID = platform_id
            _ensure_platform_for_cce(xorcism_session, platform_id, cce_pk, cce_id, vocab_id)

        # Sub-elements
        for child in cce_el:
            name = _local(child.tag)
            if name == "description":
                cce.description = _trunc(_clean(_text(child)), 4000)
            elif name == "parameters":
                _import_parameters(xorcism_session, cce_pk, child, vocab_id)
            elif name == "technical_mechanisms":
                _import_technical_mechanisms(xorcism_session, cce_pk, child, vocab_id)
            elif name == "references":
                _import_references(xorcism_session, oval_session, cce_pk, cce_id, child, vocab_id)
            else:
                log(MODULE, f"  [WARN] sous-noeud cce inattendu : {name}")

        count += 1
        if count % 200 == 0:
            xorcism_session.commit()
            oval_session.commit()
            log(MODULE, f"  {count} CCE traités…")

    xorcism_session.flush()
    return count


# ─── Section <resources> ─────────────────────────────────────────────────────

def _import_resources(xorcism_session, resources_el: ET.Element, vocab_id: int) -> int:
    from xorcism_python.models.xorcism import CCERESOURCE, AUTHOR, CCERESOURCEAUTHOR

    count = 0
    for res_el in resources_el:
        if _local(res_el.tag) != "resource":
            log(MODULE, f"[WARN] noeud resources inattendu : {_local(res_el.tag)}")
            continue

        res_id = (res_el.get("resource_id") or "").strip()
        if not res_id:
            log(MODULE, "[WARN] resource sans resource_id, ignorée")
            continue
        modified = (res_el.get("modified") or "").strip()

        resource = xorcism_session.query(CCERESOURCE).filter_by(resource_id=res_id).first()
        if resource is None:
            resource = CCERESOURCE(
                resource_id=_trunc(res_id, 4000),
                VocabularyID=vocab_id,
                CreatedDate=_now(),
            )
            xorcism_session.add(resource)
            xorcism_session.flush()
        resource.modified = _trunc(modified, 50) or None

        for child in res_el:
            name = _local(child.tag)   # title/publisher/issued/version/format/creator
            value = _clean(_text(child))
            if name == "title":
                resource.ResourceTitle = _trunc(value, 4000)
            elif name == "publisher":
                resource.ResourcePublisher = _trunc(value, 4000)
            elif name == "issued":
                resource.issued = _trunc(value, 50)
            elif name == "version":
                resource.ResourceVersion = _trunc(value, 50)
            elif name == "format":
                resource.ResourceFormat = _trunc(value, 255)
            elif name == "creator":
                _ensure_resource_author(xorcism_session, resource.CCEResourceID, value, vocab_id)
            else:
                log(MODULE, f"  [WARN] sous-noeud resource inattendu : {name}")

        xorcism_session.flush()
        count += 1
        if count % 200 == 0:
            xorcism_session.commit()
            log(MODULE, f"  {count} ressources traitées…")

    xorcism_session.flush()
    return count


def _ensure_resource_author(xorcism_session, resource_pk: int, author_name: str, vocab_id: int) -> None:
    from xorcism_python.models.xorcism import AUTHOR, CCERESOURCEAUTHOR
    author_name = (author_name or "").strip()
    if not author_name:
        return

    author = xorcism_session.query(AUTHOR).filter_by(AuthorName=author_name).first()
    if author is None:
        author = AUTHOR(
            AuthorName=_trunc(author_name, 4000),
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        )
        xorcism_session.add(author)
        xorcism_session.flush()

    link = xorcism_session.query(CCERESOURCEAUTHOR).filter_by(
        AuthorID=author.AuthorID, CCEResourceID=resource_pk
    ).first()
    if link is None:
        xorcism_session.add(CCERESOURCEAUTHOR(
            AuthorID=author.AuthorID,
            CCEResourceID=resource_pk,
            VocabularyID=vocab_id,
            CreatedDate=_now(),
        ))


# ─── Orchestration ───────────────────────────────────────────────────────────

def parse_cce_xml(xml_path: str) -> None:
    log(MODULE, f"Parsing {xml_path}")
    tree = ET.parse(xml_path)
    root = tree.getroot()
    if _local(root.tag) != "cce_list":
        log(MODULE, f"[WARN] racine inattendue : {_local(root.tag)} (attendu cce_list)")

    with session_scope("XORCISM") as xorcism_session:
        vocab_id = _setup_vocabulary(xorcism_session)
        xorcism_session.commit()

    with session_scope("XORCISM") as xorcism_session, \
         session_scope("XOVAL") as oval_session:

        n_cce = n_res = 0
        for child in root:
            name = _local(child.tag)
            if name == "cces":
                n_cce = _import_cces(xorcism_session, oval_session, child, vocab_id)
                xorcism_session.commit()
                oval_session.commit()
                log(MODULE, f"CCE importés : {n_cce}")
            elif name == "resources":
                n_res = _import_resources(xorcism_session, child, vocab_id)
                xorcism_session.commit()
                log(MODULE, f"Ressources importées : {n_res}")
            elif name == "cce_list_information":
                log(MODULE, "Section cce_list_information ignorée (métadonnées).")
            else:
                log(MODULE, f"[WARN] section racine inattendue : {name}")

    log(MODULE, f"Import CCE terminé ({n_cce} CCE, {n_res} ressources).")


def main() -> None:
    parser = argparse.ArgumentParser(description="Import CCE (XML cce_list) dans XORCISM.db / XOVAL.db")
    parser.add_argument(
        "--xml", default="cce-COMBINED-5.20130214.xml",
        help="Chemin vers le fichier XML CCE COMBINED (défaut : cce-COMBINED-5.20130214.xml)"
    )
    parser.add_argument(
        "--download", action="store_true",
        help="Télécharger le XML depuis cce.mitre.org si absent (archive — peut échouer)"
    )
    args = parser.parse_args()

    if args.download or not os.path.exists(args.xml):
        if not os.path.exists(args.xml):
            download_cce(args.xml)

    parse_cce_xml(args.xml)


if __name__ == "__main__":
    main()
