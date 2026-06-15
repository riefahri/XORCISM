"""
import_nist800-53.py — Imports the NIST SP 800-53 Rev. 5 catalog (latest
version) into XORCISM.CONTROL with VocabularyID = 7 ("NIST 800-53").

Source: official NIST OSCAL catalog (public domain, US government work):
  https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json
Downloaded locally into resources/NIST_SP-800-53_rev5_catalog.json
(1196 controls: 324 base + 872 enhancements, 20 families).

Mapping:
  ControlName        = "<ref> <title>"   (e.g. "AC-1 Policy and Procedures")
  NIST               = "<ref>"            (NIST notation, e.g. "AC-2(1)")
  ControlDescription = family             (e.g. "Access Control")
  VocabularyID       = 7

Idempotent: get-or-update by (NIST == ref AND VocabularyID == 7).

Usage:
    python import_nist800-53.py [--json path.json]
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from sqlalchemy import event, text, Integer, BigInteger, SmallInteger
from sqlalchemy.orm import Mapper

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python.models.base import session_scope
from xorcism_python.utils import log

MODULE = "ImportNIST80053"
VOCAB_ID = 7  # "NIST 800-53"
DEFAULT_JSON = os.path.join(
    os.path.dirname(__file__), "..", "..",
    "resources", "NIST_SP-800-53_rev5_catalog.json",
)


# ─── Auto-increment of integer primary keys (cf. other importers) ───────
_pk_counters: dict = {}
_INT_TYPES = (Integer, BigInteger, SmallInteger)


def _auto_pk(mapper, connection, target) -> None:
    pk_cols = mapper.primary_key
    if len(pk_cols) != 1:
        return
    col = pk_cols[0]
    if not isinstance(col.type, _INT_TYPES):
        return
    attr = mapper.get_property_by_column(col).key
    if getattr(target, attr, None) is not None:
        return
    tbl = mapper.local_table.name
    key = (str(connection.engine.url), tbl)
    db_max = connection.execute(
        text(f'SELECT COALESCE(MAX("{col.name}"), 0) FROM "{tbl}"')
    ).scalar()
    nxt = max(_pk_counters.get(key, 0), int(db_max or 0)) + 1
    _pk_counters[key] = nxt
    setattr(target, attr, nxt)


event.listen(Mapper, "before_insert", _auto_pk)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_nist_ref(oscal_id: str) -> str:
    """ 'ac-1' -> 'AC-1'; 'ac-2.1' -> 'AC-2(1)' (NIST notation). """
    fam, _, rest = oscal_id.partition("-")
    fam = fam.upper()
    if "." in rest:
        base, enh = rest.split(".", 1)
        return f"{fam}-{base}({enh})"
    return f"{fam}-{rest}"


def _iter_controls(controls):
    """Iterates over the controls AND their nested enhancements."""
    for c in controls or []:
        yield c
        yield from _iter_controls(c.get("controls"))


def parse_catalog(json_path: str) -> None:
    log(MODULE, f"Lecture du catalogue OSCAL : {json_path}")
    with open(json_path, "r", encoding="utf-8") as fh:
        catalog = json.load(fh)["catalog"]

    rows = []  # (ref, name, family)
    for group in catalog.get("groups", []):
        family = group.get("title") or group.get("id", "").upper()
        for ctrl in _iter_controls(group.get("controls")):
            cid = ctrl.get("id")
            title = (ctrl.get("title") or "").strip()
            if not cid:
                continue
            ref = to_nist_ref(cid)
            rows.append((ref, f"{ref} {title}".strip(), family))

    log(MODULE, f"{len(rows)} contrôles à importer (VocabularyID={VOCAB_ID})")

    from xorcism_python.models.xorcism import CONTROL
    created = updated = 0
    with session_scope("XORCISM") as session:
        existing = {
            r.NIST: r for r in session.query(CONTROL).filter_by(VocabularyID=VOCAB_ID).all()
            if r.NIST
        }
        for ref, name, family in rows:
            ctrl = existing.get(ref)
            if ctrl is None:
                ctrl = CONTROL(CreatedDate=_now())
                session.add(ctrl)
                created += 1
            else:
                updated += 1
            ctrl.ControlName = name
            ctrl.NIST = ref
            ctrl.ControlDescription = family
            ctrl.VocabularyID = VOCAB_ID
            session.flush()
        session.commit()

    log(MODULE, f"Import terminé : {created} créés, {updated} mis à jour.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Import NIST SP 800-53 Rev.5 dans XORCISM.CONTROL")
    ap.add_argument("--json", default=DEFAULT_JSON, help="Chemin du catalogue OSCAL JSON")
    args = ap.parse_args()
    if not os.path.exists(args.json):
        raise SystemExit(
            f"Catalogue introuvable : {args.json}\n"
            "Téléchargez-le : curl -L -o resources/NIST_SP-800-53_rev5_catalog.json "
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
        )
    parse_catalog(args.json)


if __name__ == "__main__":
    main()
