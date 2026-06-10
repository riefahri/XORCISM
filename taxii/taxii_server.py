"""
taxii_server.py — Serveur TAXII 2.1 conforme à la spécification OASIS.
Réf. : https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html

Implémente l'intégralité des endpoints TAXII 2.1 :
  GET  /taxii2/                                                  → Discovery
  GET  /{api-root}/                                              → API Root
  GET  /{api-root}/status/{status-id}/                          → Status
  GET  /{api-root}/collections/                                 → Collections
  GET  /{api-root}/collections/{id}/                            → Collection
  GET  /{api-root}/collections/{id}/manifest/                   → Manifest
  GET  /{api-root}/collections/{id}/objects/                    → Envelope
  POST /{api-root}/collections/{id}/objects/                    → Status (ajout)
  GET  /{api-root}/collections/{id}/objects/{obj-id}/           → Envelope
  DELETE /{api-root}/collections/{id}/objects/{obj-id}/         → 200
  GET  /{api-root}/collections/{id}/objects/{obj-id}/versions/  → Versions

Caractéristiques conformes :
  - Type de média « application/taxii+json;version=2.1 » (Accept + Content-Type).
  - Négociation de contenu (406), Content-Type d'entrée (415).
  - Filtres d'URL : match[id], match[type], match[version], match[spec_version],
    added_after, limit, next ; pagination opaque + en-têtes
    X-TAXII-Date-Added-First / X-TAXII-Date-Added-Last.
  - Versionnement STIX (first / last / all / timestamp exact).
  - Ressource d'erreur normalisée ; codes 400/401/403/404/406/413/415.
  - Authentification HTTP Basic optionnelle + droits can_read / can_write.

Backend mémoire (remplaçable). Dépendance : Flask.
    pip install flask
    python taxii_server.py                 # http://127.0.0.1:5000
    TAXII_AUTH=1 python taxii_server.py     # exige Basic (voir USERS)
"""

from __future__ import annotations

import base64
import os
import sqlite3
import uuid
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, Response, json, request

# ── Constantes ─────────────────────────────────────────────────────────────────
TAXII_MEDIA = "application/taxii+json;version=2.1"
STIX_MEDIA = "application/stix+json;version=2.1"
TAXII_VERSION = "2.1"
DEFAULT_PAGE = 100          # taille de page par défaut imposée par le serveur
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 Mo

# Authentification (optionnelle). Active si TAXII_AUTH=1.
AUTH_ENABLED = os.getenv("TAXII_AUTH", "0") == "1"
USERS = {"admin": os.getenv("TAXII_PASSWORD", "taxii")}  # démo : à remplacer


# ── Helpers généraux ────────────────────────────────────────────────────────────
def now_ts() -> str:
    """Timestamp RFC 3339 UTC, précision microseconde, suffixe Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def stix_version(obj: Dict[str, Any]) -> str:
    """Version d'un objet STIX : 'modified', sinon 'created'."""
    return obj.get("modified") or obj.get("created") or now_ts()


def stix_spec_version(obj: Dict[str, Any]) -> str:
    return obj.get("spec_version", "2.1")


class TaxiiError(Exception):
    def __init__(self, http_status: int, title: str, description: Optional[str] = None):
        super().__init__(title)
        self.http_status = http_status
        self.title = title
        self.description = description


import re as _re

# Espace de noms stable pour des id STIX déterministes (UUIDv5) à partir des PK projet.
_STIX_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def det_stix_id(stix_type: str, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(_STIX_NS, f'{stix_type}:{key}')}"


def to_rfc3339(dbval: Any, default: str = "2020-01-01T00:00:00.000Z") -> str:
    """Convertit une date SQLite ('YYYY-MM-DD HH:MM:SS[.ffffff]' / 'YYYY-MM-DD' /
    ISO) en timestamp RFC 3339 (millisecondes + Z). Renvoie `default` si vide."""
    if not dbval:
        return default
    s = str(dbval).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(dt.microsecond / 1000):03d}Z"
        except ValueError:
            continue
    return default


def strip_html(s: Any) -> Optional[str]:
    if not s:
        return None
    txt = _re.sub(r"<[^>]+>", " ", str(s))
    txt = _re.sub(r"\s+", " ", txt).strip()
    return txt or None


def make_status(total: int, successes: List[Dict[str, Any]],
                failures: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Construit une ressource Status (opération d'ajout synchrone → complete)."""
    st: Dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "status": "complete",
        "request_timestamp": now_ts(),
        "total_count": total,
        "success_count": len(successes),
        "successes": successes,
        "failure_count": len(failures),
        "pending_count": 0,
    }
    if failures:
        st["failures"] = failures
    return st


# ── Backend mémoire ─────────────────────────────────────────────────────────────
class MemoryBackend:
    """Stockage en mémoire. Chaque enregistrement :
       {object, id, version, spec_version, date_added, media_type}."""

    def __init__(self) -> None:
        self.collections: Dict[str, Dict[str, Any]] = {}
        self.records: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.statuses: Dict[str, Dict[str, Any]] = {}

    # -- collections --
    def add_collection(self, meta: Dict[str, Any]) -> None:
        self.collections[meta["id"]] = meta
        self.records.setdefault(meta["id"], [])

    def list_collections(self) -> List[Dict[str, Any]]:
        return sorted(self.collections.values(), key=lambda c: c["id"])

    def get_collection(self, cid: str) -> Dict[str, Any]:
        col = self.collections.get(cid)
        if not col:
            raise TaxiiError(404, "Collection introuvable", f"Aucune collection {cid}")
        return col

    # -- objets --
    def _make_record(self, obj: Dict[str, Any], date_added: Optional[str] = None) -> Dict[str, Any]:
        return {
            "object": obj,
            "id": obj.get("id", ""),
            "version": stix_version(obj),
            "spec_version": stix_spec_version(obj),
            "date_added": date_added or now_ts(),
            "media_type": STIX_MEDIA,
        }

    def seed_object(self, cid: str, obj: Dict[str, Any], date_added: str) -> None:
        self.records[cid].append(self._make_record(obj, date_added))

    def add_objects(self, cid: str, objects: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Ajoute des objets STIX ; renvoie une ressource Status (synchrone)."""
        recs = self.records[cid]
        existing = {(r["id"], r["version"]) for r in recs}
        successes, failures = [], []
        for obj in objects:
            oid = obj.get("id")
            if not oid or "type" not in obj:
                failures.append({"id": oid or "unknown", "version": stix_version(obj),
                                 "message": "Objet STIX invalide (id/type manquant)"})
                continue
            ver = stix_version(obj)
            if (oid, ver) in existing:
                successes.append({"id": oid, "version": ver, "message": "Déjà présent"})
                continue
            recs.append(self._make_record(obj))
            existing.add((oid, ver))
            successes.append({"id": oid, "version": ver})

        status = make_status(len(objects), successes, failures)
        self.statuses[status["id"]] = status
        return status

    def get_records(self, cid: str) -> List[Dict[str, Any]]:
        return self.records.get(cid, [])

    def get_status(self, sid: str) -> Dict[str, Any]:
        st = self.statuses.get(sid)
        if not st:
            raise TaxiiError(404, "Status introuvable", f"Aucun status {sid}")
        return st

    def delete_object(self, cid: str, oid: str, keep_pred) -> None:
        recs = self.records[cid]
        target = [r for r in recs if r["id"] == oid]
        if not target:
            raise TaxiiError(404, "Objet introuvable", f"Aucun objet {oid}")
        self.records[cid] = [r for r in recs if not (r["id"] == oid and not keep_pred(r))]


# ── Backend SQLite (persistant) ─────────────────────────────────────────────────
class SqliteBackend:
    """Stockage persistant SQLite — interface identique à MemoryBackend.
    Tables : taxii_collection, taxii_object (1 ligne par version STIX), taxii_status."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._init_schema()

    def _conn(self) -> "sqlite3.Connection":
        con = sqlite3.connect(self.path, timeout=15)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=15000")
        return con

    @contextmanager
    def _tx(self):
        con = self._conn()
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def _init_schema(self) -> None:
        with self._tx() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS taxii_collection(
                    id TEXT PRIMARY KEY, title TEXT, description TEXT, alias TEXT,
                    can_read INTEGER, can_write INTEGER, media_types TEXT);
                CREATE TABLE IF NOT EXISTS taxii_object(
                    collection_id TEXT, stix_id TEXT, version TEXT, spec_version TEXT,
                    date_added TEXT, media_type TEXT, content TEXT,
                    PRIMARY KEY (collection_id, stix_id, version));
                CREATE INDEX IF NOT EXISTS ix_taxii_obj_coll ON taxii_object(collection_id);
                CREATE TABLE IF NOT EXISTS taxii_status(id TEXT PRIMARY KEY, content TEXT);
                """
            )

    # -- collections --
    def add_collection(self, meta: Dict[str, Any]) -> None:
        with self._tx() as con:
            con.execute(
                """INSERT OR REPLACE INTO taxii_collection
                   (id, title, description, alias, can_read, can_write, media_types)
                   VALUES (?,?,?,?,?,?,?)""",
                (meta["id"], meta["title"], meta.get("description"), meta.get("alias"),
                 1 if meta.get("can_read") else 0, 1 if meta.get("can_write") else 0,
                 json.dumps(meta.get("media_types", [STIX_MEDIA]))),
            )

    @staticmethod
    def _row_to_collection(row) -> Dict[str, Any]:
        return {
            "id": row["id"], "title": row["title"], "description": row["description"],
            "alias": row["alias"], "can_read": bool(row["can_read"]),
            "can_write": bool(row["can_write"]),
            "media_types": json.loads(row["media_types"]) if row["media_types"] else [STIX_MEDIA],
        }

    def list_collections(self) -> List[Dict[str, Any]]:
        with self._tx() as con:
            rows = con.execute("SELECT * FROM taxii_collection ORDER BY id").fetchall()
        return [self._row_to_collection(r) for r in rows]

    def get_collection(self, cid: str) -> Dict[str, Any]:
        with self._tx() as con:
            row = con.execute("SELECT * FROM taxii_collection WHERE id=?", (cid,)).fetchone()
        if not row:
            raise TaxiiError(404, "Collection introuvable", f"Aucune collection {cid}")
        return self._row_to_collection(row)

    # -- objets --
    @staticmethod
    def _row_to_record(row) -> Dict[str, Any]:
        return {
            "object": json.loads(row["content"]), "id": row["stix_id"],
            "version": row["version"], "spec_version": row["spec_version"],
            "date_added": row["date_added"], "media_type": row["media_type"],
        }

    def get_records(self, cid: str) -> List[Dict[str, Any]]:
        with self._tx() as con:
            rows = con.execute("SELECT * FROM taxii_object WHERE collection_id=?", (cid,)).fetchall()
        return [self._row_to_record(r) for r in rows]

    def seed_object(self, cid: str, obj: Dict[str, Any], date_added: str) -> None:
        with self._tx() as con:
            con.execute(
                """INSERT OR IGNORE INTO taxii_object
                   (collection_id, stix_id, version, spec_version, date_added, media_type, content)
                   VALUES (?,?,?,?,?,?,?)""",
                (cid, obj.get("id"), stix_version(obj), stix_spec_version(obj),
                 date_added, STIX_MEDIA, json.dumps(obj)),
            )

    def add_objects(self, cid: str, objects: List[Dict[str, Any]]) -> Dict[str, Any]:
        successes, failures = [], []
        with self._tx() as con:
            for obj in objects:
                oid = obj.get("id")
                if not oid or "type" not in obj:
                    failures.append({"id": oid or "unknown", "version": stix_version(obj),
                                     "message": "Objet STIX invalide (id/type manquant)"})
                    continue
                ver = stix_version(obj)
                exists = con.execute(
                    "SELECT 1 FROM taxii_object WHERE collection_id=? AND stix_id=? AND version=?",
                    (cid, oid, ver)).fetchone()
                if exists:
                    successes.append({"id": oid, "version": ver, "message": "Déjà présent"})
                    continue
                con.execute(
                    """INSERT INTO taxii_object
                       (collection_id, stix_id, version, spec_version, date_added, media_type, content)
                       VALUES (?,?,?,?,?,?,?)""",
                    (cid, oid, ver, stix_spec_version(obj), now_ts(), STIX_MEDIA, json.dumps(obj)),
                )
                successes.append({"id": oid, "version": ver})
            status = make_status(len(objects), successes, failures)
            con.execute("INSERT OR REPLACE INTO taxii_status (id, content) VALUES (?,?)",
                        (status["id"], json.dumps(status)))
        return status

    def get_status(self, sid: str) -> Dict[str, Any]:
        with self._tx() as con:
            row = con.execute("SELECT content FROM taxii_status WHERE id=?", (sid,)).fetchone()
        if not row:
            raise TaxiiError(404, "Status introuvable", f"Aucun status {sid}")
        return json.loads(row["content"])

    def delete_object(self, cid: str, oid: str, keep_pred) -> None:
        recs = [r for r in self.get_records(cid) if r["id"] == oid]
        if not recs:
            raise TaxiiError(404, "Objet introuvable", f"Aucun objet {oid}")
        to_delete = [r for r in recs if not keep_pred(r)]
        with self._tx() as con:
            for r in to_delete:
                con.execute(
                    "DELETE FROM taxii_object WHERE collection_id=? AND stix_id=? AND version=?",
                    (cid, oid, r["version"]))


# ── Backend « project » : expose les bases XORCISM en STIX (lecture seule) ───────
class ProjectBackend:
    """Lit XVULNERABILITY.VULNERABILITY et XINCIDENT.INCIDENT (read-only) et les
    convertit à la volée en objets STIX 2.1, exposés via deux collections TAXII.

    Lecture seule (can_write=False). Cap configurable (TAXII_PROJECT_MAX) pour la
    table volumineuse des vulnérabilités."""

    COL_VULN = "11111111-1111-4111-8111-111111111111"
    COL_INC = "22222222-2222-4222-8222-222222222222"
    COL_GRAPH = "33333333-3333-4333-8333-333333333333"
    REL_TS = "2024-01-01T00:00:00.000Z"  # timestamp stable des objets dérivés des liens

    def __init__(self, db_dir: str, max_rows: int = 1000) -> None:
        self.db_dir = db_dir
        self.max_rows = max_rows
        self._collections = {
            self.COL_VULN: {
                "id": self.COL_VULN, "title": "XORCISM Vulnerabilities (STIX)",
                "description": "Vulnérabilités (XVULNERABILITY) exposées en STIX 2.1 vulnerability.",
                "alias": "vulnerabilities", "can_read": True, "can_write": False,
                "media_types": [STIX_MEDIA],
            },
            self.COL_INC: {
                "id": self.COL_INC, "title": "XORCISM Incidents (STIX)",
                "description": "Incidents (XINCIDENT) exposés en STIX 2.1 incident.",
                "alias": "incidents", "can_read": True, "can_write": False,
                "media_types": [STIX_MEDIA],
            },
            self.COL_GRAPH: {
                "id": self.COL_GRAPH, "title": "XORCISM Threat Graph (STIX)",
                "description": "Graphe relié : incidents ↔ assets ↔ vulnérabilités ↔ CPE "
                               "(SROs relationship) à partir des tables de jonction XORCISM.",
                "alias": "threat-graph", "can_read": True, "can_write": False,
                "media_types": [STIX_MEDIA],
            },
        }

    def _ro(self, dbname: str) -> "sqlite3.Connection":
        path = os.path.join(self.db_dir, f"{dbname}.db")
        if not os.path.exists(path):
            raise TaxiiError(404, "Base projet introuvable", path)
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
        con.row_factory = sqlite3.Row
        return con

    # -- collections --
    def add_collection(self, meta):  # lecture seule
        raise TaxiiError(403, "Backend project en lecture seule")

    def list_collections(self):
        return list(self._collections.values())

    def get_collection(self, cid):
        col = self._collections.get(cid)
        if not col:
            raise TaxiiError(404, "Collection introuvable", f"Aucune collection {cid}")
        return col

    # -- conversion STIX --
    @staticmethod
    def _record(obj: Dict[str, Any], date_added: str) -> Dict[str, Any]:
        # version = modified (SDO) ; à défaut created ; à défaut date stable (SCO).
        version = obj.get("modified") or obj.get("created") or "2020-01-01T00:00:00.000Z"
        return {"object": obj, "id": obj["id"], "version": version,
                "spec_version": obj.get("spec_version", "2.1"),
                "date_added": date_added, "media_type": STIX_MEDIA}

    def _vuln_to_stix(self, r) -> Dict[str, Any]:
        vid = r["VulnerabilityID"]
        name = r["VULGUID"] or r["VULReferentialID"] or f"VULN-{vid}"
        created = to_rfc3339(r["VULCreatedDate"] or r["CreatedDate"])
        modified = to_rfc3339(r["VULModifiedDate"] or r["VULCreatedDate"] or r["CreatedDate"], created)
        if modified < created:
            modified = created
        obj: Dict[str, Any] = {
            "type": "vulnerability", "spec_version": "2.1",
            "id": det_stix_id("vulnerability", str(vid)),
            "created": created, "modified": modified, "name": name,
        }
        if r["VULDescription"]:
            obj["description"] = strip_html(r["VULDescription"])
        refs = []
        if name and name.upper().startswith("CVE-"):
            refs.append({"source_name": "cve", "external_id": name})
        if r["VULReferentialID"] and r["VULReferentialID"] != name:
            refs.append({"source_name": "xorcism", "external_id": r["VULReferentialID"]})
        if refs:
            obj["external_references"] = refs
        return obj

    def _incident_to_stix(self, r) -> Dict[str, Any]:
        d = dict(r)
        iid = d["IncidentID"]
        name = d.get("IncidentName") or d.get("source_id") or f"Incident {iid}"
        created = to_rfc3339(d.get("datetime_reported") or d.get("CreatedDate"))
        modified = to_rfc3339(d.get("CreatedDate") or d.get("datetime_reported"), created)
        if modified < created:
            modified = created
        obj: Dict[str, Any] = {
            "type": "incident", "spec_version": "2.1",
            "id": det_stix_id("incident", str(iid)),
            "created": created, "modified": modified, "name": name,
        }
        desc = strip_html(d.get("summary")) or d.get("security_compromise")
        if desc:
            obj["description"] = desc
        return obj

    def _agent_to_stix(self, r) -> Dict[str, Any]:
        d = dict(r)
        taid = d["ThreatAgentID"]
        created = to_rfc3339(d.get("CreatedDate"))
        obj: Dict[str, Any] = {
            "type": "threat-actor", "spec_version": "2.1",
            "id": det_stix_id("threat-actor", str(taid)),
            "created": created, "modified": created,
            "name": d.get("ThreatAgentName") or f"Threat Actor {taid}",
        }
        desc = strip_html(d.get("ThreatAgentDescription"))
        if desc:
            obj["description"] = desc
        return obj

    def _event_to_stix(self, r) -> Dict[str, Any]:
        d = dict(r)
        teid = d["ThreatEventID"]
        obj: Dict[str, Any] = {
            "type": "attack-pattern", "spec_version": "2.1",
            "id": det_stix_id("attack-pattern", str(teid)),
            "created": self.REL_TS, "modified": self.REL_TS,
            "name": d.get("ReferentialID") or f"Threat Event {teid}",
        }
        desc = strip_html(d.get("Description"))
        if desc:
            obj["description"] = desc
        if d.get("KCPhase"):
            obj["kill_chain_phases"] = [{
                "kill_chain_name": "nist-800-30",
                "phase_name": str(d["KCPhase"]).strip().lower().replace(" ", "-"),
            }]
        return obj

    def _rel_row_to_stix(self, r) -> Optional[Dict[str, Any]]:
        d = dict(r)
        src, tgt, rtype = d.get("source_ref"), d.get("target_ref"), d.get("relationship_type")
        if not (src and tgt and rtype):
            return None
        rid = d.get("RelationshipGUID") or det_stix_id("relationship", f"{src}|{rtype}|{tgt}")
        ts = to_rfc3339(d.get("CreatedDate"), self.REL_TS)
        obj: Dict[str, Any] = {
            "type": "relationship", "spec_version": "2.1", "id": rid,
            "created": ts, "modified": ts, "relationship_type": rtype,
            "source_ref": src, "target_ref": tgt,
        }
        if d.get("description"):
            obj["description"] = d["description"]
        return obj

    def get_records(self, cid: str) -> List[Dict[str, Any]]:
        if cid == self.COL_VULN:
            with self._ro("XVULNERABILITY") as con:
                rows = con.execute(
                    """SELECT VulnerabilityID, VULGUID, VULReferentialID, VULDescription,
                              VULCreatedDate, VULModifiedDate, CreatedDate
                       FROM VULNERABILITY ORDER BY VulnerabilityID DESC LIMIT ?""",
                    (self.max_rows,)).fetchall()
            out = []
            for r in rows:
                obj = self._vuln_to_stix(r)
                out.append(self._record(obj, to_rfc3339(r["CreatedDate"] or r["VULCreatedDate"], obj["created"])))
            return out
        if cid == self.COL_INC:
            with self._ro("XINCIDENT") as con:
                rows = con.execute(
                    "SELECT * FROM INCIDENT ORDER BY IncidentID DESC LIMIT ?",
                    (self.max_rows,)).fetchall()
            out = []
            for r in rows:
                obj = self._incident_to_stix(r)
                d = dict(r)
                out.append(self._record(obj, to_rfc3339(d.get("CreatedDate") or d.get("datetime_reported"), obj["created"])))
            return out
        if cid == self.COL_GRAPH:
            return self._graph_records()
        raise TaxiiError(404, "Collection introuvable", f"Aucune collection {cid}")

    def _graph_records(self) -> List[Dict[str, Any]]:
        """Construit un graphe STIX connecté à partir des tables de jonction :
           INCIDENTFORASSET (incident↔asset), ASSETVULNERABILITY (asset↔vuln),
           CPEFORASSET (asset↔cpe). Assets → identity(system), CPE → software,
           liens → relationship. Id déterministes (corrélables entre collections)."""
        objects: Dict[str, Dict[str, Any]] = {}
        rels: Dict[str, Dict[str, Any]] = {}

        def aid_id(aid):
            return det_stix_id("identity", f"asset:{aid}")

        def add_rel(src: str, tgt: str, rtype: str) -> None:
            rid = det_stix_id("relationship", f"{src}|{rtype}|{tgt}")
            if rid not in rels:
                rels[rid] = {
                    "type": "relationship", "spec_version": "2.1", "id": rid,
                    "created": self.REL_TS, "modified": self.REL_TS,
                    "relationship_type": rtype, "source_ref": src, "target_ref": tgt,
                }

        # 1) Liens
        with self._ro("XORCISM") as con:
            av = con.execute(
                "SELECT AssetID, VulnerabilityID FROM ASSETVULNERABILITY "
                "WHERE AssetID IS NOT NULL AND VulnerabilityID IS NOT NULL LIMIT ?",
                (self.max_rows,)).fetchall()
            ca = con.execute(
                "SELECT fa.AssetID AS AssetID, c.CPEID AS CPEID, c.CPEName AS CPEName "
                "FROM CPEFORASSET fa JOIN CPE c ON c.CPEID = fa.CPEID "
                "WHERE fa.AssetID IS NOT NULL LIMIT ?", (self.max_rows,)).fetchall()
        with self._ro("XINCIDENT") as con:
            ia = con.execute(
                "SELECT IncidentID, AssetID FROM INCIDENTFORASSET "
                "WHERE AssetID IS NOT NULL AND IncidentID IS NOT NULL LIMIT ?",
                (self.max_rows,)).fetchall()

        asset_ids = {r["AssetID"] for r in av} | {r["AssetID"] for r in ca} | {r["AssetID"] for r in ia}
        vuln_ids = {r["VulnerabilityID"] for r in av}
        inc_ids = {r["IncidentID"] for r in ia}

        # 2) Entités : assets → identity(system)
        names: Dict[Any, str] = {}
        if asset_ids:
            with self._ro("XORCISM") as con:
                ph = ",".join("?" * len(asset_ids))
                for r in con.execute(f"SELECT AssetID, AssetName FROM ASSET WHERE AssetID IN ({ph})",
                                     tuple(asset_ids)):
                    names[r["AssetID"]] = r["AssetName"]
        for aid in asset_ids:
            oid = aid_id(aid)
            objects[oid] = {
                "type": "identity", "spec_version": "2.1", "id": oid,
                "created": self.REL_TS, "modified": self.REL_TS,
                "name": names.get(aid) or f"Asset {aid}", "identity_class": "system",
            }

        # vulnérabilités (mêmes id que la collection vulnerabilities)
        if vuln_ids:
            with self._ro("XVULNERABILITY") as con:
                ph = ",".join("?" * len(vuln_ids))
                for r in con.execute(
                    "SELECT VulnerabilityID, VULGUID, VULReferentialID, VULDescription, "
                    f"VULCreatedDate, VULModifiedDate, CreatedDate FROM VULNERABILITY "
                    f"WHERE VulnerabilityID IN ({ph})", tuple(vuln_ids)):
                    o = self._vuln_to_stix(r)
                    objects[o["id"]] = o

        # incidents (mêmes id que la collection incidents)
        if inc_ids:
            with self._ro("XINCIDENT") as con:
                ph = ",".join("?" * len(inc_ids))
                for r in con.execute(f"SELECT * FROM INCIDENT WHERE IncidentID IN ({ph})",
                                     tuple(inc_ids)):
                    o = self._incident_to_stix(r)
                    objects[o["id"]] = o

        # CPE → software (SCO)
        asset_cpe = []
        for r in ca:
            sid = det_stix_id("software", f"cpe:{r['CPEID']}")
            if sid not in objects:
                name = r["CPEName"] or f"CPE {r['CPEID']}"
                sw: Dict[str, Any] = {"type": "software", "spec_version": "2.1", "id": sid, "name": name}
                if isinstance(name, str) and name.startswith("cpe:2.3:"):
                    sw["cpe"] = name
                objects[sid] = sw
            asset_cpe.append((r["AssetID"], sid))

        # 3) Relations
        for r in av:
            add_rel(aid_id(r["AssetID"]), det_stix_id("vulnerability", str(r["VulnerabilityID"])), "has")
        for r in ia:
            add_rel(det_stix_id("incident", str(r["IncidentID"])), aid_id(r["AssetID"]), "related-to")
        for aid, sid in asset_cpe:
            add_rel(aid_id(aid), sid, "has")

        # 3bis) XTHREAT : threat-actors (THREATAGENT), attack-patterns (THREATEVENT)
        # et relations explicites de la table RELATIONSHIP (SROs).
        agents, relrows, events = [], [], []
        try:
            with self._ro("XTHREAT") as con:
                agents = con.execute("SELECT * FROM THREATAGENT LIMIT ?", (self.max_rows,)).fetchall()
                try:
                    relrows = con.execute("SELECT * FROM RELATIONSHIP LIMIT ?", (self.max_rows,)).fetchall()
                except sqlite3.OperationalError:
                    relrows = []  # table RELATIONSHIP absente
                events = con.execute(
                    "SELECT ThreatEventID, ReferentialID, KCPhase, Tier, Description, Category "
                    "FROM THREATEVENT").fetchall()
        except TaxiiError:
            pass

        # threat-actors (catalogue)
        for a in agents:
            o = self._agent_to_stix(a)
            objects[o["id"]] = o
        # index attack-patterns par id STIX déterministe (matérialisés à la demande)
        ev_rows = {det_stix_id("attack-pattern", str(e["ThreatEventID"])): e for e in events}
        # relations explicites + matérialisation des cibles référencées
        referenced = set()
        for r in relrows:
            rel = self._rel_row_to_stix(r)
            if rel:
                rels[rel["id"]] = rel
                referenced.add(rel["source_ref"])
                referenced.add(rel["target_ref"])
        for rid in referenced:
            if rid in ev_rows and rid not in objects:
                objects[rid] = self._event_to_stix(ev_rows[rid])

        # 4) Enregistrements TAXII
        out = []
        for o in list(objects.values()) + list(rels.values()):
            out.append(self._record(o, o.get("created", self.REL_TS)))
        return out

    # -- écriture / statuts : non supportés (lecture seule) --
    def seed_object(self, cid, obj, date_added):
        pass

    def add_objects(self, cid, objects):
        raise TaxiiError(403, "Écriture non autorisée (backend project en lecture seule)")

    def get_status(self, sid):
        raise TaxiiError(404, "Status introuvable", f"Aucun status {sid}")

    def delete_object(self, cid, oid, keep_pred):
        raise TaxiiError(403, "Suppression non autorisée (backend project en lecture seule)")


# ── Filtrage / versionnement ────────────────────────────────────────────────────
def _csv(val: str) -> set:
    return {v.strip() for v in val.split(",") if v.strip()}


def apply_filters(records: List[Dict[str, Any]], args, default_version: str) -> List[Dict[str, Any]]:
    """Applique match[id|type|spec_version|version] + added_after, puis trie par date_added."""
    out = records

    if (v := args.get("match[id]")):
        ids = _csv(v)
        out = [r for r in out if r["id"] in ids]
    if (v := args.get("match[type]")):
        types = _csv(v)
        out = [r for r in out if r["object"].get("type") in types]
    if (v := args.get("added_after")):
        out = [r for r in out if r["date_added"] > v]

    # spec_version : si fourni → filtre ; sinon → dernière spec_version par objet
    if (v := args.get("match[spec_version]")):
        svs = _csv(v)
        out = [r for r in out if r["spec_version"] in svs]
    else:
        latest_sv: Dict[str, str] = {}
        for r in out:
            latest_sv[r["id"]] = max(latest_sv.get(r["id"], ""), r["spec_version"])
        out = [r for r in out if r["spec_version"] == latest_sv[r["id"]]]

    # version : first / last / all / timestamp(s) exact(s)
    out = _apply_version(out, args.get("match[version]", default_version))

    out.sort(key=lambda r: r["date_added"])
    return out


def _apply_version(records: List[Dict[str, Any]], raw: str) -> List[Dict[str, Any]]:
    tokens = _csv(raw) or {"last"}
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        groups[r["id"]].append(r)

    chosen_ids: set = set()
    for recs in groups.values():
        ordered = sorted(recs, key=lambda r: r["version"])
        for tok in tokens:
            if tok == "all":
                chosen_ids.update(id(r) for r in ordered)
            elif tok == "first":
                chosen_ids.add(id(ordered[0]))
            elif tok == "last":
                chosen_ids.add(id(ordered[-1]))
            else:  # timestamp exact
                chosen_ids.update(id(r) for r in ordered if r["version"] == tok)
    return [r for r in records if id(r) in chosen_ids]


# ── Pagination ──────────────────────────────────────────────────────────────────
def get_limit() -> int:
    raw = request.args.get("limit")
    if raw is None:
        return DEFAULT_PAGE
    if not raw.isdigit() or int(raw) <= 0:
        raise TaxiiError(400, "Paramètre limit invalide", "limit doit être un entier positif")
    return min(int(raw), DEFAULT_PAGE if DEFAULT_PAGE > int(raw) else int(raw))


def _decode_next(tok: str) -> int:
    try:
        return int(base64.urlsafe_b64decode(tok.encode()).decode())
    except Exception:
        raise TaxiiError(400, "Paramètre next invalide")


def paginate(records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], bool, Optional[str]]:
    offset = _decode_next(request.args["next"]) if request.args.get("next") else 0
    limit = get_limit()
    page = records[offset:offset + limit]
    more = (offset + limit) < len(records)
    nxt = base64.urlsafe_b64encode(str(offset + limit).encode()).decode() if more else None
    return page, more, nxt


# ── Réponses ────────────────────────────────────────────────────────────────────
def taxii_response(payload: Any, status: int = 200,
                   records_for_headers: Optional[List[Dict[str, Any]]] = None) -> Response:
    resp = Response(json.dumps(payload), status=status, mimetype="application/taxii+json")
    resp.headers["Content-Type"] = TAXII_MEDIA
    if records_for_headers:
        resp.headers["X-TAXII-Date-Added-First"] = records_for_headers[0]["date_added"]
        resp.headers["X-TAXII-Date-Added-Last"] = records_for_headers[-1]["date_added"]
    return resp


def error_response(http_status: int, title: str, description: Optional[str] = None) -> Response:
    err = {"title": title, "http_status": str(http_status)}
    if description:
        err["description"] = description
    err["error_id"] = str(uuid.uuid4())
    resp = taxii_response(err, status=http_status)
    if http_status == 401:
        resp.headers["WWW-Authenticate"] = 'Basic realm="TAXII", charset="UTF-8"'
    return resp


# ── Négociation de contenu / auth ───────────────────────────────────────────────
def accept_ok(accept: str) -> bool:
    if not accept:
        return True  # absence d'Accept → version la plus haute (autorisé)
    for rng in accept.split(","):
        parts = [p.strip() for p in rng.split(";")]
        media = parts[0].lower()
        if media in ("*/*", "application/*"):
            return True
        if media in ("application/taxii", "application/taxii+json"):
            ver = next((p.split("=", 1)[1].strip() for p in parts[1:]
                        if p.lower().startswith("version=")), None)
            if ver is None or ver == TAXII_VERSION:
                return True
    return False


def content_type_ok(ctype: str) -> bool:
    ct = (ctype or "").split(";")[0].strip().lower()
    return ct in ("application/taxii+json", "application/stix+json")


def check_auth() -> None:
    """Lève 401 si l'authentification est requise et absente/invalide."""
    if not AUTH_ENABLED:
        return
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Basic "):
        try:
            user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
            if USERS.get(user) == pw:
                request.environ["taxii.user"] = user
                return
        except Exception:
            pass
    raise TaxiiError(401, "Authentification requise")


# ── Application Flask ────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.url_map.strict_slashes = True

# Backend : SQLite persistant par défaut (TAXII_BACKEND=memory pour l'éphémère).
# Base : TAXII_DB, sinon taxii.db dans le dossier de bases hors-OneDrive, sinon
# à côté du script.
_DB_DIR = r"C:\Users\jerom\XORCISM_databases"
TAXII_DB = os.getenv("TAXII_DB") or (
    os.path.join(_DB_DIR, "taxii.db") if os.path.isdir(_DB_DIR)
    else os.path.join(os.path.dirname(os.path.abspath(__file__)), "taxii.db")
)
TAXII_BACKEND = os.getenv("TAXII_BACKEND", "sqlite").lower()
# Backend « project » : expose les bases XORCISM (vulnérabilités / incidents) en STIX.
PROJECT_DB_DIR = os.getenv("TAXII_PROJECT_DB_DIR", _DB_DIR)
PROJECT_MAX = int(os.getenv("TAXII_PROJECT_MAX", "1000"))


def _make_backend() -> Any:
    if TAXII_BACKEND == "memory":
        return MemoryBackend()
    if TAXII_BACKEND == "project":
        return ProjectBackend(PROJECT_DB_DIR, max_rows=PROJECT_MAX)
    return SqliteBackend(TAXII_DB)


backend: Any = _make_backend()

API_ROOTS: Dict[str, Dict[str, str]] = {
    "api1": {
        "title": "XORCISM TAXII 2.1 API Root",
        "description": "API Root principal pour le partage de renseignement (STIX 2.1).",
    }
}

SERVER_DISCOVERY = {
    "title": "XORCISM TAXII 2.1 Server",
    "description": "Serveur TAXII 2.1 conforme OASIS (backend mémoire de démonstration).",
    "contact": "contact@hackenaton.org",
}


def base_url() -> str:
    return request.url_root  # ex. http://127.0.0.1:5000/


def check_api_root(api_root: str) -> None:
    if api_root not in API_ROOTS:
        raise TaxiiError(404, "API Root introuvable", f"Aucun API Root « {api_root} »")


def require_read(col: Dict[str, Any]) -> None:
    if not col.get("can_read"):
        raise TaxiiError(403, "Lecture non autorisée sur cette collection")


def require_write(col: Dict[str, Any]) -> None:
    if not col.get("can_write"):
        raise TaxiiError(403, "Écriture non autorisée sur cette collection")


@app.errorhandler(TaxiiError)
def _on_taxii_error(e: TaxiiError) -> Response:
    return error_response(e.http_status, e.title, e.description)


@app.errorhandler(404)
def _on_404(_e) -> Response:
    return error_response(404, "Ressource introuvable")


@app.errorhandler(405)
def _on_405(_e) -> Response:
    return error_response(405, "Méthode non autorisée")


@app.errorhandler(413)
def _on_413(_e) -> Response:
    return error_response(413, "Corps de requête trop volumineux")


@app.before_request
def _gate() -> None:
    check_auth()
    if not accept_ok(request.headers.get("Accept", "")):
        raise TaxiiError(406, "Type de média Accept non supporté",
                         f"Utilisez {TAXII_MEDIA}")


# ── Endpoints ───────────────────────────────────────────────────────────────────
@app.get("/taxii2/")
def discovery() -> Response:
    root_url = base_url() + "api1/"
    payload = dict(SERVER_DISCOVERY)
    payload["default"] = root_url
    payload["api_roots"] = [base_url() + f"{name}/" for name in API_ROOTS]
    return taxii_response(payload)


@app.get("/<api_root>/")
def api_root_resource(api_root: str) -> Response:
    check_api_root(api_root)
    meta = API_ROOTS[api_root]
    return taxii_response({
        "title": meta["title"],
        "description": meta["description"],
        "versions": [TAXII_MEDIA],
        "max_content_length": MAX_CONTENT_LENGTH,
    })


@app.get("/<api_root>/status/<status_id>/")
def status_resource(api_root: str, status_id: str) -> Response:
    check_api_root(api_root)
    return taxii_response(backend.get_status(status_id))


@app.get("/<api_root>/collections/")
def collections_resource(api_root: str) -> Response:
    check_api_root(api_root)
    cols = [_public_collection(c) for c in backend.list_collections() if c.get("can_read") or c.get("can_write")]
    return taxii_response({"collections": cols} if cols else {})


@app.get("/<api_root>/collections/<col_id>/")
def collection_resource(api_root: str, col_id: str) -> Response:
    check_api_root(api_root)
    col = backend.get_collection(col_id)
    return taxii_response(_public_collection(col))


def _public_collection(c: Dict[str, Any]) -> Dict[str, Any]:
    out = {
        "id": c["id"],
        "title": c["title"],
        "can_read": bool(c.get("can_read")),
        "can_write": bool(c.get("can_write")),
        "media_types": c.get("media_types", [STIX_MEDIA]),
    }
    if c.get("description"):
        out["description"] = c["description"]
    if c.get("alias"):
        out["alias"] = c["alias"]
    return out


@app.get("/<api_root>/collections/<col_id>/manifest/")
def manifest_resource(api_root: str, col_id: str) -> Response:
    check_api_root(api_root)
    col = backend.get_collection(col_id)
    require_read(col)
    records = apply_filters(backend.get_records(col_id), request.args, default_version="last")
    page, more, nxt = paginate(records)
    payload: Dict[str, Any] = {}
    if page:
        payload["objects"] = [{
            "id": r["id"],
            "date_added": r["date_added"],
            "version": r["version"],
            "media_type": r["media_type"],
        } for r in page]
    if more:
        payload["more"] = True
    return taxii_response(payload, records_for_headers=page or None)


@app.route("/<api_root>/collections/<col_id>/objects/", methods=["GET", "POST"])
def objects_resource(api_root: str, col_id: str) -> Response:
    check_api_root(api_root)
    col = backend.get_collection(col_id)

    if request.method == "POST":
        require_write(col)
        if not content_type_ok(request.headers.get("Content-Type", "")):
            raise TaxiiError(415, "Content-Type non supporté",
                             "Utilisez application/taxii+json ou application/stix+json")
        try:
            body = request.get_json(force=True, silent=False)
        except Exception:
            raise TaxiiError(400, "Corps JSON invalide")
        objs = (body or {}).get("objects")
        if not isinstance(objs, list):
            raise TaxiiError(400, "Enveloppe invalide", "Le champ 'objects' (liste) est requis")
        status = backend.add_objects(col_id, objs)
        return taxii_response(status, status=202)

    # GET → enveloppe
    require_read(col)
    records = apply_filters(backend.get_records(col_id), request.args, default_version="last")
    page, more, nxt = paginate(records)
    payload: Dict[str, Any] = {}
    if page:
        payload["objects"] = [r["object"] for r in page]
    if more:
        payload["more"] = True
        if nxt:
            payload["next"] = nxt
    return taxii_response(payload, records_for_headers=page or None)


@app.route("/<api_root>/collections/<col_id>/objects/<object_id>/", methods=["GET", "DELETE"])
def object_resource(api_root: str, col_id: str, object_id: str) -> Response:
    check_api_root(api_root)
    col = backend.get_collection(col_id)

    if request.method == "DELETE":
        require_write(col)
        # Détermine les versions à supprimer (défaut : toutes)
        sel = apply_filters([r for r in backend.get_records(col_id) if r["id"] == object_id],
                            request.args, default_version="all")
        if not sel:
            raise TaxiiError(404, "Objet introuvable", f"Aucun objet {object_id}")
        keep_versions = {r["version"] for r in sel}
        backend.delete_object(col_id, object_id, keep_pred=lambda r: r["version"] not in keep_versions)
        return taxii_response({}, status=200)

    # GET → enveloppe (toutes les versions par défaut)
    require_read(col)
    base = [r for r in backend.get_records(col_id) if r["id"] == object_id]
    if not base:
        raise TaxiiError(404, "Objet introuvable", f"Aucun objet {object_id}")
    records = apply_filters(base, request.args, default_version="all")
    page, more, nxt = paginate(records)
    payload: Dict[str, Any] = {}
    if page:
        payload["objects"] = [r["object"] for r in page]
    if more:
        payload["more"] = True
        if nxt:
            payload["next"] = nxt
    return taxii_response(payload, records_for_headers=page or None)


@app.get("/<api_root>/collections/<col_id>/objects/<object_id>/versions/")
def versions_resource(api_root: str, col_id: str, object_id: str) -> Response:
    check_api_root(api_root)
    col = backend.get_collection(col_id)
    require_read(col)
    base = [r for r in backend.get_records(col_id) if r["id"] == object_id]
    if not base:
        raise TaxiiError(404, "Objet introuvable", f"Aucun objet {object_id}")
    # Toutes les versions (filtrables par spec_version / added_after)
    records = apply_filters(base, request.args, default_version="all")
    page, more, nxt = paginate(records)
    payload: Dict[str, Any] = {}
    if page:
        payload["versions"] = [r["version"] for r in page]
    if more:
        payload["more"] = True
    return taxii_response(payload, records_for_headers=page or None)


# ── Données de démonstration ─────────────────────────────────────────────────────
def seed_demo() -> None:
    if backend.list_collections():
        return  # base déjà initialisée (persistance) — pas de re-seed
    col_a = "91a7b528-80eb-42ed-a74d-c6fbd5a26116"
    col_b = "52892447-4d7e-4f70-b94d-d7f22742ff63"
    backend.add_collection({
        "id": col_a, "title": "High-Value Indicators",
        "description": "Indicateurs et logiciels malveillants (lecture seule).",
        "alias": "high-value-indicators", "can_read": True, "can_write": False,
        "media_types": [STIX_MEDIA],
    })
    backend.add_collection({
        "id": col_b, "title": "Sandbox (writable)",
        "description": "Collection de dépôt ouverte en écriture.",
        "alias": "sandbox", "can_read": True, "can_write": True,
        "media_types": [STIX_MEDIA],
    })

    ind_id = "indicator--cd981c25-8042-4166-8945-51178443bdac"
    backend.seed_object(col_a, {
        "type": "indicator", "spec_version": "2.1", "id": ind_id,
        "created": "2024-01-01T00:00:00.000Z", "modified": "2024-01-01T00:00:00.000Z",
        "name": "Malicious IP", "indicator_types": ["malicious-activity"],
        "pattern": "[ipv4-addr:value = '198.51.100.5']", "pattern_type": "stix",
        "valid_from": "2024-01-01T00:00:00Z",
    }, date_added="2024-01-01T08:00:00.000000Z")
    # Seconde version du même indicateur (modified plus récent) → versionnement
    backend.seed_object(col_a, {
        "type": "indicator", "spec_version": "2.1", "id": ind_id,
        "created": "2024-01-01T00:00:00.000Z", "modified": "2024-02-01T00:00:00.000Z",
        "name": "Malicious IP (updated)", "indicator_types": ["malicious-activity"],
        "pattern": "[ipv4-addr:value = '198.51.100.5']", "pattern_type": "stix",
        "valid_from": "2024-01-01T00:00:00Z",
    }, date_added="2024-02-01T09:30:00.000000Z")

    mal_id = "malware--3a41e552-999b-4ad3-bedc-332b6d9ff80c"
    backend.seed_object(col_a, {
        "type": "malware", "spec_version": "2.1", "id": mal_id,
        "created": "2024-01-05T00:00:00.000Z", "modified": "2024-01-05T00:00:00.000Z",
        "name": "ShadowPad", "is_family": True, "malware_types": ["backdoor"],
    }, date_added="2024-01-05T10:00:00.000000Z")

    backend.seed_object(col_a, {
        "type": "relationship", "spec_version": "2.1",
        "id": "relationship--6a2eab9c-6e6f-49f0-9a98-3b1e2b3d8d2a",
        "created": "2024-01-06T00:00:00.000Z", "modified": "2024-01-06T00:00:00.000Z",
        "relationship_type": "indicates", "source_ref": ind_id, "target_ref": mal_id,
    }, date_added="2024-01-06T11:15:00.000000Z")


seed_demo()


if __name__ == "__main__":
    host = os.getenv("TAXII_HOST", "127.0.0.1")
    port = int(os.getenv("TAXII_PORT", "5000"))
    store = {"memory": "memory", "project": f"project:{PROJECT_DB_DIR}"}.get(
        TAXII_BACKEND, f"sqlite:{TAXII_DB}")
    print(f"  TAXII 2.1 server -> http://{host}:{port}/taxii2/   (auth={'on' if AUTH_ENABLED else 'off'}, store={store})")
    app.run(host=host, port=port, debug=False)
