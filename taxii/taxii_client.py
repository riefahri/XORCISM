"""
taxii_client.py — Client TAXII 2.1 avancé (CLI + bibliothèque).
Réf. : https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html

Fonctions : découverte, listing des API Roots / collections, lecture d'objets
avec filtres et pagination automatique, manifest, versions, ajout (POST) depuis
un fichier STIX (bundle/enveloppe/objet) avec suivi de Status, suppression,
authentification HTTP Basic, export JSON.

Dépendance : requests  (pip install requests)

Exemples :
    python taxii_client.py --url http://127.0.0.1:5000 discovery
    python taxii_client.py --url http://127.0.0.1:5000 collections
    python taxii_client.py --url http://127.0.0.1:5000 get --collection <id> --type indicator --all
    python taxii_client.py --url http://127.0.0.1:5000 add --collection <id> --file ../stix/bundle-threat-report.json --poll
    python taxii_client.py --url http://127.0.0.1:5000 manifest --collection <id>
    python taxii_client.py --url http://127.0.0.1:5000 versions --collection <id> --object <stix-id>
    python taxii_client.py --url http://127.0.0.1:5000 delete --collection <id> --object <stix-id>
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Iterator, List, Optional

import requests

TAXII_MEDIA = "application/taxii+json;version=2.1"
STIX_MEDIA = "application/stix+json;version=2.1"


class TaxiiClientError(Exception):
    pass


class TAXII2Client:
    """Client TAXII 2.1 minimal mais complet."""

    def __init__(self, base_url: str, user: Optional[str] = None,
                 password: Optional[str] = None, verify: bool = True,
                 timeout: int = 30) -> None:
        self.base = base_url.rstrip("/") + "/"
        self.verify = verify
        self.timeout = timeout
        self.session = requests.Session()
        if user is not None:
            self.session.auth = (user, password or "")
        self.session.headers.update({"Accept": TAXII_MEDIA})

    # -- bas niveau --
    def _url(self, path: str) -> str:
        return self.base + path.lstrip("/")

    def _request(self, method: str, path: str, *, params=None, body=None,
                 content_type: Optional[str] = None) -> requests.Response:
        headers = {}
        if content_type:
            headers["Content-Type"] = content_type
        resp = self.session.request(
            method, self._url(path), params=params,
            data=json.dumps(body) if body is not None else None,
            headers=headers, verify=self.verify, timeout=self.timeout,
        )
        if resp.status_code >= 400:
            detail = ""
            try:
                err = resp.json()
                detail = f" — {err.get('title','')}: {err.get('description','')}".rstrip(": ")
            except Exception:
                detail = f" — {resp.text[:200]}"
            raise TaxiiClientError(f"HTTP {resp.status_code} {method} {path}{detail}")
        return resp

    def _get(self, path: str, params=None) -> Dict[str, Any]:
        return self._request("GET", path, params=params).json()

    # -- ressources TAXII --
    def discovery(self) -> Dict[str, Any]:
        return self._get("taxii2/")

    def collections(self, api_root: str) -> List[Dict[str, Any]]:
        return self._get(f"{api_root}/collections/").get("collections", [])

    def collection(self, api_root: str, cid: str) -> Dict[str, Any]:
        return self._get(f"{api_root}/collections/{cid}/")

    def manifest(self, api_root: str, cid: str, **filters) -> Iterator[Dict[str, Any]]:
        yield from self._paginate(f"{api_root}/collections/{cid}/manifest/", "objects", filters)

    def versions(self, api_root: str, cid: str, object_id: str, **filters) -> List[str]:
        data = self._get(f"{api_root}/collections/{cid}/objects/{object_id}/versions/", filters)
        return data.get("versions", [])

    def get_objects(self, api_root: str, cid: str, **filters) -> Iterator[Dict[str, Any]]:
        """Itère sur tous les objets (pagination automatique via 'next'/'more')."""
        yield from self._paginate(f"{api_root}/collections/{cid}/objects/", "objects", filters)

    def get_object(self, api_root: str, cid: str, object_id: str, **filters) -> List[Dict[str, Any]]:
        data = self._get(f"{api_root}/collections/{cid}/objects/{object_id}/", filters)
        return data.get("objects", [])

    def add_objects(self, api_root: str, cid: str, objects: List[Dict[str, Any]]) -> Dict[str, Any]:
        resp = self._request(
            "POST", f"{api_root}/collections/{cid}/objects/",
            body={"objects": objects}, content_type=TAXII_MEDIA,
        )
        return resp.json()

    def get_status(self, api_root: str, status_id: str) -> Dict[str, Any]:
        return self._get(f"{api_root}/status/{status_id}/")

    def delete_object(self, api_root: str, cid: str, object_id: str, **filters) -> None:
        self._request("DELETE", f"{api_root}/collections/{cid}/objects/{object_id}/", params=filters)

    # -- pagination --
    def _paginate(self, path: str, key: str, filters: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
        params = {k: v for k, v in filters.items() if v is not None}
        while True:
            data = self._get(path, params)
            for item in data.get(key, []):
                yield item
            if not data.get("more"):
                break
            nxt = data.get("next")
            if nxt:
                params["next"] = nxt
            else:
                # Pas de token 'next' : on s'appuie sur l'offset implicite — arrêt.
                break


# ── Filtres : transforme les arguments CLI en paramètres TAXII match[...] ─────────
def build_filters(args) -> Dict[str, Any]:
    f: Dict[str, Any] = {}
    if getattr(args, "type", None):
        f["match[type]"] = args.type
    if getattr(args, "id", None):
        f["match[id]"] = args.id
    if getattr(args, "version", None):
        f["match[version]"] = args.version
    if getattr(args, "spec_version", None):
        f["match[spec_version]"] = args.spec_version
    if getattr(args, "added_after", None):
        f["added_after"] = args.added_after
    if getattr(args, "limit", None):
        f["limit"] = args.limit
    return f


# ── Chargement STIX (bundle / enveloppe / objet) ─────────────────────────────────
def load_stix_objects(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if data.get("type") == "bundle":
            return data.get("objects", [])
        if "objects" in data:               # enveloppe TAXII
            return data["objects"]
        if "type" in data and "id" in data:  # objet STIX unique
            return [data]
    raise TaxiiClientError(f"{path} : contenu STIX non reconnu (bundle/enveloppe/objet attendu)")


def out(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def save(objects: List[Dict[str, Any]], path: str) -> None:
    bundle = {"type": "bundle", "id": "bundle--" + _rand_uuid(), "objects": objects}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2, ensure_ascii=False)
    print(f"  {len(objects)} objet(s) écrit(s) dans {path}")


def _rand_uuid() -> str:
    import uuid
    return str(uuid.uuid4())


# ── CLI ──────────────────────────────────────────────────────────────────────────
def main() -> None:
    p = argparse.ArgumentParser(description="Client TAXII 2.1 avancé")
    p.add_argument("--url", required=True, help="URL de base du serveur TAXII (ex. http://127.0.0.1:5000)")
    p.add_argument("--api-root", default="api1", help="Nom de l'API Root (défaut : api1)")
    p.add_argument("--user", help="Utilisateur HTTP Basic")
    p.add_argument("--password", help="Mot de passe HTTP Basic")
    p.add_argument("--insecure", action="store_true", help="Ne pas vérifier le certificat TLS")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("discovery", help="Ressource Discovery")
    sub.add_parser("apiroot", help="Ressource API Root")
    sub.add_parser("collections", help="Liste les collections")

    sp = sub.add_parser("collection", help="Détail d'une collection")
    sp.add_argument("--collection", required=True)

    def add_filters(sp_):
        sp_.add_argument("--type", help="match[type] (ex. indicator,malware)")
        sp_.add_argument("--id", help="match[id] (STIX id)")
        sp_.add_argument("--version", help="match[version] : first|last|all|<timestamp>")
        sp_.add_argument("--spec-version", dest="spec_version", help="match[spec_version] (ex. 2.1)")
        sp_.add_argument("--added-after", dest="added_after", help="added_after (timestamp RFC3339)")
        sp_.add_argument("--limit", type=int, help="Taille de page (limit)")

    sp = sub.add_parser("get", help="Lit des objets (pagination auto avec --all)")
    sp.add_argument("--collection", required=True)
    sp.add_argument("--all", action="store_true", help="Suivre toutes les pages")
    sp.add_argument("-o", "--output", help="Écrit le résultat dans un fichier (bundle)")
    add_filters(sp)

    sp = sub.add_parser("object", help="Lit un objet précis (toutes versions)")
    sp.add_argument("--collection", required=True)
    sp.add_argument("--object", required=True)

    sp = sub.add_parser("manifest", help="Manifest d'une collection")
    sp.add_argument("--collection", required=True)
    add_filters(sp)

    sp = sub.add_parser("versions", help="Versions d'un objet")
    sp.add_argument("--collection", required=True)
    sp.add_argument("--object", required=True)

    sp = sub.add_parser("add", help="Ajoute des objets STIX depuis un fichier")
    sp.add_argument("--collection", required=True)
    sp.add_argument("--file", required=True)
    sp.add_argument("--poll", action="store_true", help="Affiche le Status renvoyé puis le relit")

    sp = sub.add_parser("delete", help="Supprime un objet")
    sp.add_argument("--collection", required=True)
    sp.add_argument("--object", required=True)
    sp.add_argument("--version", help="match[version] (défaut : toutes)")

    sp = sub.add_parser("status", help="Lit une ressource Status")
    sp.add_argument("--status-id", required=True)

    args = p.parse_args()
    c = TAXII2Client(args.url, user=args.user, password=args.password, verify=not args.insecure)
    ar = args.api_root

    try:
        if args.cmd == "discovery":
            out(c.discovery())

        elif args.cmd == "apiroot":
            out(c._get(f"{ar}/"))

        elif args.cmd == "collections":
            cols = c.collections(ar)
            for col in cols:
                print(f"  {col['id']}  {col['title']}  (read={col['can_read']} write={col['can_write']})")
            if not cols:
                print("  (aucune)")

        elif args.cmd == "collection":
            out(c.collection(ar, args.collection))

        elif args.cmd == "get":
            objs = list(c.get_objects(ar, args.collection, **build_filters(args))) if args.all \
                else list(c.get_objects(ar, args.collection, **build_filters(args)))
            if args.output:
                save(objs, args.output)
            else:
                out({"count": len(objs), "objects": objs})

        elif args.cmd == "object":
            out(c.get_object(ar, args.collection, args.object))

        elif args.cmd == "manifest":
            recs = list(c.manifest(ar, args.collection, **build_filters(args)))
            for r in recs:
                print(f"  {r['id']}  v={r['version']}  added={r['date_added']}")
            if not recs:
                print("  (vide)")

        elif args.cmd == "versions":
            for v in c.versions(ar, args.collection, args.object):
                print(f"  {v}")

        elif args.cmd == "add":
            objs = load_stix_objects(args.file)
            status = c.add_objects(ar, args.collection, objs)
            print(f"  envoyés={len(objs)}  status={status.get('status')}  "
                  f"success={status.get('success_count')}  fail={status.get('failure_count')}  "
                  f"id={status.get('id')}")
            if args.poll:
                out(c.get_status(ar, status["id"]))

        elif args.cmd == "delete":
            f = {"match[version]": args.version} if args.version else {}
            c.delete_object(ar, args.collection, args.object, **f)
            print(f"  supprimé : {args.object}")

        elif args.cmd == "status":
            out(c.get_status(ar, args.status_id))

    except TaxiiClientError as e:
        print(f"ERREUR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
