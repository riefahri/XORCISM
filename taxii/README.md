# Serveur TAXII 2.1 (Python / Flask)

Implémentation conforme à la spécification OASIS **TAXII 2.1** :
<https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html>

Échange de renseignement sur les cybermenaces (CTI), contenu **STIX 2.1**.

## Installation & lancement

```bash
pip install flask
python taxii_server.py                 # http://127.0.0.1:5000 (backend SQLite persistant)
TAXII_PORT=5001 python taxii_server.py  # autre port
TAXII_AUTH=1 python taxii_server.py     # exige HTTP Basic (admin / $TAXII_PASSWORD, défaut "taxii")
TAXII_BACKEND=memory python taxii_server.py   # stockage éphémère (tests)
```

Variables d'environnement : `TAXII_HOST`, `TAXII_PORT`, `TAXII_AUTH`, `TAXII_PASSWORD`,
`TAXII_BACKEND` (`sqlite` par défaut, ou `memory`), `TAXII_DB` (chemin du fichier SQLite).

## Stockage

Par défaut, **backend SQLite persistant** (`SqliteBackend`). Le fichier est
`TAXII_DB`, sinon `taxii.db` dans le dossier de bases hors-OneDrive
(`C:\Users\jerom\XORCISM_databases\taxii.db`), sinon à côté du script.

Tables : `taxii_collection`, `taxii_object` (une ligne par **version** STIX,
contenu JSON), `taxii_status`. Mode WAL, `busy_timeout`. Le jeu de démonstration
n'est inséré **qu'une fois** (si la base est vide) — les ajouts ultérieurs
survivent aux redémarrages.

Pour brancher un autre stockage (PostgreSQL, base STIX existante…), implémenter
la même interface que `SqliteBackend` :
`add_collection`, `list_collections`, `get_collection`, `get_records(cid)`,
`seed_object`, `add_objects`, `get_status`, `delete_object`.

### Backend « project » (bases XORCISM en STIX)

Expose les bases existantes du projet en **STIX 2.1, lecture seule** :

```bash
TAXII_BACKEND=project python taxii_server.py
# variables : TAXII_PROJECT_DB_DIR (défaut : dossier de bases hors-OneDrive),
#             TAXII_PROJECT_MAX    (cap d'objets, défaut 1000)
```

Trois collections :
- **XORCISM Vulnerabilities (STIX)** — `XVULNERABILITY.VULNERABILITY` →
  objets STIX `vulnerability` (références `cve` si applicable).
- **XORCISM Incidents (STIX)** — `XINCIDENT.INCIDENT` → objets STIX `incident`.
- **XORCISM Threat Graph (STIX)** — graphe relié multi-bases :
  - **XORCISM / XINCIDENT / XVULNERABILITY** (tables de jonction
    `ASSETVULNERABILITY`, `INCIDENTFORASSET`, `CPEFORASSET`) :
    assets → `identity` (class `system`), CPE → `software`, vuln → `vulnerability`,
    incident → `incident`, plus des SROs : *asset* **has** *vulnerability*,
    *incident* **related-to** *asset*, *asset* **has** *software*.
  - **XTHREAT** : `THREATAGENT` → `threat-actor`, `THREATEVENT` →
    `attack-pattern` (avec `kill_chain_phases`), et les relations explicites de
    la table **`RELATIONSHIP`** (SROs : *threat-actor* **uses** *attack-pattern*,
    *threat-actor* **targets** *asset/identity*…). Ces relations peuvent
    **traverser les domaines** (un threat-actor ciblant un asset déjà présent
    dans le graphe), grâce aux id STIX déterministes communs.

  La table `RELATIONSHIP` (XTHREAT) — `RelationshipGUID`, `source_ref`,
  `target_ref`, `relationship_type`, `description`… — est la source de vérité
  des relations du domaine menace ; il suffit d'y ajouter des lignes (les
  `*_ref` sont des id STIX) pour enrichir le graphe.

Les id STIX sont **déterministes** (UUIDv5 à partir des clés primaires), donc
stables et **corrélables entre collections** (une vulnérabilité a le même id
dans « Vulnerabilities » et dans « Threat Graph »). Lecture seule (POST/DELETE → 403).

> En production : servir derrière **HTTPS** (TLS obligatoire selon la spec).

## Endpoints

| Méthode | Chemin | Ressource |
|---|---|---|
| GET | `/taxii2/` | Discovery |
| GET | `/{api-root}/` | API Root |
| GET | `/{api-root}/status/{status-id}/` | Status |
| GET | `/{api-root}/collections/` | Collections |
| GET | `/{api-root}/collections/{id}/` | Collection |
| GET | `/{api-root}/collections/{id}/manifest/` | Manifest |
| GET / POST | `/{api-root}/collections/{id}/objects/` | Envelope / Status |
| GET / DELETE | `/{api-root}/collections/{id}/objects/{obj-id}/` | Envelope / 200 |
| GET | `/{api-root}/collections/{id}/objects/{obj-id}/versions/` | Versions |

API Root de démonstration : **`api1`**. Deux collections seedées :
`High-Value Indicators` (lecture seule) et `Sandbox (writable)` (lecture/écriture).

## Conformité

- Type de média **`application/taxii+json;version=2.1`** sur `Accept` et `Content-Type`.
- Négociation de contenu (**406**), `Content-Type` d'entrée invalide (**415**).
- Filtres : `match[id]`, `match[type]`, `match[version]` (`first`/`last`/`all`/timestamp),
  `match[spec_version]`, `added_after`.
- Pagination : `limit`, `next` (token opaque) + en-têtes
  `X-TAXII-Date-Added-First` / `X-TAXII-Date-Added-Last`.
- Versionnement STIX (plusieurs versions d'un même objet).
- Ressource d'erreur normalisée ; codes **400 / 401 / 403 / 404 / 406 / 413 / 415**.
- Auth **HTTP Basic** optionnelle + droits `can_read` / `can_write` par collection.

## Exemples (curl — noter `-g` pour les `[ ]`)

```bash
A='application/taxii+json;version=2.1'; B=http://127.0.0.1:5000
CA=91a7b528-80eb-42ed-a74d-c6fbd5a26116

curl -s  -H "Accept: $A" "$B/taxii2/"                          # discovery
curl -s  -H "Accept: $A" "$B/api1/collections/"               # collections
curl -sg -H "Accept: $A" "$B/api1/collections/$CA/objects/"   # objets (version=last)
curl -sg -H "Accept: $A" "$B/api1/collections/$CA/objects/?match[type]=indicator&match[version]=all"
curl -sg -H "Accept: $A" "$B/api1/collections/$CA/manifest/"  # manifest

# Ajout d'objets (collection writable)
CB=52892447-4d7e-4f70-b94d-d7f22742ff63
curl -sg -X POST -H "Accept: $A" -H "Content-Type: $A" "$B/api1/collections/$CB/objects/" \
  -d '{"objects":[{"type":"identity","spec_version":"2.1","id":"identity--...","name":"ACME","identity_class":"organization"}]}'
```

Compatible avec les clients TAXII 2.1 standards (ex. `taxii2-client` /
`cabby`, médaillon, OpenCTI connecteur TAXII…).

---

## Console de gestion web (`manager.py`)

Interface web d'administration : configuration, démarrage/arrêt du serveur
(supervision d'un sous-processus), statistiques (collections / objets / versions /
statuts, ventilation par type), logs en direct, test de découverte.

```bash
pip install flask requests
python manager.py            # http://127.0.0.1:5050
```

À n'exposer que sur **127.0.0.1** (il contrôle un processus). API JSON :
`/api/status`, `/api/config` (GET/POST), `/api/start`, `/api/stop`,
`/api/stats`, `/api/logs`, `/api/discovery`.

## Client avancé (`taxii_client.py`)

```bash
pip install requests
U=http://127.0.0.1:5000
python taxii_client.py --url $U discovery
python taxii_client.py --url $U collections
python taxii_client.py --url $U get --collection <id> --type indicator,malware --all -o dump.json
python taxii_client.py --url $U add --collection <id> --file ../stix/bundle-threat-report.json --poll
python taxii_client.py --url $U manifest --collection <id>
python taxii_client.py --url $U versions --collection <id> --object <stix-id>
python taxii_client.py --url $U delete --collection <id> --object <stix-id>
python taxii_client.py --url $U --user admin --password taxii collections   # avec auth Basic
```

Bibliothèque réutilisable : classe `TAXII2Client` (pagination automatique,
filtres `match[...]`, ajout depuis bundle/enveloppe/objet, suivi de Status).

## Exemples STIX 2.1 (`../stix/`)

Bundles STIX 2.1 valides prêts à être publiés (`add`) :
`bundle-threat-report.json` (identity, threat-actor, malware, attack-pattern,
indicator, campaign, relations, marquage TLP:GREEN), `indicator-malicious-url.json`,
`malware-ransomware.json`, `observed-data-network.json` (SCO : ipv4-addr,
domain-name, network-traffic).
