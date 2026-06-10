"""
manager.py — Interface web de gestion du serveur TAXII 2.1.

Permet, depuis un navigateur, de :
  - configurer le serveur (hôte, port, backend, base SQLite, auth Basic) ;
  - le démarrer / l'arrêter (supervision d'un sous-processus) ;
  - consulter des statistiques (collections, objets, versions, statuts) ;
  - lire les logs en direct ;
  - lancer une requête de découverte de test.

Outil d'administration : à n'exposer que sur 127.0.0.1.

Dépendances : flask, requests.
    python manager.py            # http://127.0.0.1:5050
"""

from __future__ import annotations

import atexit
import json
import os
import sqlite3
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

import requests
from flask import Flask, Response, request

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER_PATH = os.path.join(HERE, "taxii_server.py")
LOG_PATH = os.path.join(HERE, "taxii_server.log")
CONFIG_PATH = os.path.join(HERE, "manager_config.json")

_DB_DIR = r"C:\Users\jerom\XORCISM_databases"
DEFAULT_DB = os.path.join(_DB_DIR, "taxii.db") if os.path.isdir(_DB_DIR) \
    else os.path.join(HERE, "taxii.db")

DEFAULT_CONFIG: Dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 5000,
    "backend": "sqlite",      # sqlite | memory
    "db": DEFAULT_DB,
    "auth": False,
    "password": "taxii",
}

# ── État du processus serveur ────────────────────────────────────────────────────
_proc: Optional[subprocess.Popen] = None
_logf = None
_started_at: float = 0.0


def load_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                return {**DEFAULT_CONFIG, **json.load(fh)}
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg: Dict[str, Any]) -> None:
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)


_config: Dict[str, Any] = load_config()


def is_running() -> bool:
    return _proc is not None and _proc.poll() is None


def server_base() -> str:
    host = "127.0.0.1" if _config["host"] in ("0.0.0.0", "") else _config["host"]
    return f"http://{host}:{_config['port']}"


def server_reachable() -> bool:
    try:
        r = requests.get(server_base() + "/taxii2/",
                         headers={"Accept": "application/taxii+json;version=2.1"}, timeout=2)
        return r.status_code == 200
    except Exception:
        return False


def start_server() -> Dict[str, Any]:
    global _proc, _logf, _started_at
    if is_running():
        return {"ok": False, "error": "Le serveur tourne déjà."}
    env = dict(os.environ)
    env["TAXII_HOST"] = str(_config["host"])
    env["TAXII_PORT"] = str(_config["port"])
    env["TAXII_BACKEND"] = str(_config["backend"])
    env["TAXII_DB"] = str(_config["db"])
    env["TAXII_AUTH"] = "1" if _config["auth"] else "0"
    env["TAXII_PASSWORD"] = str(_config["password"])
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    _logf = open(LOG_PATH, "a", encoding="utf-8")
    _logf.write(f"\n===== démarrage {time.strftime('%Y-%m-%d %H:%M:%S')} "
                f"(port={_config['port']}, backend={_config['backend']}) =====\n")
    _logf.flush()
    _proc = subprocess.Popen([sys.executable, SERVER_PATH], env=env, cwd=HERE,
                             stdout=_logf, stderr=subprocess.STDOUT)
    _started_at = time.time()
    return {"ok": True, "pid": _proc.pid}


def stop_server() -> Dict[str, Any]:
    global _proc, _logf
    if not is_running():
        return {"ok": False, "error": "Le serveur n'est pas démarré."}
    try:
        _proc.terminate()
        try:
            _proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _proc.kill()
    finally:
        if _logf:
            _logf.flush()
            _logf.close()
            _logf = None
        pid = _proc.pid
        _proc = None
    return {"ok": True, "pid": pid}


atexit.register(lambda: stop_server() if is_running() else None)


# ── Statistiques (lecture directe de la base SQLite) ─────────────────────────────
def api_collection_stats() -> Dict[str, Any]:
    """Repli (backend non-sqlite) : liste les collections via l'API du serveur.
    Les comptes d'objets ne sont pas calculés (coûteux) → affichés en '?'."""
    if not server_reachable():
        return {"available": False, "collections": [], "totals": {}}
    try:
        base = server_base()
        hdr = {"Accept": "application/taxii+json;version=2.1"}
        disc = requests.get(base + "/taxii2/", headers=hdr, timeout=3).json()
        roots = disc.get("api_roots") or [base + "/api1/"]
        cols = requests.get(roots[0].rstrip("/") + "/collections/", headers=hdr, timeout=5).json().get("collections", [])
        collections = [{
            "id": c["id"], "title": c["title"],
            "can_read": bool(c.get("can_read")), "can_write": bool(c.get("can_write")),
            "objects": "?", "versions": "?",
        } for c in cols]
        return {"available": True, "source": "api", "collections": collections,
                "by_type": [], "totals": {"collections": len(collections),
                                          "objects": "?", "versions": "?", "statuses": "?"}}
    except Exception as e:
        return {"available": False, "error": str(e), "collections": [], "totals": {}}


def db_stats() -> Dict[str, Any]:
    path = _config["db"]
    if _config["backend"] != "sqlite":
        return api_collection_stats()  # project / memory : via l'API du serveur
    if not os.path.exists(path):
        return {"available": False, "collections": [], "totals": {}}
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        con.row_factory = sqlite3.Row
        cols = con.execute("SELECT id,title,can_read,can_write FROM taxii_collection ORDER BY title").fetchall()
        per = {r["collection_id"]: r["n"] for r in con.execute(
            "SELECT collection_id, COUNT(*) n FROM taxii_object GROUP BY collection_id")}
        per_distinct = {r["collection_id"]: r["n"] for r in con.execute(
            "SELECT collection_id, COUNT(DISTINCT stix_id) n FROM taxii_object GROUP BY collection_id")}
        type_counts = [{"type": r["type"], "n": r["n"]} for r in con.execute(
            "SELECT json_extract(content,'$.type') type, COUNT(*) n FROM taxii_object "
            "GROUP BY type ORDER BY n DESC")]
        total_versions = con.execute("SELECT COUNT(*) FROM taxii_object").fetchone()[0]
        total_objects = con.execute("SELECT COUNT(DISTINCT stix_id) FROM taxii_object").fetchone()[0]
        total_status = con.execute("SELECT COUNT(*) FROM taxii_status").fetchone()[0]
        con.close()
        collections = [{
            "id": c["id"], "title": c["title"],
            "can_read": bool(c["can_read"]), "can_write": bool(c["can_write"]),
            "versions": per.get(c["id"], 0), "objects": per_distinct.get(c["id"], 0),
        } for c in cols]
        return {
            "available": True,
            "collections": collections,
            "by_type": type_counts,
            "totals": {
                "collections": len(collections),
                "objects": total_objects,
                "versions": total_versions,
                "statuses": total_status,
            },
        }
    except Exception as e:
        return {"available": False, "error": str(e), "collections": [], "totals": {}}


def tail(path: str, lines: int) -> str:
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return "".join(fh.readlines()[-lines:])
    except Exception as e:
        return f"(erreur lecture log: {e})"


# ── Application Flask ────────────────────────────────────────────────────────────
app = Flask(__name__)


@app.get("/api/status")
def api_status() -> Response:
    return _json({
        "running": is_running(),
        "pid": _proc.pid if is_running() else None,
        "uptime": int(time.time() - _started_at) if is_running() else 0,
        "reachable": server_reachable() if is_running() else False,
        "base_url": server_base(),
        "config": _config,
    })


@app.get("/api/config")
def api_config() -> Response:
    return _json(_config)


@app.post("/api/config")
def api_save_config() -> Response:
    global _config
    body = request.get_json(force=True, silent=True) or {}
    cfg = dict(_config)
    for k in ("host", "backend", "db", "password"):
        if k in body:
            cfg[k] = body[k]
    if "port" in body:
        cfg["port"] = int(body["port"])
    if "auth" in body:
        cfg["auth"] = bool(body["auth"])
    _config = cfg
    save_config(_config)
    return _json({"ok": True, "config": _config})


@app.post("/api/start")
def api_start() -> Response:
    return _json(start_server())


@app.post("/api/stop")
def api_stop() -> Response:
    return _json(stop_server())


@app.get("/api/stats")
def api_stats() -> Response:
    return _json(db_stats())


@app.get("/api/logs")
def api_logs() -> Response:
    n = min(int(request.args.get("lines", 200)), 2000)
    return _json({"log": tail(LOG_PATH, n)})


@app.get("/api/discovery")
def api_discovery() -> Response:
    try:
        r = requests.get(server_base() + "/taxii2/",
                         headers={"Accept": "application/taxii+json;version=2.1"}, timeout=3)
        return _json({"ok": r.ok, "status": r.status_code, "body": r.json()})
    except Exception as e:
        return _json({"ok": False, "error": str(e)})


@app.get("/")
def index() -> Response:
    return Response(HTML, mimetype="text/html")


def _json(data: Any) -> Response:
    return Response(json.dumps(data), mimetype="application/json")


# ── Interface (HTML + JS, page unique) ───────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TAXII 2.1 — Gestion</title>
<style>
  :root{color-scheme:dark}
  body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#0b0d18;color:#e2e8f0}
  .top{display:flex;align-items:center;gap:12px;padding:12px 20px;background:#13162a;border-bottom:1px solid #2d3250}
  .logo{font-weight:700;color:#7c83fd}
  .dot{width:10px;height:10px;border-radius:50%;display:inline-block}
  .on{background:#22c55e}.off{background:#6b7280}.warn{background:#f59e0b}
  .wrap{max-width:1040px;margin:0 auto;padding:18px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .card{background:#13162a;border:1px solid #2d3250;border-radius:12px;padding:16px;margin-bottom:16px}
  .card h2{font-size:14px;margin:0 0 12px;color:#cbd5e1}
  label{display:block;font-size:12px;color:#94a3b8;margin:8px 0 3px}
  input,select{width:100%;box-sizing:border-box;background:#0f1117;border:1px solid #2d3250;border-radius:6px;padding:8px 10px;color:#e2e8f0;font-size:13px}
  .row{display:flex;gap:10px}.row>div{flex:1}
  button{background:#7c83fd;border:none;border-radius:6px;color:#fff;padding:9px 14px;font-size:13px;cursor:pointer;font-weight:600}
  button.ghost{background:#1e2133;color:#cbd5e1;border:1px solid #2d3250}
  button.danger{background:#7f1d1d}
  button:disabled{opacity:.5;cursor:not-allowed}
  .btns{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}
  table{width:100%;border-collapse:collapse;font-size:12px}
  th,td{padding:5px 8px;border-bottom:1px solid #1e2133;text-align:left}
  th{color:#94a3b8}
  .stat{display:inline-block;background:#0f1117;border:1px solid #2d3250;border-radius:8px;padding:8px 12px;margin:4px 6px 4px 0}
  .stat b{font-size:18px;color:#7c83fd;display:block}
  pre{background:#0f1117;border:1px solid #2d3250;border-radius:8px;padding:10px;max-height:320px;overflow:auto;font-size:11px;line-height:1.4;white-space:pre-wrap}
  .pill{font-size:10px;border-radius:10px;padding:1px 7px}.pr{background:#14532d;color:#86efac}.pw{background:#1e3a5f;color:#bfdbfe}
  .muted{color:#64748b;font-size:11px}
</style></head><body>
<div class="top">
  <span class="logo">◆ TAXII 2.1</span>
  <span>Console de gestion</span>
  <span style="flex:1"></span>
  <span id="dot" class="dot off"></span><span id="state">…</span>
</div>
<div class="wrap">
  <div class="grid">
    <div class="card">
      <h2>Configuration</h2>
      <div class="row"><div><label>Hôte</label><input id="host"></div>
        <div><label>Port</label><input id="port" type="number"></div></div>
      <div class="row">
        <div><label>Backend</label><select id="backend"><option value="sqlite">sqlite (persistant)</option><option value="memory">memory</option></select></div>
        <div><label>Auth Basic</label><select id="auth"><option value="false">désactivée</option><option value="true">activée</option></select></div>
      </div>
      <label>Base SQLite (TAXII_DB)</label><input id="db">
      <label>Mot de passe Basic (admin)</label><input id="password">
      <div class="btns">
        <button onclick="saveCfg()">Enregistrer</button>
        <button id="btnStart" class="ghost" onclick="ctl('start')">▶ Démarrer</button>
        <button id="btnStop" class="danger" onclick="ctl('stop')">■ Arrêter</button>
      </div>
      <div class="muted" id="srvline" style="margin-top:8px"></div>
    </div>
    <div class="card">
      <h2>Statistiques</h2>
      <div id="totals"></div>
      <table style="margin-top:8px"><thead><tr><th>Collection</th><th>Objets</th><th>Versions</th><th>Droits</th></tr></thead>
        <tbody id="cols"></tbody></table>
      <div id="bytype" class="muted" style="margin-top:8px"></div>
    </div>
  </div>
  <div class="card">
    <h2>Logs <button class="ghost" style="padding:3px 8px;font-size:11px" onclick="loadLogs()">Rafraîchir</button>
      <label style="display:inline;margin-left:8px"><input type="checkbox" id="autolog" checked style="width:auto"> auto</label></h2>
    <pre id="logs">(aucun)</pre>
  </div>
</div>
<script>
const $=id=>document.getElementById(id);
async function jget(u){const r=await fetch(u);return r.json();}
async function jpost(u,b){const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});return r.json();}

let cfgLoaded=false;
async function refresh(){
  const s=await jget('/api/status');
  const running=s.running, reach=s.reachable;
  $('dot').className='dot '+(running?(reach?'on':'warn'):'off');
  $('state').textContent = running ? (reach?('en marche · pid '+s.pid+' · '+s.uptime+'s'):'démarrage…') : 'arrêté';
  $('btnStart').disabled=running; $('btnStop').disabled=!running;
  $('srvline').textContent = s.base_url + '/taxii2/';
  if(!cfgLoaded){ const c=s.config;
    $('host').value=c.host;$('port').value=c.port;$('backend').value=c.backend;
    $('db').value=c.db;$('auth').value=String(c.auth);$('password').value=c.password;
    cfgLoaded=true; }
  loadStats();
}
async function loadStats(){
  const d=await jget('/api/stats');
  if(!d.available){ $('totals').innerHTML='<span class="muted">Base indisponible (backend memory ou non créée).</span>'; $('cols').innerHTML=''; $('bytype').textContent=''; return; }
  const t=d.totals;
  $('totals').innerHTML=['collections','objects','versions','statuses'].map(k=>`<span class="stat"><b>${t[k]??0}</b>${k}</span>`).join('');
  $('cols').innerHTML=d.collections.map(c=>`<tr><td>${c.title}<div class="muted">${c.id}</div></td><td>${c.objects}</td><td>${c.versions}</td>
    <td>${c.can_read?'<span class="pill pr">read</span>':''} ${c.can_write?'<span class="pill pw">write</span>':''}</td></tr>`).join('')||'<tr><td colspan=4 class="muted">aucune</td></tr>';
  $('bytype').textContent = (d.by_type||[]).map(x=>x.type+': '+x.n).join('  ·  ');
}
async function loadLogs(){ const d=await jget('/api/logs?lines=300'); $('logs').textContent=d.log||'(vide)'; const p=$('logs'); p.scrollTop=p.scrollHeight; }
async function saveCfg(){
  await jpost('/api/config',{host:$('host').value,port:+$('port').value,backend:$('backend').value,
    db:$('db').value,auth:$('auth').value==='true',password:$('password').value});
  cfgLoaded=false; refresh();
}
async function ctl(a){ await saveCfg(); const r=await jpost('/api/'+a,{}); if(r.error)alert(r.error); setTimeout(refresh,800); setTimeout(loadLogs,1000); }
setInterval(refresh,3000);
setInterval(()=>{ if($('autolog').checked) loadLogs(); },4000);
refresh(); loadLogs();
</script>
</body></html>"""


if __name__ == "__main__":
    port = int(os.getenv("MANAGER_PORT", "5050"))
    print(f"  TAXII manager -> http://127.0.0.1:{port}/")
    app.run(host="127.0.0.1", port=port, debug=False)
