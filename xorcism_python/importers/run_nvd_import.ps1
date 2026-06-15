<#
  run_nvd_import.ps1 — Lance l'import NVD CVE (incrémental, 120 derniers jours).
  Appelé chaque heure par la tâche planifiée « XORCISM-NVD-Import ».

  Variables d'environnement (facultatives) :
    XORCISM_DB_DIR   répertoire des bases SQLite (défaut : C:\Users\<you>\XORCISM_databases)
    NVD_API_KEY      clé API NVD (recommandée : quota 50 req/30s au lieu de 5)
    XORCISM_PYTHON   chemin de python.exe (défaut : "python")
#>
$ErrorActionPreference = "Stop"

# Racine du dépôt = deux niveaux au-dessus de ce script (…\xorcism_python\importers\)
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Python   = if ($env:XORCISM_PYTHON) { $env:XORCISM_PYTHON } else { "python" }

if (-not $env:XORCISM_DB_DIR) { $env:XORCISM_DB_DIR = "C:\Users\$env:USERNAME\XORCISM_databases" }
$env:PYTHONPATH = $RepoRoot   # pour « import xorcism_python… »
$env:PYTHONIOENCODING = "utf-8"

$LogDir = Join-Path $RepoRoot "logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$Log = Join-Path $LogDir ("nvd-import-{0}.log" -f (Get-Date -Format "yyyyMMdd"))

$argList = @((Join-Path $RepoRoot "xorcism_python\importers\import_nvd_cve.py"), "--recent-only")
if ($env:NVD_API_KEY) { $argList += @("--api-key", $env:NVD_API_KEY) }

"[{0}] start NVD import (DB_DIR={1})" -f (Get-Date -Format "s"), $env:XORCISM_DB_DIR | Tee-Object -FilePath $Log -Append

& $Python @argList *>&1 | Tee-Object -FilePath $Log -Append
$code = $LASTEXITCODE

"[{0}] end (exit {1})" -f (Get-Date -Format "s"), $code | Tee-Object -FilePath $Log -Append
exit $code
