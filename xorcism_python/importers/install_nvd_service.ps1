<#
  install_nvd_service.ps1 — Installe l'exécution HORAIRE de l'import NVD CVE.

  Sur Windows, une « tâche planifiée » est la façon idiomatique de lancer un
  script toutes les heures (un vrai service tournerait en boucle ; voir la note
  NSSM en bas). Ce script enregistre la tâche « XORCISM-NVD-Import ».

  À LANCER DANS UN POWERSHELL ADMINISTRATEUR :
      powershell -ExecutionPolicy Bypass -File install_nvd_service.ps1
  Options :
      -ApiKey <clé NVD>      passe la clé API NVD (sinon variable NVD_API_KEY)
      -DbDir  <chemin>       répertoire des bases (sinon XORCISM_DB_DIR / défaut)
      -RunAsUser <DOMAIN\me> exécuter sous ce compte (défaut : SYSTEM)
      -Uninstall             supprime la tâche
#>
param(
  [string]$ApiKey,
  [string]$DbDir,
  [string]$RunAsUser,
  [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
$TaskName = "XORCISM-NVD-Import"
$Runner = Join-Path $PSScriptRoot "run_nvd_import.ps1"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Lancez ce script dans un PowerShell ADMINISTRATEUR."
}

if ($Uninstall) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "Tâche '$TaskName' supprimée." -ForegroundColor Green
  return
}

if (-not (Test-Path $Runner)) { Write-Error "Introuvable : $Runner" }

# L'action passe l'env (clé API / DB_DIR) au runner via des variables process.
$envPrefix = ""
if ($ApiKey) { $envPrefix += "`$env:NVD_API_KEY='$ApiKey'; " }
if ($DbDir)  { $envPrefix += "`$env:XORCISM_DB_DIR='$DbDir'; " }
$command = "$envPrefix& '$Runner'"

$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$command`""

# Toutes les heures, indéfiniment, en démarrant à la prochaine heure ronde.
$start   = (Get-Date).Date.AddHours((Get-Date).Hour + 1)
$trigger = New-ScheduledTaskTrigger -Once -At $start `
  -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration ([TimeSpan]::MaxValue)

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
  -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Minutes 50) `
  -MultipleInstances IgnoreNew

if ($RunAsUser) {
  $principal = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType S4U -RunLevel Highest
} else {
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
}

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
  -Settings $settings -Principal $principal -Force `
  -Description "Import horaire des CVE NVD (120 derniers jours) dans XVULNERABILITY." | Out-Null

Write-Host "Tâche '$TaskName' installée (horaire, 1re exécution à $start)." -ForegroundColor Green
Write-Host "Lancer maintenant : Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "Journaux : <repo>\logs\nvd-import-AAAAMMJJ.log"
Write-Host ""
Write-Host "Vrai service Windows (optionnel, via NSSM) :" -ForegroundColor Cyan
Write-Host "  nssm install XORCISM-NVD powershell -NoProfile -ExecutionPolicy Bypass -File `"$Runner`""
Write-Host "  (ajoutez votre propre boucle/sleep 3600 si vous voulez un service permanent)"
