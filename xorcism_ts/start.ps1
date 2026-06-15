# start.ps1 — Build and start the XORCISM TypeScript server
# Usage: .\start.ps1 [--dev]

param([switch]$Dev)

$NodeDir = "C:\Users\jerom\OneDrive\Documents\XORCISM\tools\nodejs"
$env:PATH = "$NodeDir;" + $env:PATH

$root = $PSScriptRoot
Set-Location $root

function Run($cmd) {
    Write-Host "  > $cmd" -ForegroundColor DarkGray
    Invoke-Expression $cmd
    if ($LASTEXITCODE -ne 0) { throw "Command failed: $cmd" }
}

Write-Host "`n  XORCISM TypeScript Server" -ForegroundColor Cyan

# Install deps if needed
if (-not (Test-Path "node_modules")) {
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    Run "npm install"
}

# Build
Write-Host "Building..." -ForegroundColor Yellow
Run "npx tsc -p tsconfig.server.json"
Run "node esbuild.config.js"

# Start
Write-Host "`n  Starting server..." -ForegroundColor Green
Start-Process "http://localhost:9292"
Run "node dist/server/index.js"
