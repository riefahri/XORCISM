# NVD CVE -> XVULNERABILITY SQLite Import Script
# Uses NVD API 2.0 — https://services.nvd.nist.gov/rest/json/cves/2.0
# Rate limit: 5 req/30s without API key. Pass -ApiKey to raise limit to 50 req/30s.

param(
    # Provide your NVD API key via the NVD_API_KEY env var (or -ApiKey). Never hard-code it.
    [string]$ApiKey      = $env:NVD_API_KEY,
    [int]   $StartYear   = 1999,
    [int]   $EndYear     = (Get-Date).Year,
    [int]   $BatchSize   = 2000,
    [switch]$RecentOnly         # last 120 days only
)

# Paths are derived from the script location and (optionally) $env:XORCISM_DB_DIR,
# so the script is portable and contains no machine-specific paths.
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$dbDir      = if ($env:XORCISM_DB_DIR) { $env:XORCISM_DB_DIR } else { Join-Path $scriptRoot "databases" }
$sqlite3    = Join-Path $scriptRoot "tools\sqlite3.exe"
$dbFile     = Join-Path $dbDir      "XVULNERABILITY.db"
$cacheDir   = Join-Path $scriptRoot "nvd_cache"
$logFile    = Join-Path $scriptRoot "nvd_import.log"

New-Item -ItemType Directory -Force $cacheDir | Out-Null

$baseUrl     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
$headers     = @{ "Accept" = "application/json" }
if ($ApiKey) { $headers["apiKey"] = $ApiKey }

# Rate limit: 5 req/30s without key, 50 req/30s with key
$reqWindow   = 30    # seconds
$maxPerWindow = if ($ApiKey) { 50 } else { 5 }
$reqTimes    = [System.Collections.Generic.Queue[datetime]]::new()

function Wait-RateLimit {
    $now = [datetime]::UtcNow
    # Purge entries older than the window
    while ($reqTimes.Count -gt 0 -and ($now - $reqTimes.Peek()).TotalSeconds -gt $reqWindow) {
        $reqTimes.Dequeue() | Out-Null
    }
    if ($reqTimes.Count -ge $maxPerWindow) {
        $oldest = $reqTimes.Peek()
        $wait   = $reqWindow - ($now - $oldest).TotalSeconds + 1
        if ($wait -gt 0) {
            Write-Host "  [rate limit] sleeping $([math]::Round($wait,1))s..." -ForegroundColor DarkGray
            Start-Sleep -Seconds $wait
        }
    }
    $reqTimes.Enqueue([datetime]::UtcNow)
}

function Escape-Sql([string]$s) {
    if ($null -eq $s) { return "NULL" }
    return "'" + $s.Replace("'", "''") + "'"
}

function Get-CvssV3($metrics) {
    $m = $metrics.cvssMetricV31
    if (-not $m) { $m = $metrics.cvssMetricV30 }
    if ($m -and $m.Count -gt 0) { return $m[0] }
    return $null
}

function Get-CvssV2($metrics) {
    $m = $metrics.cvssMetricV2
    if ($m -and $m.Count -gt 0) { return $m[0] }
    return $null
}

function Build-InsertSql($cve, $vulnId, [ref]$cweCounterRef) {
    $id          = $cve.id
    $desc        = ($cve.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1).value
    $published   = $cve.published
    $modified    = $cve.lastModified
    $vulnStatus  = $cve.vulnStatus

    $cvssBase = $null; $cvssImpact = $null; $cvssExploit = $null
    $av = $null; $ac = $null; $auth = $null; $ci = $null; $ii = $null; $ai = $null

    $v3 = Get-CvssV3 $cve.metrics
    if ($v3) {
        $cvssBase    = $v3.cvssData.baseScore
        $cvssImpact  = $v3.impactScore
        $cvssExploit = $v3.exploitabilityScore
        $av          = $v3.cvssData.attackVector
        $ac          = $v3.cvssData.attackComplexity
        $auth        = $v3.cvssData.privilegesRequired
        $ci          = $v3.cvssData.confidentialityImpact
        $ii          = $v3.cvssData.integrityImpact
        $ai          = $v3.cvssData.availabilityImpact
    } else {
        $v2 = Get-CvssV2 $cve.metrics
        if ($v2) {
            $cvssBase    = $v2.cvssData.baseScore
            $cvssImpact  = $v2.impactScore
            $cvssExploit = $v2.exploitabilityScore
            $av          = $v2.cvssData.accessVector
            $ac          = $v2.cvssData.accessComplexity
            $auth        = $v2.cvssData.authentication
            $ci          = $v2.cvssData.confidentialityImpact
            $ii          = $v2.cvssData.integrityImpact
            $ai          = $v2.cvssData.availabilityImpact
        }
    }

    $now = [datetime]::UtcNow.ToString("o")

    $sql = "INSERT INTO VULNERABILITY " +
        "(VulnerabilityID,VULGUID,VULReferential,VULReferentialID,VULDescription," +
        "VULPublishedDate,VULModifiedDate,CVSSBaseScore,CVSSImpactSubscore," +
        "CVSSExploitabilitySubscore,CVSSMetricAccessVector,CVSSMetricAccessComplexity," +
        "CVSSMetricAuthentication,CVSSMetricConfImpact,CVSSMetricIntegImpact," +
        "CVSSMetricAvailImpact,VULName,VULShortName,VULType,CreatedDate," +
        "ValidFromDate,isEncrypted) VALUES (" +
        "$vulnId," +
        "$(Escape-Sql $id)," +
        "$(Escape-Sql $id)," +
        "$(Escape-Sql $id)," +
        "$(Escape-Sql $desc)," +
        "$(Escape-Sql $published)," +
        "$(Escape-Sql $modified)," +
        "$(if($null -ne $cvssBase)   {$cvssBase}   else {'NULL'})," +
        "$(if($null -ne $cvssImpact) {$cvssImpact} else {'NULL'})," +
        "$(if($null -ne $cvssExploit){$cvssExploit}else {'NULL'})," +
        "$(Escape-Sql $av)," +
        "$(Escape-Sql $ac)," +
        "$(Escape-Sql $auth)," +
        "$(Escape-Sql $ci)," +
        "$(Escape-Sql $ii)," +
        "$(Escape-Sql $ai)," +
        "$(Escape-Sql $id)," +
        "$(Escape-Sql $id)," +
        "$(Escape-Sql $vulnStatus)," +
        "$(Escape-Sql $now)," +
        "$(Escape-Sql $published)," +
        "0" +
        ");"

    # CWE links
    $cweSql = ""
    if ($cve.weaknesses) {
        foreach ($w in $cve.weaknesses) {
            foreach ($wd in $w.description) {
                if ($wd.value -match '^CWE-\d+$') {
                    $cweSql += "INSERT INTO VULNERABILITYFORCWE " +
                        "(CWEVulnerabilityID,VulnerabilityID,CWEID,CreatedDate,isEncrypted) VALUES " +
                        "($($cweCounterRef.Value),$vulnId,$(Escape-Sql $wd.value),$(Escape-Sql $now),0);`n"
                    $cweCounterRef.Value++
                }
            }
        }
    }

    return $sql + "`n" + $cweSql
}

# ---- Main ----

Write-Host "=== NVD CVE Import ===" -ForegroundColor Cyan
Write-Host "Database: $dbFile"

# Get current max VulnerabilityID
$maxId = [int](& $sqlite3 $dbFile "SELECT COALESCE(MAX(VulnerabilityID),0) FROM VULNERABILITY;")
Write-Host "Current max VulnerabilityID: $maxId"

# Build URL parameters
$urlParams = "resultsPerPage=$BatchSize"
if ($RecentOnly) {
    $from = (Get-Date).AddDays(-120).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000")
    $to   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000")
    $urlParams += "&pubStartDate=${from}&pubEndDate=${to}"
    Write-Host "Mode: recent 120 days"
} else {
    Write-Host "Mode: full download $StartYear-$EndYear"
}

$totalInserted = 0
$startIndex    = 0
$totalResults  = -1
$vulnId        = $maxId + 1
$cweCounter    = [int](& $sqlite3 $dbFile "SELECT COALESCE(MAX(CWEVulnerabilityID),0) FROM VULNERABILITYFORCWE;") + 1
$sqlBuf        = [System.Text.StringBuilder]::new()
$flushEvery    = 5000  # flush to db every N CVEs

function Flush-Buffer {
    param([System.Text.StringBuilder]$buf, [string]$db, [string]$sqlite)
    if ($buf.Length -eq 0) { return }
    $tmpSql = [System.IO.Path]::GetTempFileName() + ".sql"
    "BEGIN TRANSACTION;" | Out-File $tmpSql -Encoding utf8
    $buf.ToString() | Add-Content $tmpSql -Encoding utf8
    "COMMIT;" | Add-Content $tmpSql -Encoding utf8
    $r = & $sqlite $db ".read `"$tmpSql`"" 2>&1
    Remove-Item $tmpSql -Force
    $buf.Clear() | Out-Null
    if ($r) { Write-Host "  SQL warnings: $($r | Select-Object -First 3)" -ForegroundColor Yellow }
}

$pageNum = 0
do {
    Wait-RateLimit

    $url = $baseUrl + "?" + $urlParams + "&startIndex=" + $startIndex

    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $headers -TimeoutSec 60
    } catch {
        Write-Host "  API error: $_" -ForegroundColor Red
        Start-Sleep -Seconds 10
        continue
    }

    if ($totalResults -lt 0) {
        $totalResults = $resp.totalResults
        Write-Host "Total CVEs to import: $totalResults"
    }

    $pageNum++
    $count = $resp.vulnerabilities.Count
    $pct   = if ($totalResults -gt 0) { [math]::Round(($startIndex / $totalResults) * 100, 1) } else { 0 }
    Write-Host "  Page $pageNum | offset $startIndex/$totalResults ($pct%) | $count CVEs" -ForegroundColor Gray

    foreach ($entry in $resp.vulnerabilities) {
        $insertSql = Build-InsertSql $entry.cve $vulnId ([ref]$cweCounter)
        $sqlBuf.AppendLine($insertSql) | Out-Null
        $vulnId++
        $totalInserted++

        if ($totalInserted % $flushEvery -eq 0) {
            Write-Host "  Flushing $flushEvery rows to DB... (total: $totalInserted)" -ForegroundColor DarkCyan
            Flush-Buffer $sqlBuf $dbFile $sqlite3
        }
    }

    $startIndex += $count

} while ($startIndex -lt $totalResults -and $count -gt 0)

# Final flush
Write-Host "Final flush..." -ForegroundColor DarkCyan
Flush-Buffer $sqlBuf $dbFile $sqlite3

$finalCount = & $sqlite3 $dbFile "SELECT COUNT(*) FROM VULNERABILITY;"
Write-Host "`n=== Done ===" -ForegroundColor Green
Write-Host "CVEs imported this run : $totalInserted"
Write-Host "Total rows in VULNERABILITY: $finalCount"
Write-Host "Database: $dbFile"
