# XORCISM Database Creation Script
# Converts T-SQL schemas to SQLite and creates .db files
# Jerome Athias - XORCISM project

$sqlite3 = "C:\Users\jerom\OneDrive\Documents\XORCISM\tools\sqlite3.exe"
$repoModels = "C:\Users\jerom\OneDrive\Documents\XORCISM\XORCISM_repo\MODELS"
$dbDir = "C:\Users\jerom\OneDrive\Documents\XORCISM\databases"

New-Item -ItemType Directory -Force $dbDir | Out-Null

function Convert-MssqlToSqlite {
    param([string]$sql)

    # 1. Remove SQL Server directives
    $sql = $sql -replace '(?m)^USE\s+\[.*?\]\s*$', ''
    $sql = $sql -replace '(?m)^GO\s*$', ';'
    $sql = $sql -replace '(?m)^SET\s+\w+\s+\w+\s*$', ''

    # 2. Remove schema prefix
    $sql = $sql -replace '\[dbo\]\.', ''

    # 3. Remove storage clauses (must happen before bracket→quote conversion)
    $sql = $sql -replace '(?i)\s*TEXTIMAGE_ON\s+\[PRIMARY\]', ''
    $sql = $sql -replace '(?i)\s*ON\s+\[PRIMARY\]', ''
    $sql = $sql -replace '(?i)WITH\s*\([^)]+\)', ''

    # 4. Type conversions (while types still have [brackets])
    # IDENTITY -> will become INTEGER PRIMARY KEY later; for now mark it
    $sql = $sql -replace '(?i)\[int\]\s+IDENTITY\(1,1\)\s+NOT NULL', '__SERIAL__ NOT NULL'
    $sql = $sql -replace '(?i)\[int\]\s+IDENTITY\(1,1\)\s+NULL', '__SERIAL__ NULL'
    $sql = $sql -replace '(?i)\[int\]\s+IDENTITY\(1,1\)', '__SERIAL__'

    # Text types
    $sql = $sql -replace '(?i)\[nvarchar\]\s*\(\s*max\s*\)', 'TEXT'
    $sql = $sql -replace '(?i)\[nvarchar\]\s*\(\d+\)', 'TEXT'
    $sql = $sql -replace '(?i)\[varchar\]\s*\(\s*max\s*\)', 'TEXT'
    $sql = $sql -replace '(?i)\[varchar\]\s*\(\d+\)', 'TEXT'
    $sql = $sql -replace '(?i)\[nchar\]\s*\(\d+\)', 'TEXT'
    $sql = $sql -replace '(?i)\[char\]\s*\(\d+\)', 'TEXT'
    $sql = $sql -replace '(?i)\[ntext\]', 'TEXT'
    $sql = $sql -replace '(?i)\[text\]', 'TEXT'
    $sql = $sql -replace '(?i)\[xml\]', 'TEXT'
    $sql = $sql -replace '(?i)\[uniqueidentifier\]', 'TEXT'
    $sql = $sql -replace '(?i)\[sysname\]', 'TEXT'

    # Date types
    $sql = $sql -replace '(?i)\[datetimeoffset\]\s*\(\d+\)', 'TEXT'
    $sql = $sql -replace '(?i)\[datetimeoffset\]', 'TEXT'
    $sql = $sql -replace '(?i)\[datetime2\]\s*\(\d+\)', 'TEXT'
    $sql = $sql -replace '(?i)\[datetime2\]', 'TEXT'
    $sql = $sql -replace '(?i)\[datetime\]', 'TEXT'
    $sql = $sql -replace '(?i)\[smalldatetime\]', 'TEXT'
    $sql = $sql -replace '(?i)\[date\]', 'TEXT'
    $sql = $sql -replace '(?i)\[time\]\s*\(\d+\)', 'TEXT'
    $sql = $sql -replace '(?i)\[time\]', 'TEXT'

    # Numeric types
    $sql = $sql -replace '(?i)\[bigint\]', 'INTEGER'
    $sql = $sql -replace '(?i)\[smallint\]', 'INTEGER'
    $sql = $sql -replace '(?i)\[tinyint\]', 'INTEGER'
    $sql = $sql -replace '(?i)\[int\]', 'INTEGER'
    $sql = $sql -replace '(?i)\[bit\]', 'INTEGER'
    $sql = $sql -replace '(?i)\[float\]', 'REAL'
    $sql = $sql -replace '(?i)\[real\]', 'REAL'
    $sql = $sql -replace '(?i)\[decimal\]\s*\(\d+,\s*\d+\)', 'REAL'
    $sql = $sql -replace '(?i)\[numeric\]\s*\(\d+,\s*\d+\)', 'REAL'
    $sql = $sql -replace '(?i)\[money\]', 'REAL'
    $sql = $sql -replace '(?i)\[smallmoney\]', 'REAL'

    # Binary types
    $sql = $sql -replace '(?i)\[image\]', 'BLOB'
    $sql = $sql -replace '(?i)\[varbinary\]\s*\(\s*max\s*\)', 'BLOB'
    $sql = $sql -replace '(?i)\[varbinary\]\s*\(\d+\)', 'BLOB'
    $sql = $sql -replace '(?i)\[binary\]\s*\(\d+\)', 'BLOB'
    $sql = $sql -replace '(?i)\[timestamp\]', 'BLOB'

    # 5. Convert remaining [brackets] to "quoted identifiers" for SQLite
    $sql = $sql -replace '\[(\w+)\]', '"$1"'

    # 6. Restore IDENTITY as INTEGER (column def, without quoting)
    $sql = $sql -replace '__SERIAL__', 'INTEGER'

    # 7. Remove clustered/nonclustered keywords
    $sql = $sql -replace '(?i)PRIMARY\s+KEY\s+(CLUSTERED|NONCLUSTERED)', 'PRIMARY KEY'
    $sql = $sql -replace '(?i)UNIQUE\s+(CLUSTERED|NONCLUSTERED)', 'UNIQUE'

    # 8. Remove ASC in constraint lists
    $sql = $sql -replace '(?i)\b(\w+)"\s+ASC\b', '"$1"'

    # 9. Remove COLLATE clauses
    $sql = $sql -replace '(?i)COLLATE\s+\w+', ''

    # 10. Clean up multiple blank lines
    $sql = $sql -replace '(\r?\n){3,}', "`n`n"

    return $sql.Trim()
}

$schemas = @(
    @{ Name = "XORCISM";        File = "XORCISMModel\XORCISM_Tables_Create.sql" }
    @{ Name = "XVULNERABILITY"; File = "XVULNERABILITY\XVULNERABILITY_Tables_Create.sql" }
    @{ Name = "XATTACK";        File = "XATTACK\XATTACK_Tables_Create.sql" }
    @{ Name = "XMALWARE";       File = "XMALWARE\XMALWARE_Tables_Create.sql" }
    @{ Name = "XINCIDENT";      File = "XINCIDENT\XINCIDENT_Tables_Create.sql" }
    @{ Name = "XTHREAT";        File = "XTHREAT\XTHREAT_Tables_Create.sql" }
    @{ Name = "XOVAL";          File = "XOVAL\XOVAL_Tables_Create.sql" }
    @{ Name = "XWINDOWS";       File = "XWINDOWS\XWINDOWS_Tables_Create.sql" }
)

foreach ($schema in $schemas) {
    $sqlFile  = Join-Path $repoModels $schema.File
    $dbFile   = Join-Path $dbDir "$($schema.Name).db"
    $convFile = Join-Path $dbDir "$($schema.Name)_sqlite.sql"

    Write-Host "Processing $($schema.Name)..." -ForegroundColor Cyan

    $raw = Get-Content $sqlFile -Raw -Encoding UTF8
    $converted = Convert-MssqlToSqlite -sql $raw

    $final = "BEGIN TRANSACTION;`n`n$converted`n`nCOMMIT;"
    $final | Out-File -FilePath $convFile -Encoding utf8

    if (Test-Path $dbFile) { Remove-Item $dbFile -Force }

    $result = & $sqlite3 $dbFile ".read `"$convFile`"" 2>&1
    if ($LASTEXITCODE -eq 0) {
        $size  = (Get-Item $dbFile).Length
        $count = (& $sqlite3 $dbFile "SELECT count(*) FROM sqlite_master WHERE type='table';") -join ''
        Write-Host "  OK -> $($schema.Name).db  ($size bytes, $count tables)" -ForegroundColor Green
    } else {
        Write-Host "  ERRORS (first 15):" -ForegroundColor Yellow
        $result | Select-Object -First 15 | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
    }
}

Write-Host "`nDone. Databases in: $dbDir" -ForegroundColor White
