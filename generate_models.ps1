# Generate SQLAlchemy models from SQLite schemas
# Replaces the 1571 auto-generated Entity Framework POCO classes

$sqlite3  = "C:\Users\jerom\OneDrive\Documents\XORCISM\tools\sqlite3.exe"
$dbDir    = "C:\Users\jerom\OneDrive\Documents\XORCISM\databases"
$outDir   = "C:\Users\jerom\OneDrive\Documents\XORCISM\xorcism_python\models"

$typeMap = @{
    "INTEGER" = "Integer"
    "REAL"    = "Float"
    "TEXT"    = "String"
    "BLOB"    = "LargeBinary"
    ""        = "String"
}

$schemas = @("XORCISM","XVULNERABILITY","XATTACK","XMALWARE","XINCIDENT","XTHREAT","XOVAL","XWINDOWS")

foreach ($dbName in $schemas) {
    $dbFile = Join-Path $dbDir "$dbName.db"
    $pyFile = Join-Path $outDir ($dbName.ToLower() + ".py")

    Write-Host "Generating $dbName..." -ForegroundColor Cyan

    # Get all tables
    $tables = & $sqlite3 $dbFile ".mode json" "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;" 2>&1 |
              ConvertFrom-Json | ForEach-Object { $_.name }

    $lines = @()
    $lines += '"""'
    $lines += "SQLAlchemy models for $dbName database"
    $lines += "Auto-generated from SQLite schema - replaces XORCISMModel/$dbName C# POCO classes"
    $lines += '"""'
    $lines += "from sqlalchemy import Column, Integer, Float, String, Text, LargeBinary, Boolean"
    $lines += "from .base import Base"
    $lines += ""

    foreach ($tbl in $tables) {
        # Get columns via PRAGMA
        $cols = & $sqlite3 $dbFile ".mode json" "PRAGMA table_info(`"$tbl`");" 2>&1 | ConvertFrom-Json

        $lines += ""
        $lines += "class $tbl(Base):"
        $lines += "    __tablename__ = '$tbl'"
        $lines += "    __bind_key__  = '$dbName'"
        $lines += ""

        foreach ($col in $cols) {
            $colName = $col.name
            $rawType = $col.type.ToUpper()

            # Map type
            $saType = "String"
            foreach ($k in $typeMap.Keys) {
                if ($rawType -eq $k -or $rawType.StartsWith($k)) {
                    $saType = $typeMap[$k]; break
                }
            }
            # TEXT columns: use Text for potentially long content
            if ($saType -eq "String") { $saType = "Text" }

            # Primary key detection: first INTEGER NOT NULL column ending in ID
            $pk = if ($col.pk -eq 1) { ", primary_key=True" } else { "" }
            $nullable = if ($col.notnull -eq 1 -and $col.pk -ne 1) { ", nullable=False" } else { "" }

            $lines += "    $colName = Column($saType$pk$nullable)"
        }

        $lines += ""
        $lines += "    def __repr__(self):"
        # Find a good display field
        $displayCol = ($cols | Where-Object { $_.name -match "Name|ID$" } | Select-Object -First 1).name
        if (-not $displayCol) { $displayCol = $cols[0].name }
        $lines += "        return f'<$tbl {self.$displayCol}>'"
    }

    $lines -join "`n" | Out-File $pyFile -Encoding utf8
    Write-Host "  -> $($tables.Count) tables written to $(Split-Path $pyFile -Leaf)" -ForegroundColor Green
}

# Generate __init__.py
$initLines = @('"""XORCISM SQLAlchemy Models"""')
foreach ($db in $schemas) {
    $initLines += "from . import $($db.ToLower())"
}
$initLines += ""
$initLines += "__all__ = [" + ($schemas | ForEach-Object { "'$($_.ToLower())'" } | Join-String -Separator ", ") + "]"
$initLines -join "`n" | Out-File (Join-Path $outDir "__init__.py") -Encoding utf8

Write-Host "`nDone. Models in $outDir" -ForegroundColor White
