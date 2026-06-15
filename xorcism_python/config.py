"""
XORCISM Configuration
Converted from App.config / ConfigurationManager
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Bases SQLite HORS de OneDrive (OneDrive corrompt les WAL / fige les lectures
# sous les handles ouverts). Surchargeable via la variable XORCISM_DB_DIR.
DB_DIR   = os.getenv("XORCISM_DB_DIR", r"C:\Users\jerom\XORCISM_databases")

# SQLite database URLs (SQLAlchemy format)
DATABASES = {
    "XORCISM":        f"sqlite:///{os.path.join(DB_DIR, 'XORCISM.db')}",
    "XVULNERABILITY": f"sqlite:///{os.path.join(DB_DIR, 'XVULNERABILITY.db')}",
    "XATTACK":        f"sqlite:///{os.path.join(DB_DIR, 'XATTACK.db')}",
    "XMALWARE":       f"sqlite:///{os.path.join(DB_DIR, 'XMALWARE.db')}",
    "XINCIDENT":      f"sqlite:///{os.path.join(DB_DIR, 'XINCIDENT.db')}",
    "XTHREAT":        f"sqlite:///{os.path.join(DB_DIR, 'XTHREAT.db')}",
    "XOVAL":          f"sqlite:///{os.path.join(DB_DIR, 'XOVAL.db')}",
    "XWINDOWS":       f"sqlite:///{os.path.join(DB_DIR, 'XWINDOWS.db')}",
    "XCOMPLIANCE":    f"sqlite:///{os.path.join(DB_DIR, 'XCOMPLIANCE.db')}",
    "XTICKET":        f"sqlite:///{os.path.join(DB_DIR, 'XTICKET.db')}",
    "XID":            f"sqlite:///{os.path.join(DB_DIR, 'XID.db')}",
}

# Email (was in App.config)
SMTP_SERVER   = os.getenv("SMTP_SERVER",   "smtp.example.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = "contact@hackenaton.org"

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
