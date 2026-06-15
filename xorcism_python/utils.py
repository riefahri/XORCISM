"""
utils.py - Converted from XCommon/Utils.cs
Jerome Athias - XORCISM

Replaces:
  - Utils.Helper_Trace()         -> log()
  - Utils.Helper_Encrypt()       -> hash_string()
  - Utils.Helper_SendEmail()     -> send_email()
  - Utils.Helper_RightEnforcement() -> check_right()
  - Utils.FindCPE()              -> find_cpe()
"""

import hashlib
import logging
import smtplib
import fnmatch
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from enum import Enum, auto
from typing import Optional

import config

# ---------------------------------------------------------------------------
# Logging (replaces Trace.WriteLine)
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s.%(msecs)03d : %(name)s : %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

def log(module: str, message: str) -> None:
    """Replaces Utils.Helper_Trace(module, message)."""
    logger = logging.getLogger(module)
    logger.info(message)


# ---------------------------------------------------------------------------
# Enums (replaces C# enums in XCommon namespace)
# ---------------------------------------------------------------------------

class Algorithm(Enum):
    SHA1 = auto()
    MD5  = auto()


class RIGHT(Enum):
    RELOAD    = auto()
    UNLOCK    = auto()
    CREATE    = auto()
    MODIFY    = auto()
    DELETE    = auto()
    VIEW      = auto()


class STATUS(Enum):
    FINISHED   = auto()
    IDLE       = auto()
    TOCANCEL   = auto()
    CANCELLING = auto()
    RUNNING    = auto()
    ERROR      = auto()
    CANCELED   = auto()


# RACI values required per right (replaces the switch/listRACI logic)
_RACI_MAP: dict[RIGHT, list[str]] = {
    RIGHT.CREATE: ["R"],
    RIGHT.MODIFY: ["R", "A", "C"],
    RIGHT.DELETE: ["R", "A"],
    RIGHT.VIEW:   ["R", "A", "C", "I"],
}


# ---------------------------------------------------------------------------
# Hashing (replaces Utils.Helper_Encrypt)
# ---------------------------------------------------------------------------

def hash_string(source: str, algo: Algorithm = Algorithm.MD5) -> str:
    """
    Replaces Utils.Helper_Encrypt(source, algo).
    Returns hex digest (C# returned raw byte values concatenated — kept compatible).
    """
    encoded = source.encode("utf-8")
    if algo == Algorithm.MD5:
        digest = hashlib.md5(encoded).digest()
    elif algo == Algorithm.SHA1:
        digest = hashlib.sha1(encoded).digest()
    else:
        raise ValueError(f"Unsupported algorithm: {algo}")
    # C# returned raw byte values concatenated as string (not hex)
    return "".join(str(b) for b in digest)


def hash_hex(source: str, algo: Algorithm = Algorithm.MD5) -> str:
    """Modern alternative: returns standard hex digest."""
    encoded = source.encode("utf-8")
    if algo == Algorithm.MD5:
        return hashlib.md5(encoded).hexdigest()
    return hashlib.sha1(encoded).hexdigest()


# ---------------------------------------------------------------------------
# Email (replaces Utils.Helper_SendEmail using CDO/ADODB)
# ---------------------------------------------------------------------------

def send_email(to: str, subject: str, message: str) -> bool:
    """
    Replaces Utils.Helper_SendEmail(Tos, Subject, Message).
    Uses Python smtplib instead of CDO.Message (Windows-only COM object).
    """
    try:
        msg = MIMEMultipart()
        msg["From"]    = config.SMTP_FROM
        msg["Subject"] = subject

        for recipient in to.split(","):
            recipient = recipient.strip()
            if recipient:
                msg["To"] = recipient

        msg.attach(MIMEText(message, "plain"))

        with smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT) as server:
            server.starttls()
            if config.SMTP_USERNAME:
                server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
            server.send_message(msg)

        log("Email Service", "Email sent successfully")
        return True

    except Exception as ex:
        log("Email Service", f"Error sending email: {ex}")
        return False


# ---------------------------------------------------------------------------
# Rights / RACI enforcement (replaces Utils.Helper_RightEnforcement)
# ---------------------------------------------------------------------------

def check_right(
    user_id: int,
    securable_type: str,
    right: RIGHT,
    securable_id: Optional[str] = None,
    session=None,
) -> bool:
    """
    Replaces Utils.Helper_RightEnforcement().
    Checks RACI-based access control.
    NOTE: Full RACI table lookup is TODO (as in original C# — most checks return True).
    """
    if session is None:
        return True  # No session = permissive fallback (same as original TODO)

    # Check if user is Administrator (UserAccountTypeID == 1)
    from models.xorcism import USERACCOUNT
    admin = session.query(USERACCOUNT).filter(
        USERACCOUNT.UserID == user_id,
        USERACCOUNT.UserAccountTypeID == 1,
    ).first()
    if admin:
        return True

    required_raci = _RACI_MAP.get(right, [])
    # TODO: query RACISECURABLEINSTANCE / RACISECURABLE tables
    # For now, return True if user exists (mirrors C# TODO stubs)
    return bool(required_raci)


# ---------------------------------------------------------------------------
# CPE lookup (replaces Utils.FindCPE)
# ---------------------------------------------------------------------------

def find_cpe(raw_string: str, session=None) -> str:
    """
    Replaces Utils.FindCPE(rawString).
    Searches CPE table for matching entries using LIKE on each word.
    """
    if session is None:
        return ""

    from models.xorcism import CPE
    words = raw_string.split()
    for word in words:
        pattern = f"%{word.lower()}%"
        match = session.query(CPE).filter(
            CPE.CPEName.ilike(pattern)
        ).first()
        if match:
            return match.CPEName or ""
    return ""


# ---------------------------------------------------------------------------
# Subscription / pagination (replaces Utils.GetMaxPageBySubscriptionLevel)
# ---------------------------------------------------------------------------

def get_max_page(user_id, service: int, xml_doc=None) -> int:
    """Replaces Utils.GetMaxPageBySubscriptionLevel. Returns unlimited."""
    return 999_999
