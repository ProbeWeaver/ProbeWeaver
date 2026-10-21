"""Read explicit product/version identifiers from recognized banner protocols. Missing evidence returns no version."""

import re
from typing import Optional

_SSH = re.compile(rb"^SSH-\d+\.\d+-(\S+)")
_HTTP_SERVER = re.compile(rb"(?im)^Server:\s*([^\r\n]+)")
_HTTP_STATUS = re.compile(rb"^HTTP/\d\.\d\s+\d{3}\s+([^\r\n]+)")
_FTP = re.compile(rb"^220[^\r\n]*")
_SMTP_ID = re.compile(rb"(?i)(Postfix|Sendmail|Exim|OpenSMTPD|Dovecot)")
_SMTP_GREET = re.compile(rb"^220\s+([^\r\n]+)")
_POP3 = re.compile(rb"^\+OK\s*([^\r\n]*)")
_IMAP = re.compile(rb"^\*\s+OK\s*([^\r\n]*)")
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{8,}")

def _ssh(resp: bytes) -> Optional[str]:
    m = _SSH.search(resp)
    return m.group(1).decode("latin-1") if m else None

def _http(resp: bytes) -> Optional[str]:
    m = _HTTP_SERVER.search(resp)
    if m:
        return m.group(1).decode("latin-1").strip()
    m = _HTTP_STATUS.search(resp)
    return m.group(1).decode("latin-1").strip() if m else None

def _ftp(resp: bytes) -> Optional[str]:
    m = _FTP.search(resp)
    return m.group(0).decode("latin-1").strip()[3:].strip() if m else None

def _smtp(resp: bytes) -> Optional[str]:
    m = _SMTP_ID.search(resp)
    if m:
        return m.group(1).decode("latin-1")
    m = _SMTP_GREET.search(resp)
    return m.group(1).decode("latin-1").strip() if m else None

def _pop3(resp: bytes) -> Optional[str]:
    m = _POP3.search(resp)
    return m.group(1).decode("latin-1").strip() if m else None

def _imap(resp: bytes) -> Optional[str]:
    m = _IMAP.search(resp)
    return m.group(1).decode("latin-1").strip() if m else None

def _snmp(resp: bytes) -> Optional[str]:
    
    runs = _PRINTABLE_RUN.findall(resp)
    if not runs:
        return None
    return max(runs, key=len).decode("latin-1").strip()[:80]

VERSION_EXTRACTORS = {
    "ssh": _ssh,
    "http": _http,
    "ftp": _ftp,
    "smtp": _smtp,
    "pop3": _pop3,
    "imapv4": _imap,
    "snmp": _snmp,
}

def extract_version(cluster: str, resp: bytes) -> Optional[str]:
    """Extract explicit version evidence from supported banner services."""
    fn = VERSION_EXTRACTORS.get(cluster)
    if fn is None or not resp:
        return None
    try:
        return fn(resp)
    except Exception:  # noqa: BLE001
        return None
