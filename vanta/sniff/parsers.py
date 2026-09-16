# ============================================================
#  File: vanta/sniff/parsers.py
# ============================================================
import base64
import re
from typing import Optional, Dict


HTTP_REQ_RE = re.compile(
    rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/1\.[01]",
    re.M)
HOST_RE      = re.compile(rb"^Host:\s*(\S+)", re.M | re.I)
COOKIE_RE    = re.compile(rb"^Cookie:\s*(.+)$", re.M | re.I)
AUTH_RE      = re.compile(rb"^Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)",
                          re.M | re.I)
FORM_RE      = re.compile(rb"^([A-Za-z_][\w.-]{0,40})=([^&\r\n]{1,200})",
                          re.M)


def parse_http_request(data: bytes) -> Optional[Dict]:
    m = HTTP_REQ_RE.search(data)
    if not m:
        return None
    method = m.group(1).decode()
    path   = m.group(2).decode(errors="ignore")
    host_m = HOST_RE.search(data)
    host   = host_m.group(1).decode(errors="ignore") if host_m else ""

    cookies = {}
    ck = COOKIE_RE.search(data)
    if ck:
        for pair in ck.group(1).decode(errors="ignore").split(";"):
            if "=" in pair:
                k, v = pair.strip().split("=", 1)
                cookies[k] = v[:200]

    basic = None
    am = AUTH_RE.search(data)
    if am:
        basic = parse_basic_auth(am.group(1))

    form = {}
    for fm in FORM_RE.finditer(data):
        form[fm.group(1).decode(errors="ignore")] = \
            fm.group(2).decode(errors="ignore")[:200]

    return {
        "type": "http",
        "method": method,
        "path": path,
        "host": host,
        "url": f"http://{host}{path}" if host else path,
        "cookies": cookies,
        "basic_auth": basic,
        "form": form,
    }


def parse_basic_auth(b64: bytes):
    try:
        raw = base64.b64decode(b64).decode(errors="ignore")
        if ":" in raw:
            u, p = raw.split(":", 1)
            return {"username": u, "password": p}
    except Exception:
        pass
    return None


FTP_RE  = re.compile(rb"^(USER|PASS)\s+(\S+)", re.M)
POP3_RE = re.compile(rb"^(USER|PASS)\s+(\S+)", re.M)
IMAP_RE = re.compile(rb"^[A-Z0-9]+\s+LOGIN\s+(\S+)\s+(\S+)", re.M | re.I)


def parse_ftp(data: bytes):
    m = FTP_RE.findall(data)
    if len(m) >= 2:
        u, p = None, None
        for k, v in m:
            if k == b"USER":
                u = v.decode(errors="ignore")
            elif k == b"PASS":
                p = v.decode(errors="ignore")
        if u and p:
            return {"type": "ftp", "username": u, "password": p}
    return None


def parse_pop3(data: bytes):
    m = POP3_RE.findall(data)
    if len(m) >= 2:
        u = p = None
        for k, v in m:
            if k == b"USER":
                u = v.decode(errors="ignore")
            elif k == b"PASS":
                p = v.decode(errors="ignore")
        if u and p:
            return {"type": "pop3", "username": u, "password": p}
    return None


def parse_imap(data: bytes):
    m = IMAP_RE.search(data)
    if m:
        return {"type": "imap",
                "username": m.group(1).decode(errors="ignore"),
                "password": m.group(2).decode(errors="ignore")}
    return None
