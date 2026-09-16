# ============================================================
#  File: vanta/core/logger.py
# ============================================================
import time
import threading
from datetime import datetime
from typing import Callable, List, Dict
from .. import theme as T

LEVELS = {"INFO", "OK", "WARN", "ERR", "STEP", "DATA",
          "SNARE", "ATTACK", "DATA"}


class Logger:
    """
    Structured logger with three sinks:
      • CLI (colored output)
      • in-memory records (for GUI replay and JSON export)
      • optional callback list (subscribers get live events)
    """

    COLORS = {
        "INFO":  T.CYAN,
        "OK":    T.GREEN,
        "WARN":  T.AMBER,
        "ERR":   T.RED,
        "STEP":  T.CYAN,
        "DATA":  T.WHITE,
        "SNARE": T.GREEN,
        "ATTACK": T.RED,
    }

    def __init__(self, verbose: bool = True, quiet: bool = False,
                 to_cli: bool = True):
        self.verbose = verbose
        self.quiet = quiet
        self.to_cli = to_cli
        self.records: List[Dict] = []
        self._subs: List[Callable[[Dict], None]] = []
        self._lock = threading.Lock()
        self.started = time.time()

    # ---- subscriptions ------------------------------------------------
    def subscribe(self, cb: Callable[[Dict], None]) -> None:
        with self._lock:
            self._subs.append(cb)

    def unsubscribe(self, cb: Callable[[Dict], None]) -> None:
        with self._lock:
            if cb in self._subs:
                self._subs.remove(cb)

    # ---- emission -----------------------------------------------------
    def _emit(self, level: str, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        rec = {"ts": ts, "level": level, "msg": msg,
               "elapsed": round(time.time() - self.started, 3)}
        with self._lock:
            self.records.append(rec)
            subs = list(self._subs)

        if self.to_cli and self.verbose and not self.quiet:
            color = self.COLORS.get(level, T.WHITE)
            tag = f"{color}[{level:^5}]{T.RST}"
            print(f"{T.DIM}{ts}{T.RST} {tag} {msg}")

        for cb in subs:
            try:
                cb(rec)
            except Exception:
                pass

    # ---- public shortcuts ---------------------------------------------
    def info(self, m):   self._emit("INFO", m)
    def ok(self, m):     self._emit("OK", m)
    def warn(self, m):   self._emit("WARN", m)
    def err(self, m):    self._emit("ERR", m)
    def step(self, m):   self._emit("STEP", m)
    def data(self, m):   self._emit("DATA", m)
    def snare(self, m):  self._emit("SNARE", m)
    def attack(self, m): self._emit("ATTACK", m)

    def dump(self) -> List[Dict]:
        with self._lock:
            return list(self.records)
