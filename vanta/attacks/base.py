# ============================================================
#  File: vanta/attacks/base.py
# ============================================================
import threading
import time
from enum import Enum
from typing import Optional

from ..core.logger import Logger
from ..core.config import Config


class AttackState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


class Attack:
    """
    Base class for all VANTA attacks.

    Subclasses implement:
        setup()  — one-time preparation (resolve MACs, open sockets)
        _run()   — the attack loop (called on a worker thread)
        teardown() — restore network state
    """

    NAME = "attack"

    def __init__(self, cfg: Config, logger: Logger):
        self.cfg = cfg
        self.log = logger
        self.state = AttackState.IDLE
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.started_at: Optional[float] = None
        self.stopped_at: Optional[float] = None
        self.error: Optional[str] = None
        self.stats: dict = {}

    # -------- lifecycle ------------------------------------------------
    def start(self) -> bool:
        if self.state == AttackState.RUNNING:
            self.log.warn(f"{self.NAME} already running.")
            return False
        try:
            self.setup()
        except Exception as e:
            self.state = AttackState.ERROR
            self.error = str(e)
            self.log.err(f"{self.NAME} setup failed: {e}")
            return False

        self._stop.clear()
        self.state = AttackState.RUNNING
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._runner, daemon=True,
                                        name=f"vanta-{self.NAME}")
        self._thread.start()
        self.log.attack(f"▶ {self.NAME} started")
        return True

    def stop(self, timeout: float = 3.0) -> bool:
        if self.state != AttackState.RUNNING:
            return False
        self.state = AttackState.STOPPING
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        try:
            self.teardown()
        except Exception as e:
            self.log.err(f"{self.NAME} teardown error: {e}")
        self.state = AttackState.STOPPED
        self.stopped_at = time.time()
        self.log.attack(f"■ {self.NAME} stopped")
        return True

    def _runner(self):
        try:
            self._run()
        except Exception as e:
            self.error = str(e)
            self.state = AttackState.ERROR
            self.log.err(f"{self.NAME} crashed: {e}")
            try:
                self.teardown()
            except Exception:
                pass

    # -------- to override ----------------------------------------------
    def setup(self):
        pass

    def _run(self):
        raise NotImplementedError

    def teardown(self):
        pass

    # -------- helpers ---------------------------------------------------
    def is_running(self) -> bool:
        return self.state == AttackState.RUNNING

    def uptime(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.stopped_at if self.stopped_at else time.time()
        return round(end - self.started_at, 2)

    def info(self) -> dict:
        return {
            "name":   self.NAME,
            "state":  self.state.value,
            "uptime": self.uptime(),
            "stats":  dict(self.stats),
            "error":  self.error,
        }
