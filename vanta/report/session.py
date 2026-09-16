# ============================================================
#  File: vanta/report/session.py
# ============================================================
import json
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Optional

from ..core.config import Config


@dataclass
class Session:
    started: str = field(default_factory=lambda:
                         datetime.now().isoformat(timespec="seconds"))
    finished: Optional[str] = None
    iface: Optional[str] = None
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    attacker_ip: Optional[str] = None
    attacker_mac: Optional[str] = None
    targets: List[Dict] = field(default_factory=list)
    attacks: List[Dict] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    cookies: List[Dict] = field(default_factory=list)
    requests: List[Dict] = field(default_factory=list)
    logs: List[Dict] = field(default_factory=list)
    duration: float = 0.0

    def finish(self):
        self.finished = datetime.now().isoformat(timespec="seconds")
        if self.duration == 0.0:
            self.duration = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str) -> str:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        return path

    @classmethod
    def from_config(cls, cfg: Config) -> "Session":
        return cls(
            iface=cfg.iface,
            gateway_ip=cfg.gateway_ip,
            gateway_mac=cfg.gateway_mac,
            attacker_ip=cfg.attacker_ip,
            attacker_mac=cfg.attacker_mac,
        )
