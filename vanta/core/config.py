# ============================================================
#  File: vanta/core/config.py
# ============================================================
import os
from dataclasses import dataclass, field
from typing import Optional
from .errors import ConfigError


@dataclass
class Config:
    iface: Optional[str] = None
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    attacker_ip: Optional[str] = None
    attacker_mac: Optional[str] = None
    target_ip: Optional[str] = None
    target_mac: Optional[str] = None
    session_dir: str = ".vanta_sessions"
    packet_rate: float = 2.0
    dry_run: bool = False
    verbose: bool = False
    dns_rules: dict = field(default_factory=dict)
    dhcp_pool: str = "10.66.0.100,10.66.0.200"
    dhcp_netmask: str = "255.255.255.0"
    dhcp_router: Optional[str] = None
    dhcp_dns: Optional[str] = None
    # --- auto-serve (DNS spoof landing page) ---
    auto_serve: bool = False
    serve_port: int = 80
    serve_bind: str = "0.0.0.0"
    serve_root: str = ""
    serve_page: str = ""        # custom HTML, overrides default

    def require_interface(self):
        if not self.iface:
            raise ConfigError("No interface selected. Use 'set iface <name>'.")
        return self.iface

    def require_gateway(self):
        if not self.gateway_ip:
            raise ConfigError("No gateway detected. Use 'set gateway <ip>'.")
        return self.gateway_ip

    def require_target(self):
        if not self.target_ip:
            raise ConfigError("No target selected. Use 'set target <ip>'.")
        return self.target_ip


_singleton: Optional[Config] = None


def get_config() -> Config:
    global _singleton
    if _singleton is None:
        _singleton = Config()
        os.makedirs(_singleton.session_dir, exist_ok=True)
    return _singleton


def set_config(cfg: Config) -> None:
    global _singleton
    _singleton = cfg
