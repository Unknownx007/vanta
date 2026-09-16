# ============================================================
#  File: vanta/core/iface.py
# ============================================================
import os
import re
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from .errors import InterfaceError, NotRootError


@dataclass
class Interface:
    name: str
    mac: Optional[str] = None
    ipv4: Optional[str] = None
    netmask: Optional[str] = None
    broadcast: Optional[str] = None
    is_up: bool = False
    is_wireless: bool = False
    mtu: Optional[int] = None


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def require_root():
    if not is_root():
        raise NotRootError("This operation requires root. Re-run with sudo.")


def _run(cmd: List[str]) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                       text=True)
    except Exception:
        return ""


def list_interfaces() -> List[str]:
    """Names of all interfaces except lo."""
    base = "/sys/class/net"
    if not os.path.isdir(base):
        return []
    return sorted(n for n in os.listdir(base) if n != "lo")


def get_interface(name: str) -> Interface:
    if name not in list_interfaces():
        raise InterfaceError(f"Interface '{name}' not found.")

    iface = Interface(name=name)

    # MAC
    mac_path = f"/sys/class/net/{name}/address"
    if os.path.isfile(mac_path):
        with open(mac_path) as f:
            iface.mac = f.read().strip()

    # MTU
    mtu_path = f"/sys/class/net/{name}/mtu"
    if os.path.isfile(mtu_path):
        with open(mtu_path) as f:
            try:
                iface.mtu = int(f.read().strip())
            except ValueError:
                pass

    # Wireless check
    iface.is_wireless = os.path.isdir(f"/sys/class/net/{name}/wireless")

    # IP / netmask / broadcast
    out = _run(["ip", "-4", "addr", "show", name])
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out)
    if m:
        iface.ipv4 = m.group(1)
        prefix = int(m.group(2))
        iface.netmask = _prefix_to_netmask(prefix)
        iface.broadcast = _broadcast(iface.ipv4, prefix)

    # up/down
    flags = _run(["ip", "link", "show", name])
    iface.is_up = "state UP" in flags or "UP" in flags.split(":")[2] if ":" in flags else False
    iface.is_up = (iface.ipv4 is not None)

    return iface


def _prefix_to_netmask(prefix: int) -> str:
    bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return ".".join(str((bits >> (8 * i)) & 0xFF) for i in (3, 2, 1, 0))


def _broadcast(ip: str, prefix: int) -> str:
    ip_int = sum(int(o) << (8 * (3 - i)) for i, o in enumerate(ip.split(".")))
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    bcast = (ip_int & mask) | (~mask & 0xFFFFFFFF)
    return ".".join(str((bcast >> (8 * i)) & 0xFF) for i in (3, 2, 1, 0))


def get_default_gateway() -> Optional[str]:
    out = _run(["ip", "route", "show", "default"])
    m = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def get_interface_for_ip(ip: str) -> Optional[str]:
    out = _run(["ip", "route", "get", ip])
    m = re.search(r"dev\s+(\S+)", out)
    return m.group(1) if m else None


def enable_ip_forwarding() -> bool:
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        return True
    except Exception:
        return False


def disable_ip_forwarding() -> bool:
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
        return True
    except Exception:
        return False


def set_ip_forwarding(enabled: bool) -> None:
    if enabled:
        enable_ip_forwarding()
    else:
        disable_ip_forwarding()
