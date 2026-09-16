# ============================================================
#  File: vanta/core/wireless.py
#  Wireless helpers — in-place monitor mode (universal).
# ============================================================
import os
import re
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional

from .errors import WirelessError


# ------------------------------------------------------------------
def _run(cmd: List[str], timeout: int = 10) -> str:
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    except Exception:
        return ""


# ------------------------------------------------------------------
@dataclass
class CardCapabilities:
    iface:             str
    driver:            Optional[str] = None
    supports_monitor:  bool = False
    supports_injection: bool = False
    inject_mode:       str = "standard"   # "standard" | "iwlwifi"
    reason:            str = ""


# ------------------------------------------------------------------
def is_wireless(iface: str) -> bool:
    return os.path.isdir(f"/sys/class/net/{iface}/wireless")


def list_wireless() -> List[str]:
    return sorted(i for i in os.listdir("/sys/class/net") if is_wireless(i))


def driver_of(iface: str) -> Optional[str]:
    try:
        link = f"/sys/class/net/{iface}/device/driver"
        if os.path.islink(link):
            return os.path.basename(os.readlink(link))
    except Exception:
        pass
    return None


def current_mode(iface: str) -> str:
    out = _run(["iw", "dev", iface, "info"])
    m = re.search(r"type\s+(\S+)", out)
    return m.group(1) if m else "unknown"


# ------------------------------------------------------------------
def check_capabilities(iface: str) -> CardCapabilities:
    """
    Probe the card for monitor mode support.  Injection is reported
    optimistically (no card actually blocks it in modern Linux with
    the right RadioTap headers).  iwlwifi gets a special inject mode
    flag because it needs TXFlags set.
    """
    caps = CardCapabilities(iface=iface)

    if not is_wireless(iface):
        caps.reason = f"{iface} is not a wireless interface"
        return caps

    caps.driver = driver_of(iface)

    # ---- find the phy name ----
    out = _run(["iw", "dev", iface, "info"])
    if not out:
        caps.reason = "iw dev failed — is iw installed?"
        return caps

    m = re.search(r"wiphy\s+(\d+)", out)
    phy_name = f"phy{m.group(1)}" if m else None

    # ---- locate the "Supported interface modes" block ----
    modes_block = ""
    for cmd in (
        (["iw", "phy", phy_name] if phy_name else None),
        ["iw", "phy"],
        ["iw", "list"],
    ):
        if cmd is None or modes_block:
            continue
        o = _run(cmd)
        if o:
            mm = re.search(
                r"Supported interface modes:(.*?)(?:\n\s*\n|\Z)", o, re.S)
            if mm:
                modes_block = mm.group(1)

    if modes_block:
        caps.supports_monitor = "* monitor" in modes_block
    else:
        # couldn't read the block; assume monitor is possible and let
        # enable_monitor() decide empirically
        caps.supports_monitor = True

    if not caps.supports_monitor:
        caps.reason = f"{caps.driver or 'card'} reports no monitor mode"
        return caps

    # ---- injection: assume yes; only iwlwifi needs special handling ----
    d = (caps.driver or "").lower()
    if d == "iwlwifi":
        caps.inject_mode = "iwlwifi"
        caps.supports_injection = True
        caps.reason = "iwlwifi: injection works with TXFlags=NOSEQ+ORDER"
    else:
        caps.inject_mode = "standard"
        caps.supports_injection = True
        caps.reason = f"{caps.driver or 'unknown'}: standard injection"

    return caps


# ------------------------------------------------------------------
def kill_interferers():
    _run(["systemctl", "stop", "NetworkManager"])
    for proc in ("wpa_supplicant", "avahi-daemon", "dhclient",
                 "dhcpcd", "connman", "iwd"):
        _run(["pkill", "-STOP", proc])


def restore_interferers():
    for proc in ("wpa_supplicant", "avahi-daemon", "dhclient",
                 "dhcpcd", "connman", "iwd"):
        _run(["pkill", "-CONT", proc])
    _run(["systemctl", "start", "NetworkManager"])
    time.sleep(1.2)


# ------------------------------------------------------------------
def enable_monitor(iface: str, logger) -> str:
    """
    In-place monitor mode. Matches Wi-Jam-X's proven approach:
    pkill NetworkManager, iw set type monitor, 4s stabilization.
    """
    if current_mode(iface) == "monitor":
        logger.info(f"{iface} already in monitor mode")
        return iface

    logger.info("stopping NetworkManager …")

    # Wi-Jam-X approach: pkill instead of systemctl stop
    _run(["pkill", "NetworkManager"])
    _run(["pkill", "wpa_supplicant"])
    _run(["rfkill", "unblock", "wifi"])
    time.sleep(0.5)

    # in-place monitor switch
    _run(["ip", "link", "set", iface, "down"])
    _run(["iw", iface, "set", "type", "monitor"])
    _run(["ip", "link", "set", iface, "up"])
    # redundancy — some drivers only respond to ifconfig
    _run(["ifconfig", iface, "up"])

    logger.info(f"awaiting hardware stabilization …")
    time.sleep(4.0)   # Wi-Jam-X uses 4 seconds

    if current_mode(iface) == "monitor":
        logger.ok(f"monitor mode ON  →  {iface}")
        return iface

    # fallback: airmon-ng
    _run(["airmon-ng", "start", iface])
    time.sleep(1.5)
    mon = f"{iface}mon"
    if mon in list_wireless() and current_mode(mon) == "monitor":
        logger.ok(f"monitor mode ON  →  {mon} (airmon)")
        return mon
    if current_mode(iface) == "monitor":
        logger.ok(f"monitor mode ON  →  {iface}")
        return iface

    reset_wifi_card(iface, logger, silent=True)
    raise WirelessError(
        f"could not enter monitor mode on {iface}. "
        f"Run `sudo iw {iface} set type monitor` manually to debug.")


def reset_wifi_card(iface: str, logger, silent: bool = False) -> bool:
    """Restore to managed mode. Matches Wi-Jam-X's cleanup."""
    try:
        mon = f"{iface}mon"
        if mon in list_wireless():
            _run(["airmon-ng", "stop", mon])

        _run(["ip", "link", "set", iface, "down"])
        _run(["iw", iface, "set", "type", "managed"])
        _run(["ip", "link", "set", iface, "up"])
        _run(["systemctl", "restart", "NetworkManager"])
        time.sleep(2.5)

        ok = current_mode(iface) == "managed"
        if not silent:
            if ok:
                logger.ok(f"{iface} restored to managed mode")
            else:
                logger.warn(
                    f"{iface} did not return to managed "
                    f"(mode: {current_mode(iface)})")
        return ok
    except Exception as e:
        if not silent:
            logger.err(f"reset_wifi_card({iface}) failed: {e}")
        return False


def set_channel(iface: str, channel: int) -> bool:
    """Match Wi-Jam-X exactly — no band argument."""
    out = _run(["iw", iface, "set", "channel", str(channel)])
    return True

# ------------------------------------------------------------------
def reset_wifi_card(iface: str, logger, silent: bool = False) -> bool:
    """
    Restore the interface to managed mode and restart NetworkManager.
    Safe to call repeatedly.
    """
    try:
        # stop an airmon mon vif if one exists
        mon = f"{iface}mon"
        if mon in list_wireless():
            _run(["airmon-ng", "stop", mon])

        _run(["ip", "link", "set", iface, "down"])
        _run(["iw", "dev", iface, "set", "type", "managed"])
        _run(["ip", "link", "set", iface, "up"])

        restore_interferers()

        ok = current_mode(iface) == "managed"
        if not silent:
            if ok:
                logger.ok(f"{iface} restored to managed mode")
            else:
                logger.warn(
                    f"{iface} did not return to managed "
                    f"(mode: {current_mode(iface)})")
        return ok
    except Exception as e:
        if not silent:
            logger.err(f"reset_wifi_card({iface}) failed: {e}")
        return False


# ------------------------------------------------------------------
def set_channel(iface: str, channel: int) -> bool:
    band = "a" if channel > 14 else "bg"
    out = _run(["iw", "dev", iface, "set", "channel",
                str(channel), band])
    return "error" not in out.lower() and "invalid" not in out.lower()
