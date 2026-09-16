# ============================================================
#  File: vanta/attacks/inject.py
# ============================================================
from scapy.all import (  # type: ignore
    ARP, DNS, DNSQR, Ether, ICMP, IP, Raw, TCP, UDP,
    send, sendp,
)

from .base import Attack
from ..core.iface import require_root
from ..core.errors import AttackError


class PacketInjector(Attack):
    """
    One-shot raw packet builder.  Usage:
        inj = PacketInjector(cfg, logger)
        inj.craft("ip", dst="1.1.1.1", proto="icmp")
        inj.craft("arp", ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff",
                  target="192.168.1.10")
        inj.craft("dns", domain="example.com", server="8.8.8.8")
        inj.craft("tcp", dst="1.1.1.1", dport=80, flags="S")
    """

    NAME = "inject"

    def setup(self):
        require_root()

    def _run(self):
        # nothing continuous — this module is command-driven
        return

    # -- API used by CLI / GUI -------------------------------------
    def craft(self, kind: str, **kw) -> bool:
        try:
            pkt = self._build(kind, **kw)
        except Exception as e:
            self.log.err(f"craft failed: {e}")
            return False
        iface = self.cfg.iface
        try:
            if pkt.haslayer(Ether):
                sendp(pkt, iface=iface, verbose=False)
            else:
                send(pkt, iface=iface, verbose=False)
            self.log.ok(f"injected {kind}: {pkt.summary()}")
            self.stats["injected"] = self.stats.get("injected", 0) + 1
            return True
        except Exception as e:
            self.log.err(f"send failed: {e}")
            return False

    def _build(self, kind: str, **kw):
        kind = kind.lower()
        if kind == "arp":
            return (
                Ether(dst=kw.get("target_mac", "ff:ff:ff:ff:ff:ff")) /
                ARP(op=int(kw.get("op", 2)),
                    psrc=kw.get("ip"),
                    pdst=kw.get("target"))
            )
        if kind == "icmp":
            return IP(dst=kw["dst"]) / ICMP()
        if kind == "udp":
            return (IP(dst=kw["dst"]) /
                    UDP(sport=int(kw.get("sport", 4444)),
                        dport=int(kw["dport"])) /
                    Raw(load=str(kw.get("payload", "")).encode()))
        if kind == "tcp":
            return (IP(dst=kw["dst"]) /
                    TCP(sport=int(kw.get("sport", 4444)),
                        dport=int(kw["dport"]),
                        flags=kw.get("flags", "S")))
        if kind == "dns":
            return (IP(dst=kw["server"]) /
                    UDP(sport=4444, dport=53) /
                    DNS(rd=1, qd=DNSQR(qname=kw["domain"])))
        raise AttackError(f"unknown packet kind: {kind}")
