# ============================================================
#  File: vanta/gui/app.py
# ============================================================
import sys
from PySide6.QtCore import Qt, QTimer, Signal, QObject
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QLineEdit, QFrame, QSplitter,
    QStatusBar, QMessageBox, QGridLayout,
)

from .. import theme as T, banner
from ..core import Logger, Config, ArpTable, get_interface, list_interfaces, \
    get_default_gateway, set_config
from ..core.iface import require_root, NotRootError
from ..attacks import (ArpPoison, DnsSpoofer,
                       RaSpoofer, PacketInjector)
from ..sniff import Snare
from ..report import Session, export_json, export_html
from .disclaimer import DisclaimerDialog
from . import load_stylesheet
from .widgets import ConsoleWidget, TargetTable, AttackPanel, StatsWidget


class LogBridge(QObject):
    record = Signal(dict)


class VantaWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("VANTA // DEDSEC — Network Interception Suite")
        self.resize(1500, 940)

        self.cfg = Config()
        set_config(self.cfg)
        self.log = Logger(verbose=False, to_cli=True)
        self.arp = ArpTable()
        self.snare = Snare(self.cfg, self.log)
        self.attacks: dict = {}
        self.injector: PacketInjector | None = None
        self.session = Session.from_config(self.cfg)

        self._build_ui()
        self._wire_log()
        self.arp.start()

        # periodic stats refresh (uptime, packet counters, etc.)
        self._stats_timer = QTimer(self)
        self._stats_timer.timeout.connect(self._refresh_stats)
        self._stats_timer.start(1000)  # every 1 second

        self.log.ok("VANTA GUI ready")
        self.log.info("Select an interface and click SCAN to begin.")

    # ------------------------------------------------------------------
    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(14, 14, 14, 14)
        outer.setSpacing(10)

        outer.addWidget(self._build_header())
        outer.addWidget(self._build_topbar())

        middle = QSplitter(Qt.Horizontal)
        middle.addWidget(self._build_left_col())
        middle.addWidget(self._build_right_col())
        middle.setSizes([480, 900])
        middle.setChildrenCollapsible(False)
        outer.addWidget(middle, 1)

        outer.addWidget(self._build_stats())

        self.status = QStatusBar()
        self.status.showMessage(
            f'DEDSEC  ·  "{banner.quote()}"')
        self.setStatusBar(self.status)

    # ------------------------------------------------------------------
    def _build_header(self) -> QFrame:
        f = QFrame()
        f.setObjectName("header")
        lay = QHBoxLayout(f)
        lay.setContentsMargins(22, 16, 22, 16)
        lay.setSpacing(18)

        # --- vector logo ---
        from .widgets.logo import LogoWidget
        logo = LogoWidget(58)
        lay.addWidget(logo, alignment=Qt.AlignVCenter)

        # --- title block ---
        col = QVBoxLayout()
        col.setSpacing(2)
        col.setContentsMargins(0, 0, 0, 0)

        title = QLabel("VANTA")
        title.setObjectName("title")
        col.addWidget(title)

        sub = QLabel("NETWORK  INTERCEPTION  SUITE   //   DEDSEC")
        sub.setObjectName("subtitle")
        col.addWidget(sub)

        lay.addLayout(col)
        lay.addStretch()

        # --- status pill ---
        self.status_label = QLabel("●   I D L E")
        self.status_label.setObjectName("statusIdle")
        lay.addWidget(self.status_label, alignment=Qt.AlignVCenter)

        return f

    # ------------------------------------------------------------------
    def _build_topbar(self) -> QFrame:
        f = QFrame()
        f.setObjectName("card")
        lay = QHBoxLayout(f)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(10)

        lay.addWidget(QLabel("IFACE"))
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(140)

        skip_prefixes = ("lo", "docker", "br-", "veth", "virbr",
                         "tun", "tap", "vanta", "dummy")
        names = []
        for name in list_interfaces():
            if any(name.startswith(p) for p in skip_prefixes):
                continue
            try:
                if get_interface(name).ipv4:
                    names.append(name)
            except Exception:
                continue

        for name in names:
            self.iface_combo.addItem(name)
        self.iface_combo.currentTextChanged.connect(self._select_iface)

        # apply the initial pick immediately
        if self.iface_combo.count() > 0:
            self._select_iface(self.iface_combo.currentText())

        lay.addWidget(self.iface_combo)

        lay.addWidget(QLabel("TARGET"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("192.168.1.10")
        self.target_input.setMinimumWidth(160)
        lay.addWidget(self.target_input)

        scan_btn = QPushButton("⟳  SCAN")
        scan_btn.clicked.connect(self._scan)
        lay.addWidget(scan_btn)

        apply_btn = QPushButton("◈  APPLY TARGET")
        apply_btn.clicked.connect(self._apply_target)
        lay.addWidget(apply_btn)

        lay.addStretch()

        snare_btn = QPushButton("⌬  SNARE START")
        snare_btn.setObjectName("primary")
        snare_btn.clicked.connect(self._snare_start)
        lay.addWidget(snare_btn)

        snare_stop = QPushButton("■  SNARE STOP")
        snare_stop.setObjectName("danger")
        snare_stop.clicked.connect(self._snare_stop)
        lay.addWidget(snare_stop)

        save_btn = QPushButton("⤓  SAVE")
        save_btn.clicked.connect(self._save_session)
        lay.addWidget(save_btn)

        return f

    # ------------------------------------------------------------------
    def _build_left_col(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)

        self.target_table = TargetTable()
        self.target_table.setMinimumHeight(220)
        lay.addWidget(self.target_table, 1)

        self.attack_panel = AttackPanel()
        self.attack_panel.setMinimumHeight(360)
        self.attack_panel.command.connect(self._handle_attack_command)
        lay.addWidget(self.attack_panel, 2)

        return w

    # ------------------------------------------------------------------
    def _build_right_col(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)

        self.console = ConsoleWidget()
        lay.addWidget(self.console, 1)
        return w

    # ------------------------------------------------------------------
    def _build_stats(self) -> StatsWidget:
        self.stats_widget = StatsWidget()
        return self.stats_widget

    # ------------------------------------------------------------------
    def _wire_log(self):
        bridge = LogBridge()
        bridge.record.connect(self.console.append)
        self.log.subscribe(lambda rec: bridge.record.emit(rec))

    # ------------------------------------------------------------------
    #  slots
    # ------------------------------------------------------------------
    def _select_iface(self, name: str):
        if not name:
            return
        try:
            iface = get_interface(name)
            self.cfg.iface = name
            self.cfg.attacker_mac = iface.mac
            self.cfg.attacker_ip = iface.ipv4
            self.log.ok(f"iface = {name}  ({iface.ipv4} / {iface.mac})")
            self._refresh_stats()
        except Exception as e:
            self.log.err(f"iface: {e}")

    def _scan(self):
        try:
            if not self.cfg.iface:
                cur = self.iface_combo.currentText()
                if cur:
                    self._select_iface(cur)
            if not self.cfg.iface:
                self.log.err("select an interface first")
                return
            gw = get_default_gateway()
            if gw:
                self.cfg.gateway_ip = gw
                self.arp.refresh()
                import subprocess
                subprocess.run(["ping", "-c", "1", "-W", "1", gw],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                self.arp.refresh()
                self.cfg.gateway_mac = self.arp.get(gw)
                self.log.ok(f"gateway: {gw}  mac={self.cfg.gateway_mac}")
            self.log.info("ping sweep (this takes ~2s) …")
            found = self.arp.sweep()
            self.log.ok(f"ping sweep found {found} hosts")
            self._refresh_targets()

        except Exception as e:
            self.log.err(f"scan: {e}")

    def _apply_target(self):
        ip = self.target_input.text().strip()
        if not ip:
            self.log.warn("enter a target IP")
            return
        self.cfg.target_ip = ip
        self.arp.refresh()
        self.cfg.target_mac = self.arp.get(ip)
        if not self.cfg.target_mac:
            self.log.warn(f"no ARP entry for {ip} — try pinging it first")
        else:
            self.log.ok(f"target = {ip}  mac={self.cfg.target_mac}")
        self._refresh_targets()

    def _snare_start(self):
        if not self.cfg.iface:
            cur = self.iface_combo.currentText()
            if cur:
                self._select_iface(cur)
        if not self.cfg.iface:
            self.log.err("snare: pick an interface first")
            return
        try:
            self.snare.start()
            self._refresh_stats()
        except Exception as e:
            self.log.err(f"snare: {e}")

    def _snare_stop(self):
        self.snare.stop()
        self._refresh_stats()

    def _save_session(self):
        self._refresh_session()
        import os
        from datetime import datetime
        name = f"vanta_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path = os.path.join(self.cfg.session_dir, name)
        export_json(self.session, path)
        self.log.ok(f"session saved → {path}")

    # ------------------------------------------------------------------
    def _deauth_check(self):
        from ..core import wireless
        if not self.cfg.iface:
            self.log.warn("pick an interface first")
            return
        caps = wireless.check_capabilities(self.cfg.iface)
        self.attack_panel.show_caps(caps)
        self.log.info(f"card: {caps.driver}  "
                      f"monitor={caps.supports_monitor}  "
                      f"inject={caps.supports_injection}  "
                      f"({caps.reason})")

    # ------------------------------------------------------------------
    def _deauth_scan(self):
        from ..attacks.deauth import ApScanner
        self.log.step("AP scan (15s) — card will enter monitor mode")
        self.log.warn("NetworkManager will be stopped temporarily "
                      "and restored automatically")
        try:
            scanner = ApScanner(self.cfg, self.log)
            results = scanner.scan(seconds=15)
            self.attack_panel.show_aps(results)
            self.log.ok(f"scan complete — {len(results)} APs found")
        except Exception as e:
            self.log.err(f"scan failed: {e}")

    # ------------------------------------------------------------------
    def _deauth_start(self, cmd):
        from ..attacks.deauth import Deauther
        bssid = (cmd.get("bssid") or "").strip()
        if not bssid:
            self.log.warn("pick an AP from the list or type a BSSID")
            return
        atk = Deauther(
            self.cfg, self.log,
            bssid=bssid,
            client=cmd.get("client") or None,
            channel=cmd.get("channel") or None,
            reason=cmd.get("reason") or 7,
        )
        self._start("deauth", atk)

    # ------------------------------------------------------------------
    def _deauth_stop(self):
        atk = self.attacks.get("deauth")
        if atk:
            atk.stop()
            self.attacks.pop("deauth", None)
        # safety net: also reset the card again
        from ..core import wireless
        if self.cfg.iface:
            wireless.reset_wifi_card(self.cfg.iface, self.log)

    # ------------------------------------------------------------------
    def _handle_attack_command(self, cmd: dict):
        atk = cmd.get("attack")
        try:
            if atk == "poison":
                if cmd["action"] == "start":
                    if cmd.get("target"):
                        self.target_input.setText(cmd["target"])
                        self._apply_target()
                    if cmd.get("rate"):
                        self.cfg.packet_rate = float(cmd["rate"])
                    self._start("poison", ArpPoison(self.cfg, self.log))
                else:
                    self._stop("poison")

            elif atk == "dns":
                if cmd["action"] == "add_rule":
                    d, ip = cmd.get("domain"), cmd.get("ip")
                    if d and ip:
                        self.cfg.dns_rules[d] = ip
                        self.log.ok(f"dns rule: {d} → {ip}")
                elif cmd["action"] == "start":
                    self._start("dns", DnsSpoofer(self.cfg, self.log))
                else:
                    self._stop("dns")

            elif atk == "ra":
                if cmd["action"] == "start":
                    self._start("ipv6-ra", RaSpoofer(self.cfg, self.log))
                else:
                    self._stop("ipv6-ra")

            elif atk == "inject":
                if self.injector is None:
                    self.injector = PacketInjector(self.cfg, self.log)
                    self.injector.setup()
                self.injector.craft(cmd["kind"], **cmd.get("kwargs", {}))

            elif atk == "deauth":
                action = cmd.get("action")
                if action == "scan":
                    self._deauth_scan()
                elif action == "start":
                    self._deauth_start(cmd)
                elif action == "stop":
                    self._deauth_stop()
                elif action == "check":
                    self._deauth_check()

        except Exception as e:
            self.log.err(f"attack error: {e}")
        self._refresh_stats()

    def _start(self, name: str, atk):
        if name in self.attacks and self.attacks[name].is_running():
            self.log.warn(f"{name} already running")
            return
        if atk.start():
            self.attacks[name] = atk
            self.status_label.setText("●   L I V E")
            self.status_label.setObjectName("statusLive")
            # force QSS re-evaluation
            self.status_label.style().unpolish(self.status_label)
            self.status_label.style().polish(self.status_label)

    def _stop(self, name: str):
        atk = self.attacks.get(name)
        if atk:
            atk.stop()
            self.attacks.pop(name, None)
        if not any(a.is_running() for a in self.attacks.values()):
            self.status_label.setText("●   I D L E")
            self.status_label.setObjectName("statusIdle")
            self.status_label.style().unpolish(self.status_label)
            self.status_label.style().polish(self.status_label)
    # ------------------------------------------------------------------
    def _refresh_targets(self):
        hosts = self.arp.all()
        self.target_table.set_hosts(
            hosts,
            gateway_ip=self.cfg.gateway_ip or "",
            target_ip=self.cfg.target_ip or "",
        )

    def _refresh_stats(self):
        self.stats_widget.update_stat("targets", len(self.arp.all()))
        running = sum(1 for a in self.attacks.values() if a.is_running())
        self.stats_widget.update_stat("attacks", running)
        self.stats_widget.update_stat("creds", len(self.snare.credentials))
        self.stats_widget.update_stat("cookies", len(self.snare.cookies))
        self.stats_widget.update_stat("requests",
                                      self.snare.stats.get("packets", 0))
        up = max((a.uptime() for a in self.attacks.values()), default=0)
        mm, ss = divmod(int(up), 60)
        hh, mm = divmod(mm, 60)
        self.stats_widget.update_stat("uptime", f"{hh:02d}:{mm:02d}:{ss:02d}")

    def _refresh_session(self):
        self.session.iface = self.cfg.iface
        self.session.gateway_ip = self.cfg.gateway_ip
        self.session.gateway_mac = self.cfg.gateway_mac
        self.session.attacker_ip = self.cfg.attacker_ip
        self.session.attacker_mac = self.cfg.attacker_mac
        self.session.targets = [{"ip": ip, "mac": mac}
                                for ip, mac in self.arp.all().items()]
        self.session.attacks = [a.info() for a in self.attacks.values()]
        self.session.credentials = list(self.snare.credentials)
        self.session.cookies = list(self.snare.cookies)
        self.session.requests = list(self.snare.requests)
        self.session.logs = self.log.dump()
        self.session.finish()

    # ------------------------------------------------------------------
    def closeEvent(self, event):
        for atk in list(self.attacks.values()):
            try:
                atk.stop()
            except Exception:
                pass
        try:
            self.snare.stop()
        except Exception:
            pass
        self.arp.stop()
        # reset wifi card if we left it in monitor mode
        try:
            from ..core import wireless
            if self.cfg.iface and wireless.is_wireless(self.cfg.iface):
                wireless.reset_wifi_card(self.cfg.iface, self.log,
                                          silent=True)
        except Exception:
            pass
        event.accept()


def run_gui() -> int:
    try:
        require_root()
    except NotRootError:
        # show message then exit
        app = QApplication.instance() or QApplication(sys.argv)
        QMessageBox.critical(
            None, "VANTA",
            "VANTA requires root privileges.\n\nRe-run with sudo (Linux/macOS).",
        )
        return 1

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("VANTA")
    app.setStyleSheet(load_stylesheet())

    if not DisclaimerDialog.gate():
        return 1

    win = VantaWindow()
    win.show()
    return app.exec()
