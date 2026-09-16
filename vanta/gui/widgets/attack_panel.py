# ============================================================
#  File: vanta/gui/widgets/attack_panel.py
# ============================================================
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QComboBox, QLineEdit, QSpinBox, QDoubleSpinBox,
    QButtonGroup, QWidget, QStackedWidget, QFormLayout,
    QTableWidget, QTableWidgetItem, QHeaderView,
)

from ... import theme as T


class AttackPanel(QFrame):
    """
    Attack control panel with tab switcher and per-attack forms.
    Emits `command` dict for the main window to dispatch.
    """

    command = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ---- tab strip ----
        tabs_row = QHBoxLayout()
        tabs_row.setContentsMargins(0, 0, 0, 0)
        tabs_row.setSpacing(0)
        tabs_wrap = QWidget()
        tabs_wrap.setLayout(tabs_row)
        tabs_wrap.setStyleSheet(
            f"background-color: {T.HEX['bg_soft']}; "
            f"border-bottom: 1px solid {T.HEX['line']};"
        )

        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self.pages = QStackedWidget()

        for idx, name in enumerate(["ARP POISON", "DNS",
                                    "IPv6 RA", "DEAUTH", "INJECT"]):
            btn = QPushButton(name)
            btn.setCheckable(True)
            btn.setObjectName("attack-tab")
            if idx == 0:
                btn.setChecked(True)
            self.group.addButton(btn, idx)
            tabs_row.addWidget(btn)
        tabs_row.addStretch()
        root.addWidget(tabs_wrap)

        # ---- pages ----
        self.pages.addWidget(self._page_poison())
        self.pages.addWidget(self._page_dns())
        self.pages.addWidget(self._page_ra())
        self.pages.addWidget(self._page_deauth())
        self.pages.addWidget(self._page_inject())

        root.addWidget(self.pages, 1)
        self.group.idClicked.connect(self.pages.setCurrentIndex)

    # ==================================================================
    #  POISON
    # ==================================================================
    def _page_poison(self):
        w = QWidget()
        form = QFormLayout(w)
        form.setContentsMargins(24, 18, 24, 18)
        form.setSpacing(10)

        self.poison_target = QLineEdit()
        self.poison_target.setPlaceholderText(
            "192.168.1.10  (blank = use target field)")
        form.addRow("Target IP", self.poison_target)

        self.poison_rate = QDoubleSpinBox()
        self.poison_rate.setRange(0.1, 100.0)
        self.poison_rate.setValue(2.0)
        self.poison_rate.setSuffix("  pkt/s")
        form.addRow("Rate", self.poison_rate)

        btns = QHBoxLayout()
        start = QPushButton("▶  START POISON")
        start.setObjectName("primary")
        start.clicked.connect(lambda: self.command.emit({
            "attack": "poison", "action": "start",
            "target": self.poison_target.text().strip() or None,
            "rate": self.poison_rate.value(),
        }))
        stop = QPushButton("■  STOP")
        stop.setObjectName("danger")
        stop.clicked.connect(lambda: self.command.emit({
            "attack": "poison", "action": "stop"}))
        btns.addWidget(start)
        btns.addWidget(stop)
        form.addRow("", btns)
        return w

    # ==================================================================
    #  DNS
    # ==================================================================
    def _page_dns(self):
        w = QWidget()
        form = QFormLayout(w)
        form.setContentsMargins(24, 18, 24, 18)
        form.setSpacing(10)

        self.dns_domain = QLineEdit()
        self.dns_domain.setPlaceholderText(
            "example.com   (use * for wildcard)")
        form.addRow("Domain", self.dns_domain)

        self.dns_ip = QLineEdit()
        self.dns_ip.setPlaceholderText("192.168.0.100")
        form.addRow("Reply IP", self.dns_ip)

        add = QPushButton("+  ADD RULE")
        add.clicked.connect(lambda: self.command.emit({
            "attack": "dns", "action": "add_rule",
            "domain": self.dns_domain.text().strip(),
            "ip": self.dns_ip.text().strip(),
        }))
        form.addRow("", add)

        btns = QHBoxLayout()
        start = QPushButton("▶  START DNS SPOOF")
        start.setObjectName("primary")
        start.clicked.connect(lambda: self.command.emit({
            "attack": "dns", "action": "start"}))
        stop = QPushButton("■  STOP")
        stop.setObjectName("danger")
        stop.clicked.connect(lambda: self.command.emit({
            "attack": "dns", "action": "stop"}))
        btns.addWidget(start)
        btns.addWidget(stop)
        form.addRow("", btns)
        return w

    # ==================================================================
    #  IPv6 RA
    # ==================================================================
    def _page_ra(self):
        w = QWidget()
        form = QFormLayout(w)
        form.setContentsMargins(24, 18, 24, 18)
        form.setSpacing(10)

        start = QPushButton("▶  START RA SPOOF")
        start.setObjectName("primary")
        start.clicked.connect(lambda: self.command.emit({
            "attack": "ra", "action": "start"}))
        stop = QPushButton("■  STOP")
        stop.setObjectName("danger")
        stop.clicked.connect(lambda: self.command.emit({
            "attack": "ra", "action": "stop"}))
        btns = QHBoxLayout()
        btns.addWidget(start)
        btns.addWidget(stop)
        form.addRow("", btns)
        return w

    # ==================================================================
    #  DEAUTH
    # ==================================================================
    def _page_deauth(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(24, 14, 24, 14)
        v.setSpacing(10)

        # --- capability banner ---
        self.deauth_caps = QLabel("Card: not checked yet")
        self.deauth_caps.setStyleSheet(
            f"color: {T.HEX['text_dim']}; font-size: 11px; "
            f"letter-spacing: 1px;")
        v.addWidget(self.deauth_caps)

        # --- scan button ---
        scan_row = QHBoxLayout()
        scan = QPushButton("⟳  SCAN FOR APs  (15s)")
        scan.setObjectName("primary")
        scan.clicked.connect(lambda: self.command.emit({
            "attack": "deauth", "action": "scan"}))
        scan_row.addWidget(scan)
        scan_row.addStretch()
        v.addLayout(scan_row)

        # --- AP results table ---
        self.deauth_ap_table = QTableWidget(0, 4)
        self.deauth_ap_table.setHorizontalHeaderLabels(
            ["BSSID", "SSID", "CH", "SIGNAL"])
        self.deauth_ap_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch)
        self.deauth_ap_table.verticalHeader().setVisible(False)
        self.deauth_ap_table.setSelectionBehavior(
            QTableWidget.SelectRows)
        self.deauth_ap_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.deauth_ap_table.setAlternatingRowColors(True)
        self.deauth_ap_table.setMinimumHeight(160)
        self.deauth_ap_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {T.HEX['bg_input']};
                gridline-color: {T.HEX['line_soft']};
                border: 1px solid {T.HEX['line']};
                border-radius: 4px;
            }}
            QTableWidget::item {{ padding: 6px 10px; }}
            QTableWidget::item:selected {{
                background-color: {T.HEX['green_dim']};
                color: {T.HEX['green']};
            }}
            QHeaderView::section {{
                background-color: {T.HEX['bg_titlebar']};
                color: {T.HEX['text_dim']};
                padding: 6px 8px; border: none;
                border-bottom: 1px solid {T.HEX['line']};
                font-size: 10px; letter-spacing: 2px;
            }}
        """)
        # click a row → auto-fill form
        self.deauth_ap_table.itemSelectionChanged.connect(
            self._on_ap_selected)
        v.addWidget(self.deauth_ap_table, 1)

        # --- manual form ---
        form = QFormLayout()
        form.setSpacing(8)

        self.deauth_bssid = QLineEdit()
        self.deauth_bssid.setPlaceholderText("aa:bb:cc:dd:ee:ff")
        form.addRow("AP BSSID", self.deauth_bssid)

        self.deauth_client = QLineEdit()
        self.deauth_client.setPlaceholderText(
            "blank = all clients, or aa:bb:cc:dd:ee:ff")
        form.addRow("Client", self.deauth_client)

        row = QHBoxLayout()
        self.deauth_channel = QSpinBox()
        self.deauth_channel.setRange(0, 165)
        self.deauth_channel.setValue(6)
        row.addWidget(self.deauth_channel)
        row.addWidget(QLabel("reason"))
        self.deauth_reason = QSpinBox()
        self.deauth_reason.setRange(0, 40)
        self.deauth_reason.setValue(7)
        row.addWidget(self.deauth_reason)
        row.addStretch()
        form.addRow("Channel / reason", row)

        v.addLayout(form)

        # --- start / stop ---
        btns = QHBoxLayout()
        start = QPushButton("▶  START DEAUTH")
        start.setObjectName("primary")
        start.clicked.connect(lambda: self.command.emit({
            "attack": "deauth", "action": "start",
            "bssid":  self.deauth_bssid.text().strip(),
            "client": self.deauth_client.text().strip() or None,
            "channel": self.deauth_channel.value(),
            "reason":  self.deauth_reason.value(),
        }))
        stop = QPushButton("■  STOP + RESET CARD")
        stop.setObjectName("danger")
        stop.clicked.connect(lambda: self.command.emit({
            "attack": "deauth", "action": "stop"}))
        btns.addWidget(start)
        btns.addWidget(stop)
        v.addLayout(btns)

        return w

    def _on_ap_selected(self):
        rows = self.deauth_ap_table.selectionModel().selectedRows()
        if not rows:
            return
        r = rows[0].row()
        bssid = self.deauth_ap_table.item(r, 0).text()
        ch    = self.deauth_ap_table.item(r, 2).text()
        self.deauth_bssid.setText(bssid)
        try:
            self.deauth_channel.setValue(int(ch))
        except Exception:
            pass

    # --- called from the main window with scan results ---
    def show_aps(self, aps):
        self.deauth_ap_table.setRowCount(0)
        for ap in aps:
            row = self.deauth_ap_table.rowCount()
            self.deauth_ap_table.insertRow(row)
            sig = ap.get("signal_dbm")
            cells = [
                ap.get("bssid", ""),
                ap.get("ssid", "") or "(hidden)",
                str(ap.get("channel", "?")),
                f"{sig} dBm" if sig is not None else "-",
            ]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if c == 0:
                    f = item.font(); f.setBold(True); item.setFont(f)
                    item.setForeground(QColor(T.HEX["green"]))
                self.deauth_ap_table.setItem(row, c, item)

    def show_caps(self, caps):
        if caps.supports_monitor:
            color = T.HEX["white"]
            text = (f"Card: {caps.driver}  —  monitor ✔  "
                    f"injection {'✔' if caps.supports_injection else '⚠'}"
                    f"   ({caps.reason})")
        else:
            color = T.HEX["red"]
            text = f"Card: {caps.driver}  —  monitor ✘   ({caps.reason})"
        self.deauth_caps.setText(text)
        self.deauth_caps.setStyleSheet(
            f"color: {color}; font-size: 11px; letter-spacing: 1px;")

    # ==================================================================
    #  INJECT
    # ==================================================================
    def _page_inject(self):
        w = QWidget()
        form = QFormLayout(w)
        form.setContentsMargins(24, 18, 24, 18)
        form.setSpacing(10)

        self.inj_kind = QComboBox()
        self.inj_kind.addItems(["arp", "icmp", "udp", "tcp", "dns"])
        form.addRow("Type", self.inj_kind)

        self.inj_args = QLineEdit()
        self.inj_args.setPlaceholderText(
            "dst=1.1.1.1 dport=80 flags=S")
        form.addRow("Key=val pairs", self.inj_args)

        send = QPushButton("▶  SEND PACKET")
        send.setObjectName("primary")
        send.clicked.connect(self._emit_inject)
        form.addRow("", send)
        return w

    def _emit_inject(self):
        raw = self.inj_args.text().strip()
        kwargs = {}
        for pair in raw.split():
            if "=" in pair:
                k, v = pair.split("=", 1)
                kwargs[k] = v
        self.command.emit({
            "attack": "inject",
            "kind": self.inj_kind.currentText(),
            "kwargs": kwargs,
        })
