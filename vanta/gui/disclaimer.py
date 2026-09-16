# ============================================================
#  File: vanta/gui/disclaimer.py
# ============================================================
import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QCheckBox,
    QPushButton, QFrame,
)

from .. import theme as T
from ..banner import quote


class DisclaimerDialog(QDialog):
    """
    Modal gate shown before the main window.  User must tick the
    acknowledgement checkbox to enable the PROCEED button.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("VANTA // Legal Notice")
        self.setModal(True)
        self.resize(820, 780)
        self.setMinimumSize(720, 640)
        self.setStyleSheet(f"QDialog {{ background-color: {T.HEX['bg_primary']}; }}")

        root = QVBoxLayout(self)
        root.setContentsMargins(40, 26, 40, 26)
        root.setSpacing(12)

        # ---------------- ASCII logo ----------------
        logo = QLabel(T.LOGO.strip("\n"))
        logo.setFont(QFont("JetBrains Mono, Consolas, monospace", 10))
        logo.setStyleSheet(
            f"color: {T.HEX['red']}; background: transparent;"
            f"letter-spacing: 0px;")
        logo.setAlignment(Qt.AlignCenter)
        root.addWidget(logo)

        # ---------------- title ----------------
        title = QLabel("V A N T A")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            f"color: {T.HEX['red']}; font-size: 30px; font-weight: 800; "
            f"letter-spacing: 12px; background: transparent;")
        root.addWidget(title)

        # ---------------- subtitle ----------------
        subtitle = QLabel("NETWORK  INTERCEPTION  SUITE   //   DEDSEC")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet(
            f"color: {T.HEX['white']}; font-size: 10px; "
            f"letter-spacing: 4px; background: transparent;")
        root.addWidget(subtitle)

        # ---------------- separator ----------------
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background: {T.HEX['line']};")
        root.addWidget(sep)

        # ---------------- LEGAL NOTICE header ----------------
        warn = QLabel("⚠   L E G A L   N O T I C E   ⚠")
        warn.setAlignment(Qt.AlignCenter)
        warn.setStyleSheet(
            f"color: {T.HEX['red']}; font-size: 15px; font-weight: 700; "
            f"letter-spacing: 4px; padding: 4px 0; background: transparent;")
        root.addWidget(warn)

        # ---------------- body ----------------
        body = QLabel(
            "VANTA performs <b>active network interception</b>: ARP spoofing, "
            "DNS spoofing, DHCP attacks, session hijacking, IPv6 router "
            "advertisement spoofing, wireless deauthentication and packet "
            "injection. These are hostile actions on any network.<br><br>"
            f"<span style='color:{T.HEX['amber']}'>Use ONLY on:</span><br>"
            f"&nbsp;&nbsp;• networks you own,<br>"
            f"&nbsp;&nbsp;• isolated lab environments,<br>"
            f"&nbsp;&nbsp;• engagements with <b>WRITTEN authorization</b>.<br><br>"
            f"<span style='color:{T.HEX['red_dim']}'>"
            "Unauthorized interception is a criminal offense in nearly every "
            "jurisdiction (CFAA, CMA, PECA, StGB §202a, etc.).<br><br>"
            "You are solely responsible for your use of this tool. "
            "DEDSEC assumes no liability for misuse.</span>"
        )
        body.setWordWrap(True)
        body.setTextFormat(Qt.RichText)
        body.setStyleSheet(
            f"color: {T.HEX['text']}; font-size: 12px; "
            f"background: transparent;")
        root.addWidget(body)

        # ---------------- separator ----------------
        sep2 = QFrame()
        sep2.setFixedHeight(1)
        sep2.setStyleSheet(f"background: {T.HEX['line']};")
        root.addWidget(sep2)

        # ---------------- checkbox ----------------
        self.check = QCheckBox(
            "  I have read and understood the above, and I accept full "
            "responsibility for my use of VANTA."
        )
        self.check.setStyleSheet(
            f"QCheckBox {{ color: {T.HEX['amber']}; font-size: 12px; "
            f"padding: 10px 2px; spacing: 10px; background: transparent; }}"
            f"QCheckBox::indicator {{"
            f"  width: 20px; height: 20px;"
            f"  border: 2px solid {T.HEX['red']};"
            f"  background: {T.HEX['bg_input']};"
            f"}}"
            f"QCheckBox::indicator:checked {{"
            f"  background: {T.HEX['red']};"
            f"}}"
            f"QCheckBox::indicator:hover {{"
            f"  border-color: {T.HEX['amber']};"
            f"}}"
        )
        self.check.setChecked(False)

        # Multiple signals — one will always fire
        self.check.clicked.connect(self._update_proceed)
        self.check.toggled.connect(self._update_proceed)
        self.check.stateChanged.connect(self._update_proceed)

        root.addWidget(self.check)

        # ---------------- status hint ----------------
        self.hint = QLabel("⬤  Awaiting acknowledgement — PROCEED is locked.")
        self.hint.setAlignment(Qt.AlignCenter)
        self.hint.setStyleSheet(
            f"color: {T.HEX['red']}; font-size: 11px; letter-spacing: 2px; "
            f"padding: 2px 0 8px 0; background: transparent;")
        root.addWidget(self.hint)

        # ---------------- buttons ----------------
        btn_row = QHBoxLayout()
        btn_row.setSpacing(14)
        btn_row.addStretch()

        self.abort_btn = QPushButton("ABORT")
        self.abort_btn.setFixedSize(180, 42)
        self.abort_btn.setStyleSheet(
            f"QPushButton {{ background: {T.HEX['red_deep']}; "
            f"color: {T.HEX['red']}; "
            f"border: 1px solid {T.HEX['red']}; font-weight: 700; "
            f"letter-spacing: 3px; border-radius: 4px; }}"
            f"QPushButton:hover {{ background: {T.HEX['red']}; "
            f"color: {T.HEX['bg_primary']}; }}"
        )
        self.abort_btn.clicked.connect(self.reject)
        btn_row.addWidget(self.abort_btn)

        self.proceed_btn = QPushButton("PROCEED →")
        self.proceed_btn.setFixedSize(180, 42)
        self.proceed_btn.setEnabled(False)
        self.proceed_btn.setStyleSheet(self._proceed_qss(False))
        self.proceed_btn.clicked.connect(self.accept)
        btn_row.addWidget(self.proceed_btn)

        btn_row.addStretch()
        root.addLayout(btn_row)

        # ---------------- quote footer ----------------
        q = QLabel(f'"{quote()}"')
        q.setAlignment(Qt.AlignCenter)
        q.setStyleSheet(
            f"color: {T.HEX['red']}; font-style: italic; font-size: 12px; "
            f"padding-top: 10px; background: transparent;")
        root.addWidget(q)

        # run once so state is correct at launch
        self._update_proceed()

    # ------------------------------------------------------------------
    def _proceed_qss(self, enabled: bool) -> str:
        if enabled:
            return (
                f"QPushButton {{ background: {T.HEX['red']}; "
                f"color: {T.HEX['bg_primary']}; border: 1px solid "
                f"{T.HEX['red']}; font-weight: 800; letter-spacing: 3px; "
                f"border-radius: 4px; }}"
                f"QPushButton:hover {{ background: {T.HEX['red_glow']}; }}"
            )
        return (
            f"QPushButton {{ background: {T.HEX['red_deep']}; "
            f"color: {T.HEX['red_dim']}; "
            f"border: 1px solid {T.HEX['line']}; font-weight: 800; "
            f"letter-spacing: 3px; border-radius: 4px; }}"
        )

    # ------------------------------------------------------------------
    def _update_proceed(self, *args):
        checked = self.check.isChecked()
        self.proceed_btn.setEnabled(checked)
        self.proceed_btn.setStyleSheet(self._proceed_qss(checked))
        if checked:
            self.hint.setText(
                "⬤  Acknowledgement received — PROCEED is unlocked.")
            self.hint.setStyleSheet(
                f"color: {T.HEX['white']}; font-size: 11px; "
                f"letter-spacing: 2px; padding: 2px 0 8px 0; "
                f"background: transparent;")
        else:
            self.hint.setText(
                "⬤  Awaiting acknowledgement — PROCEED is locked.")
            self.hint.setStyleSheet(
                f"color: {T.HEX['red']}; font-size: 11px; "
                f"letter-spacing: 2px; padding: 2px 0 8px 0; "
                f"background: transparent;")

    # ------------------------------------------------------------------
    @classmethod
    def gate(cls, parent=None) -> bool:
        dlg = cls(parent)
        return dlg.exec() == QDialog.Accepted
