# ============================================================
#  File: vanta/gui/widgets/stats.py
# ============================================================
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QLabel

from ... import theme as T


class StatCard(QFrame):
    def __init__(self, label: str, value: str = "0", accent: str = None,
                 parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        accent = accent or T.HEX["red"]

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(2)

        self.label = QLabel(label)
        self.label.setStyleSheet(
            f"color: {T.HEX['text_dim']}; font-size: 10px; "
            f"letter-spacing: 2.5px; background: transparent;")
        lay.addWidget(self.label)

        self.value = QLabel(value)
        self.value.setStyleSheet(
            f"color: {accent}; font-size: 22px; font-weight: 800; "
            f"letter-spacing: 1px;")
        lay.addWidget(self.value)

    def set_value(self, v):
        self.value.setText(str(v))


class StatsWidget(QFrame):
    """Row of stat cards shown below the log."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background: {T.HEX['bg_primary']};")

        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        self.cards = {
            "targets":  StatCard("TARGETS"),
            "attacks":  StatCard("ATTACKS"),
            "creds":    StatCard("CREDENTIALS", accent=T.HEX["red"]),
            "cookies":  StatCard("COOKIES", accent=T.HEX["amber"]),
            "requests": StatCard("REQUESTS", accent=T.HEX["cyan"]),
            "uptime":   StatCard("UPTIME", accent=T.HEX["white"]),
        }

        for c in self.cards.values():
            lay.addWidget(c, 1)

    def update_stat(self, key: str, value):
        if key in self.cards:
            self.cards[key].set_value(value)
