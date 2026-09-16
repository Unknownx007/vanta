# ============================================================
#  File: vanta/gui/widgets/target_table.py
# ============================================================
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
    QHeaderView,
)

from ... import theme as T


class TargetTable(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        header = QLabel("  ◈  TARGETS")
        header.setStyleSheet(
            f"background-color: {T.HEX['bg_titlebar']}; "
            f"color: {T.HEX['red']}; letter-spacing: 4px; "
            f"font-weight: 700; font-size: 11px; "
            f"padding: 8px 14px; "
            f"border-bottom: 1px solid {T.HEX['line_red']};"
        )

        root.addWidget(header)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["IP ADDRESS", "MAC", "ROLE"])
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {T.HEX['bg_panel']};
                gridline-color: {T.HEX['line_soft']};
                border: none;
            }}
            QTableWidget::item {{
                padding: 6px 10px;
            }}
            QHeaderView::section {{
                background-color: {T.HEX['bg_titlebar']};
                color: {T.HEX['text_dim']};
                padding: 8px 10px;
                border: none;
                border-bottom: 1px solid {T.HEX['line']};
                font-size: 10px;
                letter-spacing: 2px;
            }}
        """)
        root.addWidget(self.table, 1)

    def set_hosts(self, hosts: dict, gateway_ip: str = "", target_ip: str = ""):
        self.table.setRowCount(0)
        for ip, mac in sorted(hosts.items()):
            row = self.table.rowCount()
            self.table.insertRow(row)

            role = ""
            color = T.HEX["text"]
            if ip == gateway_ip:
                role = "GATEWAY"
                color = T.HEX["amber"]
            elif ip == target_ip:
                role = "TARGET"
                color = T.HEX["red"]

            for col, text in enumerate([ip, mac, role]):
                item = QTableWidgetItem(text)
                item.setForeground(QColor(color))
                if col == 0:
                    f = item.font()
                    f.setBold(True)
                    item.setFont(f)
                self.table.setItem(row, col, item)
