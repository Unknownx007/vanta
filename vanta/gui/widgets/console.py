# ============================================================
#  File: vanta/gui/widgets/console.py
# ============================================================
from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtGui import QTextCursor, QColor, QFont
from PySide6.QtWidgets import QTextEdit, QVBoxLayout, QFrame, QLabel

from ... import theme as T


LEVEL_COLORS = {
    "INFO":   T.HEX["cyan"],
    "OK":     T.HEX["green"],
    "WARN":   T.HEX["amber"],
    "ERR":    T.HEX["red"],
    "STEP":   T.HEX["red"],
    "DATA":   T.HEX["text"],
    "SNARE":  T.HEX["white"],
    "ATTACK": T.HEX["red"],
}

class ConsoleWidget(QFrame):
    """Terminal-style live log panel with colored tags."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        header = QLabel("  ◈  LIVE  LOG")
        header.setStyleSheet(
            f"background-color: {T.HEX['bg_titlebar']}; "
            f"color: {T.HEX['red']}; letter-spacing: 4px; "
            f"font-weight: 700; font-size: 11px; "
            f"padding: 8px 14px; "
            f"border-bottom: 1px solid {T.HEX['line_red']};"
        )
        root.addWidget(header)

        self.text = QTextEdit()
        self.text.setObjectName("console")
        self.text.setReadOnly(True)
        self.text.setFont(QFont("JetBrains Mono, Consolas, monospace", 10))
        self.text.setStyleSheet(
            f"background-color: {T.HEX['bg_input']}; "
            f"border: none; color: {T.HEX['text']}; padding: 8px;"
        )
        root.addWidget(self.text, 1)

    def append(self, rec: dict):
        ts = rec.get("ts", "")
        level = rec.get("level", "INFO")
        msg = rec.get("msg", "")
        color = LEVEL_COLORS.get(level, T.HEX["text"])

        cursor = self.text.textCursor()
        cursor.movePosition(QTextCursor.End)

        fmt_time = cursor.charFormat()
        fmt_time.setForeground(QColor(T.HEX["text_dim"]))
        cursor.setCharFormat(fmt_time)
        cursor.insertText(f"{ts} ")

        fmt_tag = cursor.charFormat()
        fmt_tag.setForeground(QColor(color))
        fmt_tag.setFontWeight(QFont.Bold)
        cursor.setCharFormat(fmt_tag)
        cursor.insertText(f"[{level:^5}] ")

        fmt_msg = cursor.charFormat()
        fmt_msg.setForeground(QColor(T.HEX["text"]))
        fmt_msg.setFontWeight(QFont.Normal)
        cursor.setCharFormat(fmt_msg)
        cursor.insertText(f"{msg}\n")

        self.text.setTextCursor(cursor)
        self.text.ensureCursorVisible()

    def clear(self):
        self.text.clear()
