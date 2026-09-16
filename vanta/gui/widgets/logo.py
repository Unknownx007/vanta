# ============================================================
#  File: vanta/gui/widgets/logo.py
#  VANTA vector logo — red hexagonal shield with a white V.
#  Drawn via QPainter so it scales cleanly at any size.
# ============================================================
from PySide6.QtCore import Qt, QPointF
from PySide6.QtGui import QColor, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import QWidget


class LogoWidget(QWidget):
    def __init__(self, size: int = 56, parent=None,
                 color: str = "#ff003c", glyph: str = "#ffffff"):
        super().__init__(parent)
        self._size = size
        self._red = QColor(color)
        self._white = QColor(glyph)
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WA_TranslucentBackground, True)

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setRenderHint(QPainter.SmoothPixmapTransform)

        s = self._size
        cx, cy = s / 2, s / 2
        m = s * 0.06

        # ---- outer hexagon ----
        hex_pts = [
            QPointF(cx,     m),
            QPointF(s - m,  cy * 0.5),
            QPointF(s - m,  cy * 1.5),
            QPointF(cx,     s - m),
            QPointF(m,      cy * 1.5),
            QPointF(m,      cy * 0.5),
        ]
        pen = QPen(self._red, max(1.5, s * 0.035))
        pen.setJoinStyle(Qt.MiterJoin)
        p.setPen(pen)
        p.setBrush(Qt.NoBrush)
        p.drawPolygon(QPolygonF(hex_pts))

        # ---- inner faint hexagon ----
        k = s * 0.11
        inner_pts = [
            QPointF(cx,         m + s * 0.13),
            QPointF(s - m - k,  cy * 0.5 + s * 0.06),
            QPointF(s - m - k,  cy * 1.5 - s * 0.06),
            QPointF(cx,         s - m - s * 0.13),
            QPointF(m + k,      cy * 1.5 - s * 0.06),
            QPointF(m + k,      cy * 0.5 + s * 0.06),
        ]
        pen2 = QPen(QColor(self._red.red(), self._red.green(),
                           self._red.blue(), 110),
                    max(1.0, s * 0.02))
        p.setPen(pen2)
        p.drawPolygon(QPolygonF(inner_pts))

        # ---- white V glyph ----
        pen3 = QPen(self._white, max(2.0, s * 0.06))
        pen3.setCapStyle(Qt.RoundCap)
        pen3.setJoinStyle(Qt.RoundJoin)
        p.setPen(pen3)
        p.drawLine(QPointF(cx - s * 0.20, cy - s * 0.22),
                   QPointF(cx,            cy + s * 0.20))
        p.drawLine(QPointF(cx,            cy + s * 0.20),
                   QPointF(cx + s * 0.20, cy - s * 0.22))

        p.end()
