# ============================================================
#  File: vanta/gui/__init__.py
# ============================================================
import os


def load_stylesheet() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "theme.qss")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


__all__ = ["load_stylesheet"]
