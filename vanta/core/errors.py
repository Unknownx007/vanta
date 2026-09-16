# ============================================================
#  File: vanta/core/errors.py
# ============================================================
class VantaError(Exception):
    """Base class for all VANTA errors."""


class NotRootError(VantaError):
    """Raised when an operation requires root privileges."""


class InterfaceError(VantaError):
    """Raised when the selected interface is invalid or missing."""


class ScapyError(VantaError):
    """Raised when scapy operations fail."""


class AttackError(VantaError):
    """Raised when an attack module fails."""


class ConfigError(VantaError):
    """Raised when config values are invalid."""


class WirelessError(VantaError):
    """Raised for monitor-mode / injection / wireless-card failures."""
