# ============================================================
#  File: vanta/core/sysctl.py
# ============================================================
import threading


class Sysctl:
    """
    Save/set/restore /proc/sys values.  Every value we change is
    remembered and restored when the attack stops.
    """

    def __init__(self, logger):
        self.log = logger
        self._originals = {}
        self._lock = threading.Lock()

    @staticmethod
    def _path(key: str) -> str:
        return "/proc/sys/" + key.replace(".", "/")

    def get(self, key: str):
        try:
            with open(self._path(key)) as f:
                return f.read().strip()
        except Exception:
            return None

    def set(self, key: str, value) -> bool:
        with self._lock:
            if key not in self._originals:
                self._originals[key] = self.get(key)
        try:
            with open(self._path(key), "w") as f:
                f.write(str(value))
            return True
        except Exception as e:
            self.log.warn(f"sysctl {key}={value} failed: {e}")
            return False

    def restore(self, key: str):
        with self._lock:
            orig = self._originals.pop(key, None)
        if orig is not None:
            try:
                with open(self._path(key), "w") as f:
                    f.write(orig)
            except Exception:
                pass

    def restore_all(self):
        for k in list(self._originals.keys()):
            self.restore(k)

    # ---- convenience wrappers ------------------------------------
    def enable_ipv4_forwarding(self):
        if self.set("net.ipv4.ip_forward", 1):
            self.log.ok("sysctl: ipv4 forwarding ON")
            return True
        return False

    def enable_ipv6_forwarding(self):
        if self.set("net.ipv6.conf.all.forwarding", 1):
            self.log.ok("sysctl: ipv6 forwarding ON")
            return True
        return False

    def silence_ipv6_autoconf(self, iface: str):
        self.set(f"net.ipv6.conf.{iface}.accept_ra", 0)
        self.set(f"net.ipv6.conf.{iface}.autoconf", 0)
        self.log.ok(f"sysctl: silenced ipv6 autoconf on {iface}")
