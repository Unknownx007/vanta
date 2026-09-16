# ============================================================
#  File: vanta/core/firewall.py
# ============================================================
import shutil
import subprocess
import threading


class Firewall:
    """
    Detects the running firewall backend (firewalld / ufw / none) and
    opens TCP/UDP ports for the duration of an attack.  All rules are
    remembered and removed on close_all().
    """

    def __init__(self, logger):
        self.log = logger
        self._rules = []
        self._lock = threading.Lock()
        self.backend = self._detect()

    def _run(self, cmd):
        try:
            return subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=5).stdout or ""
        except Exception as e:
            return f"error: {e}"

    def _detect(self):
        if shutil.which("firewall-cmd"):
            if "active" in self._run(["systemctl", "is-active", "firewalld"]):
                return "firewalld"
        if shutil.which("ufw"):
            if "Status: active" in self._run(["ufw", "status"]):
                return "ufw"
        return None

    # ------------------------------------------------------------------
    def open_tcp(self, port: int) -> bool:
        return self._open("tcp", port)

    def open_udp(self, port: int) -> bool:
        return self._open("udp", port)

    def _open(self, proto: str, port: int) -> bool:
        if self.backend is None:
            return True

        with self._lock:
            if self.backend == "firewalld":
                self._run(["firewall-cmd", f"--add-port={port}/{proto}"])
                self._run(["firewall-cmd", f"--add-port={port}/{proto}",
                           "--permanent"])
                self._run(["firewall-cmd", "--reload"])
                self._rules.append(("firewalld", proto, port))
            elif self.backend == "ufw":
                self._run(["ufw", "allow", f"{port}/{proto}"])
                self._rules.append(("ufw", proto, port))

        self.log.ok(f"firewall: opened {port}/{proto}  ({self.backend})")
        return True

    def close_all(self):
        with self._lock:
            rules = list(self._rules)
            self._rules.clear()
        for backend, proto, port in rules:
            if backend == "firewalld":
                self._run(["firewall-cmd", f"--remove-port={port}/{proto}"])
                self._run(["firewall-cmd", f"--remove-port={port}/{proto}",
                           "--permanent"])
                self._run(["firewall-cmd", "--reload"])
            elif backend == "ufw":
                self._run(["ufw", "delete", "allow", f"{port}/{proto}"])
            self.log.info(f"firewall: closed {port}/{proto}")
