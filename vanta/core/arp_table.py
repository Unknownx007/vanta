# ============================================================
#  File: vanta/core/arp_table.py
# ============================================================
import re
import subprocess
import threading
import time
from typing import Dict, Optional

from .iface import _run


class ArpTable:
    """
    Thread-safe view of the kernel ARP table, refreshed on demand.
    Also caches a manual map (ip -> mac) learned from scans.
    """

    def sweep(self, cidr: str = None) -> int:
        """
        Actively ping every host in the /24 subnet to populate the ARP
        cache, then refresh.  Returns the number of entries found.
        """
        import concurrent.futures as cf
        import subprocess

        if cidr is None:
            # infer from the current interface
            from .iface import get_default_gateway
            gw = get_default_gateway()
            if not gw:
                return len(self.all())
            cidr = ".".join(gw.split(".")[:3]) + ".0/24"

        base = cidr.rsplit(".", 1)[0]   # "192.168.0"

        def ping_one(i: int):
            ip = f"{base}.{i}"
            try:
                subprocess.run(
                    ["ping", "-c", "1", "-W", "1", "-n", ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=1.5,
                )
            except Exception:
                pass

        with cf.ThreadPoolExecutor(max_workers=128) as pool:
            list(pool.map(ping_one, range(1, 255)))

        self.refresh()
        return len(self.all())





    def __init__(self, refresh_interval: float = 3.0):
        self._cache: Dict[str, str] = {}
        self._manual: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._interval = refresh_interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # -- public API -------------------------------------------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)

    def refresh(self) -> Dict[str, str]:
        out = _run(["ip", "neigh", "show"])
        table: Dict[str, str] = {}
        for line in out.splitlines():
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+"
                         r"([0-9a-f:]{17})", line, re.I)
            if m:
                table[m.group(1)] = m.group(2).lower()
        with self._lock:
            self._cache = table
            self._cache.update(self._manual)
        return dict(self._cache)

    def get(self, ip: str) -> Optional[str]:
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
            if ip in self._manual:
                return self._manual[ip]
        self.refresh()
        with self._lock:
            return self._cache.get(ip)

    def put(self, ip: str, mac: str) -> None:
        with self._lock:
            self._manual[ip] = mac.lower()
            self._cache[ip] = mac.lower()

    def all(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._cache)

    def hosts(self) -> list[str]:
        return sorted(self.all().keys())

    # -- background loop --------------------------------------------
    def _loop(self):
        while not self._stop.is_set():
            try:
                self.refresh()
            except Exception:
                pass
            self._stop.wait(self._interval)
