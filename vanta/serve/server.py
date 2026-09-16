# ============================================================
#  File: vanta/serve/server.py
# ============================================================
import http.server
import os
import socketserver
import threading


DEFAULT_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>⚠ DEDSEC</title>
<style>
  html,body{margin:0;height:100%}
  body{background:#05070a;color:#c8d6e5;
       font-family:ui-monospace,"JetBrains Mono",Consolas,monospace;
       display:flex;align-items:center;justify-content:center;
       text-align:center}
  .box{border:1px solid #ff003c;padding:48px 72px;border-radius:10px;
       background:#0a0a0a;box-shadow:0 0 60px rgba(255,0,60,.35)}
  h1{color:#ff003c;letter-spacing:8px;margin:0 0 24px 0;font-size:26px}
  p{letter-spacing:1px;line-height:1.9;font-size:14px;margin:8px 0}
  .q{color:#00ff9c;font-style:italic;margin-top:32px;font-size:13px}
</style></head>
<body><div class="box">
  <h1>◈ D E D S E C</h1>
  <p>You've just been DNS-spoofed.</p>
  <p>This page is being served from the attacker's host.<br>
     The real site lives somewhere else.</p>
  <p class="q">"We don't break the network. We become it."</p>
</div></body></html>
"""


class FakeServer:
    """
    Threaded HTTP server for phishing / DNS-spoof landing pages.
    Auto-creates its document root and a default DEDSEC page.
    """

    def __init__(self, logger, port: int = 80,
                 bind: str = "0.0.0.0",
                 root: str = None,
                 page_html: str = None):
        self.log = logger
        self.port = port
        self.bind = bind
        self.root = root or os.path.expanduser("~/vanta-fake")
        self.page_html = page_html
        self._httpd = None
        self._thread = None

    def is_running(self) -> bool:
        return self._httpd is not None

    def start(self) -> bool:
        os.makedirs(self.root, exist_ok=True)
        index = os.path.join(self.root, "index.html")

        if self.page_html is not None:
            with open(index, "w") as f:
                f.write(self.page_html)
        elif not os.path.isfile(index):
            with open(index, "w") as f:
                f.write(DEFAULT_PAGE)

        root   = self.root
        port   = self.port
        bind   = self.bind
        logger = self.log

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **kw):
                super().__init__(*a, directory=root, **kw)

            def log_message(self, fmt, *args):
                logger.snare(
                    f"HTTP  {self.client_address[0]}  {fmt % args}")

        class TCPServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        try:
            self._httpd = TCPServer((bind, port), Handler)
        except OSError as e:
            self.log.err(f"server: bind {bind}:{port} failed — {e}")
            return False

        self._thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True,
            name="vanta-http")
        self._thread.start()
        self.log.ok(f"server: serving {root} on {bind}:{port}")
        return True

    def stop(self):
        if self._httpd:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
        if self._thread:
            self._thread.join(timeout=1)
            self._thread = None
        self.log.info("server: stopped")
