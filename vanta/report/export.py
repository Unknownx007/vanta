# ============================================================
#  File: vanta/report/export.py
# ============================================================
import html
import json
from datetime import datetime


def export_json(session, path: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(session.to_dict(), f, indent=2, ensure_ascii=False)
    return path


HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>VANTA Session — {title}</title>
<style>
  body{{background:#05070a;color:#c8d6e5;font-family:ui-monospace,monospace;
       padding:40px;max-width:1100px;margin:auto}}
  h1,h2{{color:#00ff9c;letter-spacing:3px}}
  h2{{border-left:3px solid #00ff9c;padding-left:12px;margin-top:38px}}
  table{{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}}
  th{{text-align:left;padding:8px;color:#5d7185;background:#0a121b;
      border-bottom:1px solid #16222f;letter-spacing:1.6px;font-size:11px}}
  td{{padding:8px;border-bottom:1px solid #101a25}}
  tr:hover td{{background:rgba(0,255,156,.04)}}
  .hl{{color:#00ff9c}} .dim{{color:#5d7185}} .red{{color:#ff003c}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
        gap:1px;background:#16222f;border:1px solid #16222f}}
  .stat{{background:#0a0f16;padding:14px}}
  .stat .l{{font-size:10px;color:#5d7185;letter-spacing:2px}}
  .stat .v{{font-size:22px;color:#00ff9c;font-weight:700;margin-top:6px}}
  .footer{{margin-top:60px;padding-top:24px;border-top:1px solid #16222f;
           text-align:center;color:#5d7185;font-size:12px}}
</style></head><body>
<h1>◈ VANTA</h1>
<p class="dim">Session {title} · built by DEDSEC</p>

<div class="grid">
  <div class="stat"><div class="l">INTERFACE</div><div class="v">{iface}</div></div>
  <div class="stat"><div class="l">TARGETS</div><div class="v">{n_targets}</div></div>
  <div class="stat"><div class="l">ATTACKS</div><div class="v">{n_attacks}</div></div>
  <div class="stat"><div class="l">CREDENTIALS</div><div class="v red">{n_creds}</div></div>
  <div class="stat"><div class="l">COOKIES</div><div class="v">{n_cookies}</div></div>
  <div class="stat"><div class="l">HTTP REQS</div><div class="v">{n_requests}</div></div>
</div>

<h2>Targets</h2>
<table><tr><th>IP</th><th>MAC</th></tr>
{targets_rows}
</table>

<h2>Attacks</h2>
<table><tr><th>Attack</th><th>State</th><th>Uptime</th></tr>
{attacks_rows}
</table>

<h2>Credentials</h2>
<table><tr><th>Type</th><th>Source</th><th>Host</th><th>Username</th><th>Password</th></tr>
{creds_rows}
</table>

<h2>Cookies</h2>
<table><tr><th>Host</th><th>Name</th><th>Value</th><th>Src</th></tr>
{cookies_rows}
</table>

<div class="footer">
  "We don't break the network. We become it." — DEDSEC
</div>
</body></html>
"""


def _rows(items, cols):
    if not items:
        return f'<tr><td colspan="{len(cols)}" class="dim">none</td></tr>'
    out = []
    for it in items:
        cells = "".join(f"<td>{html.escape(str(it.get(c, '')))}</td>"
                        for c in cols)
        out.append(f"<tr>{cells}</tr>")
    return "\n".join(out)


def export_html(session, path: str) -> str:
    d = session.to_dict()
    doc = HTML_TEMPLATE.format(
        title=d.get("started", "").replace("T", " "),
        iface=d.get("iface", "-") or "-",
        n_targets=len(d.get("targets", [])),
        n_attacks=len(d.get("attacks", [])),
        n_creds=len(d.get("credentials", [])),
        n_cookies=len(d.get("cookies", [])),
        n_requests=len(d.get("requests", [])),
        targets_rows=_rows(d.get("targets", []), ["ip", "mac"]),
        attacks_rows=_rows(d.get("attacks", []),
                           ["name", "state", "uptime"]),
        creds_rows=_rows(d.get("credentials", []),
                         ["type", "src", "host", "username", "password"]),
        cookies_rows=_rows(d.get("cookies", []),
                           ["host", "name", "value", "src"]),
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path
