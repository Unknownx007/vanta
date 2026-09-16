# ============================================================
#  File: vanta/banner.py
# ============================================================
import random
import sys
from . import theme as T

QUOTES = [
    "We don't break the network. We become it.",
    "The wire remembers everything. So do we.",
    "Packets don't lie. People do.",
    "You are the ghost on the wire.",
    "Trust is a protocol. We speak it fluently.",
    "Every ARP reply is a promise. Break it.",
    "The gateway is a suggestion, not a rule.",
    "Silence is a signal. We listen to both.",
    "We are the space between the frame and the wire.",
    "They see a network. We see a suggestion.",
    "In a world of trust, be the MITM.",
    "The strongest firewall is the one that thinks it's alone.",
    "Handshakes are agreements. We renegotiate.",
    "Nothing on the wire is private. Only unwatched.",
    "DEDSEC does not knock. DEDSEC is already inside.",
]


def quote() -> str:
    return random.choice(QUOTES)


def print_banner(version: str = "1.0.0", show_quote: bool = True) -> None:
    sys.stdout.write("\n")
    print(T.DCYAN + "   ┌" + "─" * 58 + "┐" + T.RST)
    for line in T.LOGO.strip("\n").splitlines():
        print(T.RED + line + T.RST)
    print()
    print(T.DRED + "        ╭──────────────────────────────────────────────────╮" + T.RST)
    print(T.RED  + "        │  " + T.WHITE + "N E T W O R K   I N T E R C E P T I O N" + T.RED + "         │" + T.RST)
    print(T.RED  + "        │  " + T.DGREEN + "S U I T E   ·   D E D S E C   O P S" + T.RED + "            │" + T.RST)
    print(T.DRED + "        ╰──────────────────────────────────────────────────╯" + T.RST)
    print()
    print(f"             {T.DGREEN}v{version}{T.RST}  {T.DIM}·{T.RST}  "
          f"{T.DCYAN}built by DEDSEC{T.RST}  {T.DIM}·{T.RST}  "
          f"{T.DGREEN}ghost in the wire{T.RST}")
    print()
    print(T.DCYAN + "   └" + "─" * 58 + "┘" + T.RST)
    if show_quote:
        print()
        print(f"   {T.AMBER}»{T.RST}  {T.DGREEN}\"{quote()}\"{T.RST}")
    print()


def print_compact() -> None:
    print(T.RED + T.LOGO_COMPACT + T.RST)


def print_disclaimer() -> None:
    lines = [
        "",
        "  ╔══════════════════════════════════════════════════════════════╗",
        "  ║              ⚠   L E G A L   N O T I C E   ⚠                 ║",
        "  ╠══════════════════════════════════════════════════════════════╣",
        "  ║  VANTA performs active network interception: ARP spoofing,   ║",
        "  ║  DNS spoofing, DHCP attacks, session hijacking and packet   ║",
        "  ║  injection. These are hostile actions on any network.        ║",
        "  ║                                                              ║",
        "  ║  Use ONLY on:                                                ║",
        "  ║    • networks you own,                                       ║",
        "  ║    • isolated lab environments,                              ║",
        "  ║    • engagements with WRITTEN authorization.                 ║",
        "  ║                                                              ║",
        "  ║  Unauthorized interception is a criminal offense in nearly   ║",
        "  ║  every jurisdiction (CFAA, CMA, PECA, StGB §202a, etc.).     ║",
        "  ║                                                              ║",
        "  ║  You are solely responsible for your use of this tool.       ║",
        "  ║  DEDSEC assumes no liability for misuse.                     ║",
        "  ╚══════════════════════════════════════════════════════════════╝",
        "",
    ]
    for line in lines:
        if "⚠" in line or "LEGAL" in line:
            print(T.RED + line + T.RST)
        elif "•" in line or "Use ONLY" in line:
            print(T.AMBER + line + T.RST)
        elif "criminal" in line or "no liability" in line or "solely" in line:
            print(T.DRED + line + T.RST)
        else:
            print(T.WHITE + line + T.RST)


def rule(char: str = "─", width: int = 62, color: str = T.DIM) -> None:
    print(color + char * width + T.RST)


def step(title: str) -> None:
    print()
    print(T.CYAN + f"┌──[ {title.upper()} ]" + "─" * max(0, 48 - len(title)) + T.RST)


def step_end() -> None:
    print(T.CYAN + "└" + "─" * 62 + T.RST)


def tag_attack(name: str, status: str) -> None:
    color = {"start": T.GREEN, "stop": T.RED,
             "live": T.AMBER, "done": T.CYAN}.get(status, T.WHITE)
    print(f"  {color}[{status.upper():^5}]{T.RST}  {T.WHITE}{name}{T.RST}")
