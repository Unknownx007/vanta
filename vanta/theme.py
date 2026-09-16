# ============================================================
#  File: vanta/theme.py
#  DEDSEC // VANTA — red/black/white palette
# ============================================================
from colorama import Fore, Style

# --- CLI ANSI tokens ------------------------------------------------
RED      = Fore.RED    + Style.BRIGHT     # primary
DRED     = Fore.RED                       # dim red (borders, muted)
WHITE    = Fore.WHITE  + Style.BRIGHT     # headings
DWHITE   = Fore.WHITE                     # body
GREEN    = Fore.GREEN  + Style.BRIGHT     # "live" state only
DGREEN   = Fore.GREEN
AMBER    = Fore.YELLOW + Style.BRIGHT     # warnings
DAMBER   = Fore.YELLOW
CYAN     = Fore.CYAN   + Style.BRIGHT     # info / links
DCYAN    = Fore.CYAN
DIM      = Style.DIM
RST      = Style.RESET_ALL
BOLD     = Style.BRIGHT

# --- Hex tokens (GUI / QSS) ----------------------------------------
HEX = {
    "bg_primary":  "#000000",
    "bg_soft":     "#0a0a0a",
    "bg_panel":    "#0a0a0a",
    "bg_input":    "#050505",
    "bg_titlebar": "#100608",      # deep red tint
    "line":        "#1a1a1a",
    "line_soft":   "#101010",
    "line_red":    "#2a0a12",      # red-tinted separator

    "red":         "#ff003c",
    "red_dim":     "#7a001c",
    "red_glow":    "#ff3366",
    "red_deep":    "#1a0510",

    "white":       "#ffffff",
    "text":        "#d0d0d0",
    "text_dim":    "#5a5a5a",
    "text_mute":   "#303030",

    "amber":       "#ffb400",
    "amber_dim":   "#7a5600",

    "green":       "#00ff9c",
    "green_dim":   "#0b6b48",

    "cyan":        "#00d4ff",   # kept for links / info lines
}

# --- ASCII logos ---------------------------------------------------
LOGO = r"""
`7MMF'   `7MF' db      `7MN.   `7MF'MMP""MM""YMM   db      
  `MA     ,V  ;MM:       MMN.    M  P'   MM   `7  ;MM:     
   VM:   ,V  ,V^MM.      M YMb   M       MM      ,V^MM.    
    MM.  M' ,M  `MM      M  `MN. M       MM     ,M  `MM    
    `MM A'  AbmmmqMA     M   `MM.M       MM     AbmmmqMA   
     :MM;  A'     VML    M     YMM       MM    A'     VML  
        VF .AMA.   .AMMA..JML.    YM     .JMML..AMA.   .AMMA.
"""

LOGO_COMPACT = r"""
  ╔══════════════════════════════════════════════════════╗
  ║   ▓▒░  V A N T A   //   D E D S E C   S U I T E  ░▒▓  ║
  ╚══════════════════════════════════════════════════════╝
"""
