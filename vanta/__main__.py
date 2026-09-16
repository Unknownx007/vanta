# ============================================================
#  File: vanta/__main__.py
# ============================================================
import argparse
import sys

from . import __version__, banner, theme as T


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="vanta",
        description="VANTA — Network Interception Suite // DEDSEC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  sudo vanta                    launch the GUI (default)
  sudo vanta --cli              launch the interactive shell
  sudo vanta --cli -q           shell, minimal banner
  vanta --version               print version
""",
    )
    p.add_argument("--cli", action="store_true",
                   help="run the interactive CLI shell instead of the GUI")
    p.add_argument("--gui", action="store_true",
                   help="force the GUI (default)")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="suppress the banner (CLI mode only)")
    p.add_argument("--version", action="version",
                   version=f"VANTA {__version__}  (DEDSEC)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.cli:
        from .cli import VantaShell
        from .core import Logger
        logger = Logger(verbose=not args.quiet, to_cli=True)
        shell = VantaShell(logger)
        try:
            return shell.run()
        except KeyboardInterrupt:
            print(T.RED + "\n[!] Interrupted." + T.RST)
            return 130

    # default: GUI
    try:
        from .gui.app import run_gui
    except ImportError as e:
        print(T.RED + f"[!] GUI unavailable: {e}\n"
              f"    Install PySide6:  pip install PySide6\n"
              f"    Or run CLI:       sudo vanta --cli" + T.RST)
        return 1
    return run_gui()


if __name__ == "__main__":
    sys.exit(main())
