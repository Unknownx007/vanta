# ============================================================
#  File: vanta/cli/shell.py
# ============================================================
import sys
import threading
import time

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style

from .. import banner, theme as T
from ..core import Logger, ArpTable
from .commands import CommandHandler


PROMPT_STYLE = Style.from_dict({
    "prompt": "bold #00ff9c",
    "": "#c8d6e5",
})


class VantaShell:
    def __init__(self, logger: Logger):
        self.log = logger
        self.handler = CommandHandler(logger)
        self.arp = ArpTable()
        self.handler.arp = self.arp

    def run(self):
        banner.print_banner()
        banner.print_disclaimer()
        try:
            ans = input(f"{T.AMBER}Type 'I HAVE PERMISSION' to continue: {T.RST}")
        except (EOFError, KeyboardInterrupt):
            return 1
        if ans.strip().upper() != "I HAVE PERMISSION":
            print(T.RED + "Authorization not confirmed. Aborting." + T.RST)
            return 1

        self.arp.start()

        # welcome + hint
        print()
        self.log.ok("VANTA shell ready. Type 'help' for commands.")
        print()

        try:
            session = PromptSession(
                history=FileHistory(".vanta_history"),
                style=PROMPT_STYLE,
            )
        except Exception:
            session = None

        while True:
            try:
                if session:
                    line = session.prompt([("class:prompt", "vanta » ")])
                else:
                    line = input("vanta » ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            try:
                keep_going = self.handler.dispatch(line)
            except Exception as e:
                self.log.err(f"dispatch failed: {e}")
                keep_going = True
            if not keep_going:
                break

        print()
        self.log.info("shutting down …")
        self.handler.shutdown()
        self.arp.stop()
        print(T.DGREEN + "\n  DEDSEC out. The wire is silent again.\n" + T.RST)
        return 0
