# ============================================================
#  File: vanta/cli/render.py
# ============================================================
from .. import theme as T


def table(headers, rows, widths=None):
    widths = widths or [max(len(str(h)), *(len(str(r[i]))
                          for r in rows) if rows else [0])
                        for i, h in enumerate(headers)]
    sep = T.DIM + "─" * (sum(widths) + 3 * (len(widths) - 1) + 4) + T.RST

    print(T.CYAN + "  " + "  ".join(
        str(h).ljust(widths[i]) for i, h in enumerate(headers)) + T.RST)
    print(sep)
    for r in rows:
        cells = []
        for i, c in enumerate(r):
            s = str(c)
            if i == 0:
                cells.append(T.GREEN + s.ljust(widths[i]) + T.RST)
            else:
                cells.append(s.ljust(widths[i]))
        print("  " + "  ".join(cells))
    print(sep)


def kv(key, value, key_color=T.CYAN, val_color=T.WHITE):
    print(f"  {key_color}{key:<14}{T.RST} {val_color}{value}{T.RST}")


def stats_row(items):
    print()
    for k, v in items:
        print(f"    {T.DIM}{k:<14}{T.RST}{T.GREEN}{v}{T.RST}")
    print()
