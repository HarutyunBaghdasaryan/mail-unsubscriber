"""Command-line entry point. Commands are placeholders until implemented."""

from __future__ import annotations

import argparse
import sys

from . import __version__

COMMANDS = ("login", "scan", "show", "unsubscribe", "logout", "mcp")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="unsub", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("command", nargs="?", choices=COMMANDS)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    print(f"unsub {args.command}: not implemented yet", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
