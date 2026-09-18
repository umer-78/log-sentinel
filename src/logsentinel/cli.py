"""logsentinel command line."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
from collections import Counter
from datetime import timedelta
from pathlib import Path

from .detector import DetectorConfig, detect
from .parser import parse_lines


def _open(path: str):
    if path == "-":
        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    """Entry point. Wraps the real work so that piping into `head` — which closes
    the pipe early — ends quietly instead of printing a BrokenPipeError."""
    try:
        return _run(argv)
    except BrokenPipeError:
        # The reader went away. Point stdout at the void so the interpreter's
        # own flush on exit does not raise the same error again.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130


def _run(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="logsentinel", description=__doc__)
    ap.add_argument("logs", nargs="+", help="auth log files (.gz ok), or - for stdin")
    ap.add_argument("--window", type=int, default=10, help="window in minutes (default 10)")
    ap.add_argument("--threshold", type=int, default=10, help="failures that count as brute force")
    ap.add_argument("--spray", type=int, default=5, help="distinct usernames that count as spraying")
    ap.add_argument("--allow", action="append", default=[], help="IP to ignore (repeatable)")
    ap.add_argument("--year", type=int, help="year for syslog lines without one")
    ap.add_argument("--format", choices=["table", "json", "blocklist"], default="table")
    args = ap.parse_args(argv)

    events = []
    for path in args.logs:
        if path != "-" and not Path(path).exists():
            ap.error(f"no such file: {path}")
        with _open(path) as fh:
            events.extend(parse_lines(fh, args.year))

    cfg = DetectorConfig(timedelta(minutes=args.window), args.threshold, args.spray,
                         frozenset(args.allow))
    alerts = detect(events, cfg)

    if args.format == "json":
        print(json.dumps([a.to_dict() for a in alerts], indent=2))
    elif args.format == "blocklist":
        for ip in dict.fromkeys(a.ip for a in alerts if a.severity in ("high", "critical")):
            print(ip)
    else:
        kinds = Counter(e.kind for e in events)
        print(f"Parsed {len(events)} sshd lines: {kinds['failed']} failed-login, "
              f"{kinds['invalid_user']} invalid-user, {kinds['success']} successful")
        if not alerts:
            print("No suspicious activity found.")
        for a in alerts:
            print(f"[{a.severity.upper():8}] {a.rule:24} {a.ip:39} {a.failures:>5} tries  "
                  f"{a.first_seen:%Y-%m-%d %H:%M} → {a.last_seen:%H:%M}")
            print(f"           users: {', '.join(a.users[:8])}{' …' if len(a.users) > 8 else ''}")
            print(f"           {a.detail}")
    return 2 if any(a.severity == "critical" for a in alerts) else (1 if alerts else 0)


if __name__ == "__main__":
    raise SystemExit(main())
