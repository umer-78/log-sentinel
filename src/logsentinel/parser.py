"""Parse OpenSSH lines from /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL)."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime

# "Sep 17 10:02:11 web01 sshd[1234]: <message>"  (classic syslog)
SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
# "2026-09-17T10:02:11.123456+05:00 web01 sshd[1234]: <message>"  (RFC 3339, newer rsyslog)
ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)

IP = r"(?P<ip>[0-9a-fA-F:.]+)"
PATTERNS = [
    ("failed", re.compile(rf"^Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S*) from {IP}")),
    ("invalid_user", re.compile(rf"^Invalid user (?P<user>\S*) from {IP}")),
    ("success", re.compile(rf"^Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from {IP}")),
]


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    host: str
    kind: str  # "failed" | "invalid_user" | "success"
    user: str
    ip: str


def _parse_ts(raw: str, year: int) -> datetime:
    if raw[0].isdigit():
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=None)
    return datetime.strptime(f"{year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int | None = None) -> AuthEvent | None:
    """Return an AuthEvent for an sshd authentication line, or None."""
    line = line.rstrip("\n")
    m = SYSLOG.match(line) or ISO.match(line)
    if not m:
        return None
    msg = m.group("msg")
    for kind, pattern in PATTERNS:
        p = pattern.match(msg)
        if p:
            ts = _parse_ts(m.group("ts"), year or datetime.now().year)
            return AuthEvent(ts, m.group("host"), kind, p.group("user") or "?", p.group("ip"))
    return None


def parse_lines(lines: Iterable[str], year: int | None = None) -> Iterator[AuthEvent]:
    """Parse many lines. Classic syslog has no year, so a December→January
    rollover is detected and the year advanced."""
    current_year = year or datetime.now().year
    last_month = None
    for line in lines:
        event = parse_line(line, current_year)
        if event is None:
            continue
        if last_month == 12 and event.timestamp.month == 1 and not line[0].isdigit():
            current_year += 1
            event = parse_line(line, current_year)
        last_month = event.timestamp.month
        yield event
