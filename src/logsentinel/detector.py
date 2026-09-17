"""Sliding-window detection of brute-force patterns."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .parser import AuthEvent


@dataclass
class DetectorConfig:
    window: timedelta = timedelta(minutes=10)
    brute_force_threshold: int = 10  # failures from one IP inside the window
    spray_user_threshold: int = 5  # distinct usernames tried by one IP inside the window
    allowlist: frozenset[str] = frozenset()


@dataclass
class Alert:
    ip: str
    rule: str  # "brute_force" | "password_spray" | "success_after_failures"
    severity: str  # "medium" | "high" | "critical"
    first_seen: datetime
    last_seen: datetime
    failures: int
    users: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        return d


def detect(events: Iterable[AuthEvent], config: DetectorConfig | None = None) -> list[Alert]:
    """Return one alert per (ip, rule), strongest evidence kept."""
    cfg = config or DetectorConfig()
    windows: dict[str, deque[AuthEvent]] = defaultdict(deque)
    alerts: dict[tuple[str, str], Alert] = {}
    total_failures: dict[str, int] = defaultdict(int)
    # sshd logs one bad attempt at an unknown user twice ("Invalid user x" and then
    # "Failed password for invalid user x"). Count that as one attempt.
    recent_invalid: dict[tuple[str, str], datetime] = {}
    same_attempt = timedelta(seconds=5)

    def raise_alert(ip, rule, severity, window_events, detail):
        users = sorted({e.user for e in window_events})
        key = (ip, rule)
        existing = alerts.get(key)
        if existing is None:
            alerts[key] = Alert(ip, rule, severity, window_events[0].timestamp,
                                window_events[-1].timestamp, len(window_events), users, detail)
        else:
            existing.last_seen = window_events[-1].timestamp
            existing.failures = max(existing.failures, len(window_events))
            existing.users = sorted(set(existing.users) | set(users))
            existing.detail = detail

    for event in sorted(events, key=lambda e: e.timestamp):
        if event.ip in cfg.allowlist:
            continue
        win = windows[event.ip]

        if event.kind == "success":
            failures = [e for e in win if event.timestamp - e.timestamp <= cfg.window]
            if len(failures) >= cfg.brute_force_threshold // 2 and failures:
                raise_alert(
                    event.ip, "success_after_failures", "critical", failures + [event],
                    f"login as '{event.user}' succeeded after {len(failures)} failures: "
                    "investigate this account now",
                )
            win.clear()
            continue

        key = (event.ip, event.user)
        if event.kind == "invalid_user":
            recent_invalid[key] = event.timestamp
        elif key in recent_invalid and event.timestamp - recent_invalid.pop(key) <= same_attempt:
            continue  # second log line for an attempt already counted

        total_failures[event.ip] += 1
        win.append(event)
        while win and event.timestamp - win[0].timestamp > cfg.window:
            win.popleft()

        if len(win) >= cfg.brute_force_threshold:
            raise_alert(event.ip, "brute_force", "high", list(win),
                        f"{len(win)} failed logins within {cfg.window}")
        distinct = {e.user for e in win}
        if len(distinct) >= cfg.spray_user_threshold:
            raise_alert(event.ip, "password_spray", "medium", list(win),
                        f"{len(distinct)} different usernames within {cfg.window}")

    for (ip, _), alert in alerts.items():
        alert.detail += f" ({total_failures[ip]} failures from this IP in total)"
    order = {"critical": 0, "high": 1, "medium": 2}
    return sorted(alerts.values(), key=lambda a: (order[a.severity], -a.failures, a.ip))
