"""Regenerate samples/auth.log (synthetic; documentation IP ranges only)."""

import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(7)
lines: list[str] = []
t = datetime(2026, 9, 17, 1, 0, 0)


def emit(ts: datetime, msg: str) -> None:
    lines.append(f"{ts:%b %d %H:%M:%S} web01 sshd[{random.randint(1000, 9999)}]: {msg}")


# normal key-based logins
for h in (2, 9, 14):
    emit(t.replace(hour=h), "Accepted publickey for deploy from 192.0.2.10 port 50122 ssh2: ED25519 SHA256:abc")
# brute force against root
bt = t.replace(hour=3)
for i in range(40):
    emit(bt + timedelta(seconds=i * 6), f"Failed password for root from 198.51.100.23 port {40000 + i} ssh2")
# password spraying across usernames
st = t.replace(hour=5)
for i, u in enumerate(["admin", "test", "oracle", "ubuntu", "git", "postgres", "pi", "guest"]):
    emit(st + timedelta(seconds=i * 20), f"Invalid user {u} from 203.0.113.77 port {41000 + i}")
    emit(st + timedelta(seconds=i * 20 + 1),
         f"Failed password for invalid user {u} from 203.0.113.77 port {41000 + i} ssh2")
# success after failures: the compromise indicator
ct = t.replace(hour=11)
for i in range(7):
    emit(ct + timedelta(seconds=i * 10), f"Failed password for alice from 2001:db8::42 port {42000 + i} ssh2")
emit(ct + timedelta(seconds=80), "Accepted password for alice from 2001:db8::42 port 42010 ssh2")
# a user mistyping twice, then logging in: must not alert
mt = t.replace(hour=16)
for i in range(2):
    emit(mt + timedelta(seconds=i * 5), "Failed password for umer from 192.0.2.55 port 43000 ssh2")
emit(mt + timedelta(seconds=15), "Accepted password for umer from 192.0.2.55 port 43001 ssh2")
emit(mt, "pam_unix(sshd:session): session opened for user umer")

lines.sort(key=lambda line: datetime.strptime("2026 " + line[:15], "%Y %b %d %H:%M:%S"))
out = Path(__file__).with_name("auth.log")
out.write_text("\n".join(lines) + "\n")
print(f"wrote {len(lines)} lines to {out}")
