# logsentinel: SSH brute-force detector

[![CI](https://github.com/umer-78/log-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/umer-78/log-sentinel/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A small blue-team tool that reads Linux authentication logs and flags
**brute-force attacks**, **password spraying** and the one that really matters:
**a successful login right after a run of failures**.

```text
$ logsentinel samples/auth.log --year 2026
Parsed 70 sshd lines: 57 failed-login, 8 invalid-user, 5 successful
[CRITICAL] success_after_failures   2001:db8::42                                8 tries  2026-09-17 11:00 → 11:01
           users: alice
           login as 'alice' succeeded after 7 failures: investigate this account now (7 failures from this IP in total)
[HIGH    ] brute_force              198.51.100.23                              40 tries  2026-09-17 03:00 → 03:03
           users: root
           40 failed logins within 0:10:00 (40 failures from this IP in total)
[MEDIUM  ] password_spray           203.0.113.77                                8 tries  2026-09-17 05:00 → 05:02
           users: admin, git, guest, oracle, pi, postgres, test, ubuntu
           8 different usernames within 0:10:00 (8 failures from this IP in total)
```

## Detection rules

| Rule | Fires when | Severity |
|---|---|---|
| `brute_force` | one IP has ≥ `--threshold` failed logins inside the sliding window | high |
| `password_spray` | one IP tries ≥ `--spray` different usernames inside the window | medium |
| `success_after_failures` | a login succeeds from an IP with ≥ half the threshold of recent failures | critical |

The window slides per IP, so slow attacks that stay under the threshold are not
flagged. That is a deliberate trade-off against false positives. Lower
`--threshold` or raise `--window` to catch them.

## Supported input

- OpenSSH lines from `/var/log/auth.log` (Debian/Ubuntu) and `/var/log/secure` (RHEL)
- Classic syslog timestamps (`Sep 17 10:02:11`, with December→January rollover) and RFC 3339 timestamps
- IPv4 and IPv6, rotated `.gz` files, or standard input
- `journalctl -u ssh -o short` output

## Install and run

```bash
git clone https://github.com/umer-78/log-sentinel.git
cd log-sentinel
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

logsentinel samples/auth.log --year 2026            # table
logsentinel /var/log/auth.log* --format json        # JSON for a SIEM
sudo journalctl -u ssh -o short | logsentinel -     # from systemd
logsentinel /var/log/auth.log --format blocklist > block.txt   # high/critical IPs only
```

Exit codes: `0` nothing found, `1` alerts, `2` at least one critical alert, so it
can run from cron and notify on non-zero.

## Using the block list

`--format blocklist` prints one IP per line. Review it before acting, then for example:

```bash
while read ip; do sudo ufw deny from "$ip"; done < block.txt
```

For automatic blocking in production, use a maintained tool such as fail2ban.
This project is for analysis and learning.

## Sample data

`samples/auth.log` is synthetic and uses only documentation IP ranges
(RFC 5737 and RFC 3849), so no real hosts appear. Regenerate it with
`python samples/make_sample.py`.

## Development

```bash
ruff check .
pytest -q
```

## License

[MIT](LICENSE)
