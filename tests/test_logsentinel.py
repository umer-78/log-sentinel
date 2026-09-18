from datetime import datetime, timedelta
from pathlib import Path

from logsentinel import DetectorConfig, detect, parse_line, parse_lines
from logsentinel.cli import main

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "auth.log"


def test_parse_failed_password():
    e = parse_line("Sep 17 03:00:00 web01 sshd[1]: Failed password for root from 198.51.100.23 port 1 ssh2", 2026)
    assert (e.kind, e.user, e.ip, e.host) == ("failed", "root", "198.51.100.23", "web01")
    assert e.timestamp == datetime(2026, 9, 17, 3, 0, 0)


def test_parse_invalid_user_and_ipv6_and_iso_timestamp():
    e = parse_line("2026-09-17T10:00:00.5+05:00 h sshd[9]: Invalid user bob from 2001:db8::1 port 22")
    assert (e.kind, e.user, e.ip) == ("invalid_user", "bob", "2001:db8::1")


def test_parse_failed_for_invalid_user():
    e = parse_line("Sep  7 03:00:00 h sshd[1]: Failed password for invalid user zz from 203.0.113.9 port 1 ssh2", 2026)
    assert e.kind == "failed" and e.user == "zz" and e.timestamp.day == 7


def test_parse_accepted_and_ignored_lines():
    assert parse_line("Sep 17 03:00:00 h sshd[1]: Accepted publickey for deploy from 192.0.2.1 port 5 ssh2", 2026).kind == "success"
    assert parse_line("Sep 17 03:00:00 h sshd[1]: pam_unix(sshd:session): session opened", 2026) is None
    assert parse_line("Sep 17 03:00:00 h cron[1]: Failed password for x from 1.2.3.4", 2026) is None
    assert parse_line("garbage") is None


def test_year_rollover():
    lines = [
        "Dec 31 23:59:59 h sshd[1]: Failed password for a from 192.0.2.1 port 1 ssh2",
        "Jan  1 00:00:01 h sshd[1]: Failed password for a from 192.0.2.1 port 1 ssh2",
    ]
    events = list(parse_lines(lines, 2025))
    assert [e.timestamp.year for e in events] == [2025, 2026]


def _events():
    return list(parse_lines(SAMPLE.read_text().splitlines(), 2026))


def test_sample_alerts():
    alerts = detect(_events())
    found = {(a.ip, a.rule) for a in alerts}
    assert ("198.51.100.23", "brute_force") in found
    assert ("203.0.113.77", "password_spray") in found
    assert ("2001:db8::42", "success_after_failures") in found
    # a user who mistyped twice must not be flagged
    assert not any(a.ip == "192.0.2.55" for a in alerts)
    assert alerts[0].severity == "critical"


def test_window_expiry():
    base = datetime(2026, 1, 1)
    from logsentinel.parser import AuthEvent
    slow = [AuthEvent(base + timedelta(minutes=5 * i), "h", "failed", "root", "192.0.2.9") for i in range(20)]
    assert detect(slow) == []  # one try every 5 minutes never reaches 10 in 10 minutes
    fast = [AuthEvent(base + timedelta(seconds=i), "h", "failed", "root", "192.0.2.9") for i in range(10)]
    assert [a.rule for a in detect(fast)] == ["brute_force"]


def test_allowlist():
    cfg = DetectorConfig(allowlist=frozenset({"198.51.100.23"}))
    assert not any(a.ip == "198.51.100.23" for a in detect(_events(), cfg))


def test_cli_blocklist_and_exit_code(capsys):
    code = main([str(SAMPLE), "--year", "2026", "--format", "blocklist"])
    out = capsys.readouterr().out.split()
    assert out == ["2001:db8::42", "198.51.100.23"]
    assert code == 2


def test_cli_missing_file(capsys):
    import pytest
    with pytest.raises(SystemExit):
        main(["/nope/auth.log"])


def test_piping_into_head_does_not_print_a_traceback(tmp_path):
    """`logsentinel samples/auth.log | head` closes the pipe early; that must end quietly.

    Without the guard in cli.main, Python prints a BrokenPipeError traceback to
    stderr the moment the reader goes away — which looks like a crash in any
    pipeline a person actually writes.
    """
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(root / "src")}

    producer = subprocess.Popen(
        [sys.executable, "-m", 'logsentinel'] + ['samples/auth.log'],
        cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,

    )
    reader = subprocess.Popen(["head", "-2"], stdin=producer.stdout, stdout=subprocess.DEVNULL)
    producer.stdout.close()
    reader.communicate()
    stderr = producer.stderr.read().decode()
    producer.wait()

    assert "BrokenPipeError" not in stderr, stderr
    assert "Traceback" not in stderr, stderr
