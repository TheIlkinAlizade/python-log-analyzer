import time
from datetime import datetime
from pathlib import Path

import pytest

from log_analyzer.models import ParseStats, SshEvent, SshEventType
from log_analyzer.parsers.ssh import Outcome, YearResolver, parse_ssh_file, parse_ssh_line

DATA = Path(__file__).resolve().parent / "data"
NOW = datetime(2026, 10, 22, 12, 0, 0)


def make_line(
    message: str,
    stamp: str = "Oct 21 14:03:11",
    host: str = "web01",
    process: str = "sshd[1234]",
) -> str:
    return f"{stamp} {host} {process}: {message}"


def new_resolver() -> YearResolver:
    return YearResolver(year=2026, now=NOW)


def parse(line: str) -> SshEvent | Outcome:
    return parse_ssh_line(line, 3, new_resolver())


FAILED_LINES = [
    "",
    "garbage",
    make_line("Failed password for root from 999.1.1.1 port 22 ssh2"),
    make_line("Failed password for root from 203.0.113.5 port 70000 ssh2"),
    make_line("Failed password for root from 203.0.113.5 port 123456 ssh2"),
    make_line("Failed password for invalid user a b from 203.0.113.5 port 22 ssh2"),
    make_line("Accepted password for root from 203.0.113.5 port 22 ssh2", stamp="Feb 30 14:03:11"),
    make_line("Accepted password for root from 203.0.113.5 port 22 ssh2", stamp="Foo 21 14:03:11"),
    make_line("Accepted password for root from 203.0.113.5 port 22 ssh2", stamp="Oct 21 25:03:11"),
    "Oct 21 14:03:11 web01 sshd[" + "9" * 5000 + "]: Failed password for root from 1.2.3.4 port 22",
]

IGNORED_LINES = [
    make_line("Connection closed by 203.0.113.5 port 52814 [preauth]"),
    make_line("Received disconnect from 203.0.113.5 port 52814:11: Bye Bye"),
    make_line("pam_unix(sshd:auth): authentication failure; logname= uid=0"),
    make_line("session opened for user root", process="CRON[9]"),
    make_line(
        "message repeated 3 times: [ Failed password for root from 203.0.113.5 port 22 ssh2]"
    ),
]


def test_parses_failed_password() -> None:
    event = parse(make_line("Failed password for root from 203.0.113.5 port 52814 ssh2"))
    assert isinstance(event, SshEvent)
    assert event.line_number == 3
    assert event.timestamp == datetime(2026, 10, 21, 14, 3, 11)
    assert event.hostname == "web01"
    assert event.pid == 1234
    assert event.event_type is SshEventType.FAILED_PASSWORD
    assert event.username == "root"
    assert event.source_ip == "203.0.113.5"
    assert event.port == 52814


def test_parses_failed_password_for_invalid_user() -> None:
    event = parse(make_line("Failed password for invalid user admin from 203.0.113.5 port 22 ssh2"))
    assert isinstance(event, SshEvent)
    assert event.event_type is SshEventType.FAILED_PASSWORD
    assert event.username == "admin"


def test_parses_accepted_password() -> None:
    event = parse(make_line("Accepted password for alice from 198.51.100.7 port 40022 ssh2"))
    assert isinstance(event, SshEvent)
    assert event.event_type is SshEventType.ACCEPTED_PASSWORD
    assert event.username == "alice"
    assert event.source_ip == "198.51.100.7"


def test_parses_invalid_user_with_and_without_port() -> None:
    with_port = parse(make_line("Invalid user oracle from 203.0.113.9 port 41234"))
    without_port = parse(make_line("Invalid user oracle from 203.0.113.9"))
    assert isinstance(with_port, SshEvent)
    assert isinstance(without_port, SshEvent)
    assert with_port.event_type is SshEventType.INVALID_USER
    assert with_port.port == 41234
    assert without_port.port is None


def test_space_padded_day() -> None:
    event = parse(make_line("Invalid user x from 203.0.113.9", stamp="Oct  1 14:03:11"))
    assert isinstance(event, SshEvent)
    assert event.timestamp == datetime(2026, 10, 1, 14, 3, 11)


def test_sshd_session_process_name_is_accepted() -> None:
    line = make_line("Invalid user x from 203.0.113.9", process="sshd-session[4321]")
    event = parse(line)
    assert isinstance(event, SshEvent)
    assert event.pid == 4321


def test_process_without_pid() -> None:
    event = parse(make_line("Invalid user x from 203.0.113.9", process="sshd"))
    assert isinstance(event, SshEvent)
    assert event.pid is None


def test_ipv6_source_is_normalised() -> None:
    event = parse(make_line("Invalid user x from 2001:DB8::1 port 22"))
    assert isinstance(event, SshEvent)
    assert event.source_ip == "2001:db8::1"


def test_control_characters_stay_raw_for_later_sanitising() -> None:
    event = parse(make_line("Invalid user \x1b[31mroot from 203.0.113.9 port 22"))
    assert isinstance(event, SshEvent)
    assert event.username == "\x1b[31mroot"


@pytest.mark.parametrize("line", FAILED_LINES)
def test_invalid_lines_are_failed(line: str) -> None:
    assert parse(line) is Outcome.FAILED


@pytest.mark.parametrize("line", IGNORED_LINES)
def test_untracked_lines_are_ignored(line: str) -> None:
    assert parse(line) is Outcome.IGNORED


def test_adversarial_lines_finish_quickly() -> None:
    candidates = [
        "Oct" + " " * 8000,
        "Oct 21 14:03:11 " + "a" * 8000,
        "Oct 21 14:03:11 web01 " + "a" * 8000,
        make_line("Failed password for " + "a " * 4000),
        make_line("Failed password for root from " + "9" * 8000),
        make_line("Invalid user " + "x" * 8000),
    ]
    started = time.perf_counter()
    for line in candidates:
        assert isinstance(parse(line), Outcome)
    assert time.perf_counter() - started < 1.0


def test_file_separates_parsed_ignored_failed_and_oversized(tmp_path: Path) -> None:
    path = tmp_path / "mixed.log"
    lines = [
        make_line("Failed password for root from 203.0.113.5 port 22 ssh2"),
        "",
        make_line("session opened", process="CRON[9]"),
        "garbage",
        make_line("Connection closed by 203.0.113.5 port 22 [preauth]"),
        "x" * 5000,
        make_line("Accepted password for alice from 203.0.113.6 port 22 ssh2"),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    stats = ParseStats()
    events = list(parse_ssh_file(path, stats, new_resolver(), max_line_length=200))
    assert [event.event_type for event in events] == [
        SshEventType.FAILED_PASSWORD,
        SshEventType.ACCEPTED_PASSWORD,
    ]
    assert stats.total_lines == 6
    assert stats.parsed_lines == 2
    assert stats.ignored_lines == 2
    assert stats.failed_lines == 2
    assert stats.oversized_lines == 1


def test_invalid_utf8_does_not_crash(tmp_path: Path) -> None:
    path = tmp_path / "bytes.log"
    line = b"Oct 21 14:03:11 web01 sshd[1]: Failed password for ro\xffot from 203.0.113.5 port 22\n"
    path.write_bytes(line)
    events = list(parse_ssh_file(path, ParseStats(), new_resolver()))
    assert len(events) == 1
    assert events[0].username == "ro\ufffdot"


def test_sample_file_parses_completely() -> None:
    stats = ParseStats()
    events = list(parse_ssh_file(DATA / "auth.log", stats, new_resolver()))
    assert stats.total_lines == 98
    assert stats.parsed_lines == 98
    assert stats.ignored_lines == 0
    assert stats.failed_lines == 0
    assert len(events) == 98


def test_sample_file_contains_brute_force_and_spray() -> None:
    events = list(parse_ssh_file(DATA / "auth.log", ParseStats(), new_resolver()))
    brute = [event for event in events if event.source_ip == "203.0.113.10"]
    spray = [event for event in events if event.source_ip == "203.0.113.20"]
    assert len(brute) == 12
    assert {event.username for event in brute} == {"root", "deploy"}
    assert len(spray) == 30
    assert len({event.username for event in spray}) == 15
    assert sum(event.event_type is SshEventType.INVALID_USER for event in spray) == 15


def test_rollover_sample_with_explicit_year() -> None:
    resolver = YearResolver(year=2025, now=NOW)
    events = list(parse_ssh_file(DATA / "auth_rollover.log", ParseStats(), resolver))
    assert len(events) == 8
    assert events[0].timestamp == datetime(2025, 12, 31, 23, 58, 30)
    assert events[-1].timestamp == datetime(2026, 1, 1, 0, 0, 50)
    assert {event.source_ip for event in events} == {"203.0.113.60"}


def test_rollover_sample_with_guessed_year() -> None:
    resolver = YearResolver(now=datetime(2026, 1, 5))
    events = list(parse_ssh_file(DATA / "auth_rollover.log", ParseStats(), resolver))
    assert events[0].timestamp == datetime(2025, 12, 31, 23, 58, 30)
    assert events[-1].timestamp == datetime(2026, 1, 1, 0, 0, 50)
    assert resolver.year_assumed is True
    assert resolver.first_year == 2025


def test_ipv6_scope_id_is_rejected() -> None:
    line = make_line("Failed password for root from fe80::1%\x1b[31m port 22 ssh2")
    assert parse(line) is Outcome.FAILED
