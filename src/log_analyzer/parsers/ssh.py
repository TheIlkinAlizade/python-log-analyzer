import re
from collections.abc import Iterator
from datetime import datetime
from enum import Enum
from pathlib import Path

from log_analyzer.models import ParseStats, SshEvent, SshEventType
from log_analyzer.parsers.access import MONTHS, normalize_ip
from log_analyzer.parsers.common import DEFAULT_MAX_LINE_LENGTH, iter_lines

SSHD_PROCESSES = frozenset({"sshd", "sshd-session"})
TRACKED_PREFIXES = ("Failed password for ", "Accepted password for ", "Invalid user ")
ROLLOVER_MONTH_DROP = 6
MAX_GUESS_YEARS = 8
MAX_PORT = 65535

HEADER_PATTERN = re.compile(
    r"^([A-Za-z]{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) "
    r"([^\s\[:]+)(?:\[(\d{1,10})\])?: (.*)$"
)

FAILED_PATTERN = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
    r"(?: port (?P<port>\d{1,5}))?(?: ssh2)?$"
)
ACCEPTED_PATTERN = re.compile(
    r"^Accepted password for (?P<user>\S+) from (?P<ip>\S+)"
    r"(?: port (?P<port>\d{1,5}))?(?: ssh2)?$"
)
INVALID_PATTERN = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d{1,5}))?$"
)

EVENT_PATTERNS = (
    (SshEventType.FAILED_PASSWORD, FAILED_PATTERN),
    (SshEventType.ACCEPTED_PASSWORD, ACCEPTED_PATTERN),
    (SshEventType.INVALID_USER, INVALID_PATTERN),
)


class Outcome(Enum):
    IGNORED = "ignored"
    FAILED = "failed"


class YearResolver:
    def __init__(self, year: int | None = None, now: datetime | None = None) -> None:
        self.now = now if now is not None else datetime.now()
        self.year_assumed = year is None
        self.first_year: int | None = None
        self.current_year: int | None = year
        self.last_month: int | None = None

    def resolve(self, month: int, day: int, hour: int, minute: int, second: int) -> datetime | None:
        year = self.current_year
        if year is None:
            year = self.guess_year(month, day, hour, minute, second)
            if year is None:
                return None
        elif self.last_month is not None and self.last_month - month > ROLLOVER_MONTH_DROP:
            year += 1
        try:
            moment = datetime(year, month, day, hour, minute, second)
        except ValueError:
            return None
        self.current_year = year
        self.last_month = month
        if self.first_year is None:
            self.first_year = year
        return moment

    def guess_year(self, month: int, day: int, hour: int, minute: int, second: int) -> int | None:
        year = self.now.year
        for _ in range(MAX_GUESS_YEARS):
            try:
                candidate = datetime(year, month, day, hour, minute, second)
            except ValueError:
                year -= 1
                continue
            if candidate <= self.now:
                return year
            year -= 1
        return None


def match_message(message: str) -> tuple[SshEventType, re.Match[str]] | None:
    for event_type, pattern in EVENT_PATTERNS:
        match = pattern.match(message)
        if match is not None:
            return event_type, match
    return None


def parse_ssh_line(line: str, line_number: int, resolver: YearResolver) -> SshEvent | Outcome:
    header = HEADER_PATTERN.match(line)
    if header is None:
        return Outcome.FAILED
    month_name, day, hour, minute, second, hostname, process, pid_text, message = header.groups()
    month = MONTHS.get(month_name)
    if month is None:
        return Outcome.FAILED
    timestamp = resolver.resolve(month, int(day), int(hour), int(minute), int(second))
    if timestamp is None:
        return Outcome.FAILED
    if process not in SSHD_PROCESSES:
        return Outcome.IGNORED
    found = match_message(message)
    if found is None:
        return Outcome.FAILED if message.startswith(TRACKED_PREFIXES) else Outcome.IGNORED
    event_type, match = found
    source_ip = normalize_ip(match.group("ip"))
    if source_ip is None:
        return Outcome.FAILED
    port_text = match.group("port")
    port = int(port_text) if port_text is not None else None
    if port is not None and port > MAX_PORT:
        return Outcome.FAILED
    return SshEvent(
        line_number=line_number,
        timestamp=timestamp,
        hostname=hostname,
        pid=int(pid_text) if pid_text is not None else None,
        event_type=event_type,
        username=match.group("user"),
        source_ip=source_ip,
        port=port,
    )


def parse_ssh_file(
    path: Path,
    stats: ParseStats,
    resolver: YearResolver,
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
) -> Iterator[SshEvent]:
    for raw in iter_lines(path, max_line_length):
        if not raw.oversized and not raw.text.strip():
            continue
        stats.total_lines += 1
        if raw.oversized:
            stats.oversized_lines += 1
            stats.failed_lines += 1
            continue
        outcome = parse_ssh_line(raw.text, raw.number, resolver)
        if isinstance(outcome, Outcome):
            if outcome is Outcome.IGNORED:
                stats.ignored_lines += 1
            else:
                stats.failed_lines += 1
            continue
        stats.parsed_lines += 1
        yield outcome
