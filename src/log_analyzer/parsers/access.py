import ipaddress
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote_plus

from log_analyzer.models import AccessEvent, ParseStats
from log_analyzer.parsers.common import DEFAULT_MAX_LINE_LENGTH, iter_lines

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

QUOTED = r'"((?:[^"\\]|\\.)*)"'

LINE_PATTERN = re.compile(
    rf"^(\S+) \S+ \S+ \[([^\]]*)\] {QUOTED} (\d{{3}}) (\d{{1,12}}|-) {QUOTED} {QUOTED}$"
)

TIMESTAMP_PATTERN = re.compile(
    r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$"
)


def normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_timestamp(value: str) -> datetime | None:
    match = TIMESTAMP_PATTERN.match(value)
    if match is None:
        return None
    day, month_name, year, hour, minute, second, sign, offset_hours, offset_minutes = match.groups()
    month = MONTHS.get(month_name)
    if month is None or int(offset_minutes) > 59:
        return None
    offset = timedelta(hours=int(offset_hours), minutes=int(offset_minutes))
    if sign == "-":
        offset = -offset
    try:
        local = datetime(
            int(year),
            month,
            int(day),
            int(hour),
            int(minute),
            int(second),
            tzinfo=timezone(offset),
        )
    except ValueError:
        return None
    return local.astimezone(UTC)


def split_request(request: str) -> tuple[str, str, str]:
    parts = request.split(" ")
    if len(parts) >= 3:
        return parts[0], " ".join(parts[1:-1]), parts[-1]
    return "", request, ""


def parse_access_line(line: str, line_number: int = 0) -> AccessEvent | None:
    match = LINE_PATTERN.match(line)
    if match is None:
        return None
    ip_text, time_text, request, status_text, size_text, referer, user_agent = match.groups()
    source_ip = normalize_ip(ip_text)
    timestamp = parse_timestamp(time_text)
    if source_ip is None or timestamp is None:
        return None
    method, raw_url, protocol = split_request(request)
    return AccessEvent(
        line_number=line_number,
        source_ip=source_ip,
        timestamp=timestamp,
        method=method,
        raw_url=raw_url,
        decoded_url=unquote_plus(raw_url),
        protocol=protocol,
        status=int(status_text),
        size=0 if size_text == "-" else int(size_text),
        referer=referer,
        user_agent=user_agent,
    )


def parse_access_file(
    path: Path,
    stats: ParseStats,
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
) -> Iterator[AccessEvent]:
    for raw in iter_lines(path, max_line_length):
        if not raw.oversized and not raw.text.strip():
            continue
        stats.total_lines += 1
        if raw.oversized:
            stats.oversized_lines += 1
            stats.failed_lines += 1
            continue
        event = parse_access_line(raw.text, raw.number)
        if event is None:
            stats.failed_lines += 1
            continue
        stats.parsed_lines += 1
        yield event
