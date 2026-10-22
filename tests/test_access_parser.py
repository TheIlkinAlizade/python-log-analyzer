import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from log_analyzer.models import ParseStats
from log_analyzer.parsers.access import parse_access_file, parse_access_line

SAMPLE = Path(__file__).resolve().parent / "data" / "access.log"


def make_line(
    ip: str = "203.0.113.5",
    stamp: str = "14/Mar/2026:08:00:01 +0000",
    request: str = "GET /index.html HTTP/1.1",
    status: str = "200",
    size: str = "512",
    referer: str = "-",
    agent: str = "Mozilla/5.0",
) -> str:
    return f'{ip} - - [{stamp}] "{request}" {status} {size} "{referer}" "{agent}"'


INVALID_LINES = [
    "",
    "garbage",
    make_line(ip="999.1.1.1"),
    make_line(ip="not-an-ip"),
    make_line(stamp="14/Foo/2026:08:00:01 +0000"),
    make_line(stamp="32/Mar/2026:08:00:01 +0000"),
    make_line(stamp="14/Mar/2026:25:00:01 +0000"),
    make_line(stamp="14/Mar/2026:08:00:01 +9999"),
    make_line(status="2OO"),
    make_line(size="abc"),
    make_line().rsplit(" ", 1)[0],
    make_line()[:-1],
]


def test_parses_valid_line() -> None:
    event = parse_access_line(make_line(), line_number=7)
    assert event is not None
    assert event.line_number == 7
    assert event.source_ip == "203.0.113.5"
    assert event.timestamp == datetime(2026, 3, 14, 8, 0, 1, tzinfo=UTC)
    assert event.method == "GET"
    assert event.raw_url == "/index.html"
    assert event.protocol == "HTTP/1.1"
    assert event.status == 200
    assert event.size == 512
    assert event.referer == "-"
    assert event.user_agent == "Mozilla/5.0"


def test_positive_offset_is_converted_to_utc() -> None:
    event = parse_access_line(make_line(stamp="14/Mar/2026:12:00:01 +0400"))
    assert event is not None
    assert event.timestamp == datetime(2026, 3, 14, 8, 0, 1, tzinfo=UTC)


def test_negative_offset_is_converted_to_utc() -> None:
    event = parse_access_line(make_line(stamp="14/Mar/2026:03:00:01 -0500"))
    assert event is not None
    assert event.timestamp == datetime(2026, 3, 14, 8, 0, 1, tzinfo=UTC)


def test_dash_size_becomes_zero() -> None:
    event = parse_access_line(make_line(size="-"))
    assert event is not None
    assert event.size == 0


def test_url_is_decoded_once() -> None:
    event = parse_access_line(make_line(request="GET /s?q=1%27%20UNION+SELECT HTTP/1.1"))
    assert event is not None
    assert event.raw_url == "/s?q=1%27%20UNION+SELECT"
    assert event.decoded_url == "/s?q=1' UNION SELECT"


def test_double_encoding_is_not_decoded_twice() -> None:
    event = parse_access_line(make_line(request="GET /a%252e%252e HTTP/1.1"))
    assert event is not None
    assert event.decoded_url == "/a%2e%2e"


def test_spaces_inside_request_target_are_kept() -> None:
    event = parse_access_line(make_line(request="GET /a b c HTTP/1.1"))
    assert event is not None
    assert event.method == "GET"
    assert event.raw_url == "/a b c"
    assert event.protocol == "HTTP/1.1"


def test_garbage_request_is_kept_as_url() -> None:
    event = parse_access_line(make_line(request="-"))
    assert event is not None
    assert event.method == ""
    assert event.raw_url == "-"
    assert event.protocol == ""


def test_ipv6_is_normalised() -> None:
    event = parse_access_line(make_line(ip="2001:DB8::1"))
    assert event is not None
    assert event.source_ip == "2001:db8::1"


def test_escaped_quote_in_user_agent() -> None:
    event = parse_access_line(make_line(agent='Evil\\"Agent'))
    assert event is not None
    assert event.user_agent == 'Evil\\"Agent'


@pytest.mark.parametrize("line", INVALID_LINES)
def test_invalid_lines_return_none(line: str) -> None:
    assert parse_access_line(line) is None


def test_adversarial_lines_finish_quickly() -> None:
    prefix = '203.0.113.5 - - [14/Mar/2026:08:00:01 +0000] "'
    candidates = [
        prefix + "\\" * 8000,
        prefix + '\\"' * 4000,
        prefix + '"' * 8000,
        "1.1.1.1 " * 1000,
    ]
    started = time.perf_counter()
    for line in candidates:
        assert parse_access_line(line) is None
    assert time.perf_counter() - started < 1.0


def test_file_counts_blank_garbage_and_oversized(tmp_path: Path) -> None:
    path = tmp_path / "mixed.log"
    content = "\n".join(
        [
            make_line(),
            "",
            "garbage",
            "x" * 5000,
            make_line(ip="203.0.113.6"),
        ]
    )
    path.write_text(content + "\n", encoding="utf-8")
    stats = ParseStats()
    events = list(parse_access_file(path, stats, max_line_length=200))
    assert [event.source_ip for event in events] == ["203.0.113.5", "203.0.113.6"]
    assert stats.total_lines == 4
    assert stats.parsed_lines == 2
    assert stats.failed_lines == 2
    assert stats.oversized_lines == 1


def test_invalid_utf8_does_not_crash(tmp_path: Path) -> None:
    path = tmp_path / "bytes.log"
    path.write_bytes(make_line(agent="bad").encode().replace(b"bad", b"\xff\xfe") + b"\n")
    stats = ParseStats()
    events = list(parse_access_file(path, stats))
    assert len(events) == 1
    assert "\ufffd" in events[0].user_agent
    assert stats.failed_lines == 0


def test_sample_file_parses_completely() -> None:
    stats = ParseStats()
    events = list(parse_access_file(SAMPLE, stats))
    assert stats.total_lines == 491
    assert stats.parsed_lines == 491
    assert stats.failed_lines == 0
    assert len(events) == 491


def test_sample_file_contains_injected_scan() -> None:
    events = list(parse_access_file(SAMPLE, ParseStats()))
    scan = [event for event in events if event.source_ip == "203.0.113.30"]
    assert len(scan) == 45
    assert all(event.status == 404 for event in scan)


def test_sample_file_decodes_traversal_payload() -> None:
    events = list(parse_access_file(SAMPLE, ParseStats()))
    decoded = {event.decoded_url for event in events if event.source_ip == "203.0.113.40"}
    assert "/download?file=../../../etc/passwd" in decoded
