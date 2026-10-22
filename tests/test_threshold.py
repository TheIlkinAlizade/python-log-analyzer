from collections.abc import Iterable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from log_analyzer.detectors.threshold import ThresholdDetector
from log_analyzer.models import (
    AccessEvent,
    Finding,
    LogType,
    ParseStats,
    Rule,
    RuleType,
    Severity,
    SshEvent,
    SshEventType,
    ThresholdSpec,
)
from log_analyzer.parsers.access import parse_access_file
from log_analyzer.parsers.ssh import YearResolver, parse_ssh_file
from log_analyzer.rules import load_rules

TESTS = Path(__file__).resolve().parent
DATA = TESTS / "data"
DEFAULT_RULES = TESTS.parent / "rules" / "default.yml"
BASE = datetime(2026, 3, 14, 8, 0, 0)
FAILED = (SshEventType.FAILED_PASSWORD,)


def make_rule(spec: ThresholdSpec, log_type: LogType) -> Rule:
    return Rule(
        id="T-1",
        title="test",
        description="test",
        severity=Severity.HIGH,
        log_type=log_type,
        rule_type=RuleType.THRESHOLD,
        remediation="fix",
        false_positive_notes="none",
        mitre_attack=(),
        enabled=True,
        threshold=spec,
        match=None,
    )


def ssh_rule(
    count: int = 3,
    minutes: int = 1,
    distinct: str | None = None,
    events: tuple[SshEventType, ...] = FAILED,
) -> Rule:
    spec = ThresholdSpec(
        count=count, window_minutes=minutes, events=events, statuses=(), distinct=distinct
    )
    return make_rule(spec, LogType.SSH)


def web_rule(count: int = 3, minutes: int = 1) -> Rule:
    spec = ThresholdSpec(
        count=count, window_minutes=minutes, events=(), statuses=(404,), distinct=None
    )
    return make_rule(spec, LogType.ACCESS)


def ssh_event(
    seconds: float,
    ip: str = "203.0.113.5",
    user: str = "root",
    kind: SshEventType = SshEventType.FAILED_PASSWORD,
    line: int = 1,
) -> SshEvent:
    return SshEvent(
        line_number=line,
        timestamp=BASE + timedelta(seconds=seconds),
        hostname="web01",
        pid=1,
        event_type=kind,
        username=user,
        source_ip=ip,
        port=22,
    )


def web_event(
    seconds: float,
    ip: str = "203.0.113.5",
    status: int = 404,
    url: str = "/x",
    line: int = 1,
) -> AccessEvent:
    return AccessEvent(
        line_number=line,
        source_ip=ip,
        timestamp=BASE.replace(tzinfo=UTC) + timedelta(seconds=seconds),
        method="GET",
        raw_url=url,
        decoded_url=url,
        protocol="HTTP/1.1",
        status=status,
        size=0,
        referer="-",
        user_agent="ua",
    )


def run(rule: Rule, events: Iterable[SshEvent | AccessEvent]) -> list[Finding]:
    detector = ThresholdDetector(rule)
    for event in events:
        detector.feed(event)
    return detector.finish()


def load_default(rule_id: str) -> Rule:
    for rule in load_rules(DEFAULT_RULES):
        if rule.id == rule_id:
            return rule
    raise AssertionError(rule_id)


def ssh_sample(name: str, year: int = 2026) -> list[SshEvent]:
    return list(parse_ssh_file(DATA / name, ParseStats(), YearResolver(year=year)))


def web_sample() -> list[AccessEvent]:
    return list(parse_access_file(DATA / "access.log", ParseStats()))


def test_below_threshold_produces_nothing() -> None:
    assert run(ssh_rule(), [ssh_event(0), ssh_event(10)]) == []


def test_exact_threshold_produces_one_finding() -> None:
    events = [ssh_event(0, line=1), ssh_event(10, line=2), ssh_event(20, line=3)]
    (finding,) = run(ssh_rule(), events)
    assert finding.rule_id == "T-1"
    assert finding.severity is Severity.HIGH
    assert finding.source_ip == "203.0.113.5"
    assert finding.event_count == 3
    assert finding.distinct_count is None
    assert finding.first_seen == BASE
    assert finding.last_seen == BASE + timedelta(seconds=20)
    assert finding.first_line == 1
    assert finding.last_line == 3
    assert finding.evidence == ("root",)


def test_events_spread_beyond_window_do_not_trigger() -> None:
    assert run(ssh_rule(), [ssh_event(0), ssh_event(40), ssh_event(80)]) == []


def test_window_boundary_is_inclusive() -> None:
    assert len(run(ssh_rule(), [ssh_event(0), ssh_event(30), ssh_event(60)])) == 1


def test_one_second_past_the_boundary_does_not_trigger() -> None:
    assert run(ssh_rule(), [ssh_event(0), ssh_event(30), ssh_event(61)]) == []


def test_single_burst_produces_single_finding() -> None:
    events = [ssh_event(index * 5, line=index + 1) for index in range(12)]
    (finding,) = run(ssh_rule(count=5, minutes=5), events)
    assert finding.event_count == 12
    assert finding.first_line == 1
    assert finding.last_line == 12


def test_burst_ends_after_a_quiet_window() -> None:
    first = [ssh_event(index) for index in range(5)]
    second = [ssh_event(300 + index) for index in range(5)]
    findings = run(ssh_rule(count=5), first + second)
    assert [finding.first_seen for finding in findings] == [
        BASE,
        BASE + timedelta(seconds=300),
    ]
    assert [finding.event_count for finding in findings] == [5, 5]


def test_trickle_after_threshold_stays_in_the_same_burst() -> None:
    times = [0, 1, 2, 50, 100, 150]
    (finding,) = run(ssh_rule(), [ssh_event(seconds) for seconds in times])
    assert finding.event_count == 6


def test_sources_are_tracked_separately() -> None:
    events = [
        ssh_event(0, ip="203.0.113.1"),
        ssh_event(1, ip="203.0.113.2"),
        ssh_event(2, ip="203.0.113.1"),
        ssh_event(3, ip="203.0.113.2"),
    ]
    assert run(ssh_rule(), events) == []


def test_other_event_types_are_ignored() -> None:
    events = [ssh_event(index, kind=SshEventType.ACCEPTED_PASSWORD) for index in range(5)]
    assert run(ssh_rule(), events) == []


def test_distinct_ignores_repeated_username() -> None:
    events = [ssh_event(index) for index in range(10)]
    assert run(ssh_rule(distinct="username"), events) == []


def test_distinct_counts_unique_usernames() -> None:
    events = [ssh_event(index, user=f"user{index}") for index in range(3)]
    (finding,) = run(ssh_rule(distinct="username"), events)
    assert finding.distinct_count == 3
    assert finding.event_count == 3


def test_distinct_forgets_usernames_outside_the_window() -> None:
    events = [ssh_event(0, user="a"), ssh_event(10, user="b"), ssh_event(100, user="c")]
    assert run(ssh_rule(distinct="username"), events) == []


def test_distinct_reports_peak_and_total_events() -> None:
    events = [ssh_event(index, user=f"u{index // 2}") for index in range(10)]
    (finding,) = run(ssh_rule(distinct="username"), events)
    assert finding.distinct_count == 5
    assert finding.event_count == 10


def test_evidence_is_unique_and_capped() -> None:
    events = [ssh_event(index, user=f"u{index}") for index in range(8)]
    (finding,) = run(ssh_rule(distinct="username"), events)
    assert finding.evidence == ("u0", "u1", "u2", "u3", "u4")


def test_web_threshold_uses_status_and_reports_urls() -> None:
    events = [
        web_event(0, url="/a"),
        web_event(1, url="/b", status=200),
        web_event(2, url="/c"),
        web_event(3, url="/d"),
    ]
    (finding,) = run(web_rule(), events)
    assert finding.event_count == 3
    assert finding.evidence == ("/a", "/c", "/d")


def test_count_of_one_splits_on_quiet_gap() -> None:
    events = [ssh_event(0), ssh_event(10), ssh_event(600)]
    findings = run(ssh_rule(count=1), events)
    assert [finding.event_count for finding in findings] == [2, 1]


def test_out_of_order_timestamps_are_clamped() -> None:
    events = [ssh_event(10), ssh_event(5), ssh_event(8)]
    (finding,) = run(ssh_rule(), events)
    assert finding.event_count == 3
    assert finding.first_seen == BASE + timedelta(seconds=10)
    assert finding.last_seen == BASE + timedelta(seconds=10)


def test_large_burst_counts_every_event() -> None:
    events = [ssh_event(index * 0.01) for index in range(5000)]
    (finding,) = run(ssh_rule(count=5), events)
    assert finding.event_count == 5000


def test_cleanup_closes_stale_bursts_and_frees_state() -> None:
    detector = ThresholdDetector(ssh_rule(), cleanup_interval=4)
    for event in [
        ssh_event(0),
        ssh_event(1),
        ssh_event(2),
        ssh_event(600, ip="203.0.113.99"),
    ]:
        detector.feed(event)
    assert len(detector.findings) == 1
    assert detector.tracked_sources == 1
    (finding,) = detector.finish()
    assert finding.source_ip == "203.0.113.5"
    assert detector.tracked_sources == 0


def test_findings_are_sorted_by_first_seen() -> None:
    late = [ssh_event(100 + index, ip="203.0.113.1") for index in range(3)]
    early = [ssh_event(index, ip="203.0.113.2") for index in range(3)]
    findings = run(ssh_rule(), late + early)
    assert [finding.source_ip for finding in findings] == ["203.0.113.2", "203.0.113.1"]


def test_pattern_rule_is_rejected() -> None:
    with pytest.raises(ValueError, match="not a threshold rule"):
        ThresholdDetector(replace(ssh_rule(), rule_type=RuleType.PATTERN))


def test_invalid_cleanup_interval_is_rejected() -> None:
    with pytest.raises(ValueError, match="cleanup_interval"):
        ThresholdDetector(ssh_rule(), cleanup_interval=0)


def test_sample_ssh_brute_force_rule() -> None:
    findings = run(load_default("SSH-001"), ssh_sample("auth.log"))
    by_ip = {finding.source_ip: finding for finding in findings}
    assert len(findings) == 2
    assert set(by_ip) == {"203.0.113.10", "203.0.113.20"}
    assert by_ip["203.0.113.10"].event_count == 12
    assert by_ip["203.0.113.10"].evidence == ("root", "deploy")
    assert by_ip["203.0.113.20"].event_count == 15


def test_sample_ssh_spraying_rule() -> None:
    (finding,) = run(load_default("SSH-002"), ssh_sample("auth.log"))
    assert finding.source_ip == "203.0.113.20"
    assert finding.distinct_count == 15
    assert finding.event_count == 30
    assert finding.evidence == ("admin", "test", "user", "oracle", "postgres")


def test_sample_web_scanning_rule_includes_the_crawler_false_positive() -> None:
    findings = run(load_default("WEB-001"), web_sample())
    counts = {finding.source_ip: finding.event_count for finding in findings}
    assert counts == {"203.0.113.30": 45, "198.51.100.99": 32}


def test_sample_rollover_burst_crosses_new_year() -> None:
    events = ssh_sample("auth_rollover.log", year=2025)
    (finding,) = run(load_default("SSH-001"), events)
    assert finding.event_count == 8
    assert finding.first_seen == datetime(2025, 12, 31, 23, 58, 30)
    assert finding.last_seen == datetime(2026, 1, 1, 0, 0, 50)
