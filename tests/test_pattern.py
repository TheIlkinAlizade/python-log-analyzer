import re
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from log_analyzer.detectors.pattern import PatternDetector
from log_analyzer.models import (
    AccessEvent,
    Finding,
    LogType,
    MatchField,
    MatchSpec,
    ParseStats,
    PatternKind,
    PatternSpec,
    Rule,
    RuleType,
    Severity,
)
from log_analyzer.parsers.access import parse_access_file
from log_analyzer.rules import load_rules

TESTS = Path(__file__).resolve().parent
DATA = TESTS / "data"
DEFAULT_RULES = TESTS.parent / "rules" / "default.yml"
BASE = datetime(2026, 3, 14, 9, 0, 0, tzinfo=UTC)

PatternDef = tuple[PatternKind, str, str]
CONTAINS_DOTS: PatternDef = (PatternKind.CONTAINS, "dots", "../")
CONTAINS_SCRIPT: PatternDef = (PatternKind.CONTAINS, "script", "<script")


def make_rule(
    patterns: list[PatternDef],
    field: MatchField = MatchField.DECODED_URL,
    case_insensitive: bool = True,
) -> Rule:
    flags = re.IGNORECASE if case_insensitive else 0
    specs = tuple(
        PatternSpec(
            kind=kind,
            name=name,
            value=value,
            regex=re.compile(value, flags) if kind is PatternKind.REGEX else None,
        )
        for kind, name, value in patterns
    )
    return Rule(
        id="P-1",
        title="test",
        description="test",
        severity=Severity.HIGH,
        log_type=LogType.ACCESS,
        rule_type=RuleType.PATTERN,
        remediation="fix",
        false_positive_notes="none",
        mitre_attack=(),
        enabled=True,
        threshold=None,
        match=MatchSpec(field=field, case_insensitive=case_insensitive, patterns=specs),
    )


def make_event(
    url: str = "/",
    agent: str = "Mozilla/5.0",
    ip: str = "203.0.113.5",
    seconds: float = 0,
    line: int = 1,
) -> AccessEvent:
    return AccessEvent(
        line_number=line,
        source_ip=ip,
        timestamp=BASE + timedelta(seconds=seconds),
        method="GET",
        raw_url=url,
        decoded_url=url,
        protocol="HTTP/1.1",
        status=200,
        size=0,
        referer="-",
        user_agent=agent,
    )


def run(rule: Rule, events: list[AccessEvent]) -> list[Finding]:
    detector = PatternDetector(rule)
    for event in events:
        detector.feed(event)
    return detector.finish()


def load_default(rule_id: str) -> Rule:
    for rule in load_rules(DEFAULT_RULES):
        if rule.id == rule_id:
            return rule
    raise AssertionError(rule_id)


def web_sample() -> list[AccessEvent]:
    return list(parse_access_file(DATA / "access.log", ParseStats()))


def test_no_match_produces_nothing() -> None:
    assert run(make_rule([CONTAINS_DOTS]), [make_event("/index.html")]) == []


def test_single_match_produces_a_finding() -> None:
    (finding,) = run(make_rule([CONTAINS_DOTS]), [make_event("/a/../b", seconds=5, line=9)])
    assert finding.rule_id == "P-1"
    assert finding.severity is Severity.HIGH
    assert finding.source_ip == "203.0.113.5"
    assert finding.event_count == 1
    assert finding.distinct_count is None
    assert finding.first_seen == BASE + timedelta(seconds=5)
    assert finding.last_seen == BASE + timedelta(seconds=5)
    assert finding.first_line == 9
    assert finding.last_line == 9
    assert finding.evidence == ("/a/../b",)
    assert finding.matched == ("dots",)


def test_repeated_matches_from_one_ip_make_one_finding() -> None:
    events = [make_event(f"/a/../{index}", seconds=index, line=index + 1) for index in range(5)]
    (finding,) = run(make_rule([CONTAINS_DOTS]), events)
    assert finding.event_count == 5
    assert finding.first_line == 1
    assert finding.last_line == 5


def test_sources_are_reported_separately() -> None:
    events = [
        make_event("/../a", ip="203.0.113.2", seconds=10),
        make_event("/../b", ip="203.0.113.1", seconds=20),
    ]
    findings = run(make_rule([CONTAINS_DOTS]), events)
    assert [finding.source_ip for finding in findings] == ["203.0.113.2", "203.0.113.1"]


def test_event_matching_two_patterns_counts_once() -> None:
    (finding,) = run(make_rule([CONTAINS_DOTS, CONTAINS_SCRIPT]), [make_event("/x?<script>../")])
    assert finding.event_count == 1
    assert finding.matched == ("dots", "script")


def test_matched_names_follow_rule_order() -> None:
    events = [make_event("/<script>", seconds=0), make_event("/../", seconds=1)]
    (finding,) = run(make_rule([CONTAINS_DOTS, CONTAINS_SCRIPT]), events)
    assert finding.matched == ("dots", "script")


def test_case_insensitive_contains() -> None:
    assert len(run(make_rule([CONTAINS_SCRIPT]), [make_event("/<SCRIPT>")])) == 1


def test_case_sensitive_contains() -> None:
    rule = make_rule([CONTAINS_SCRIPT], case_insensitive=False)
    assert run(rule, [make_event("/<SCRIPT>")]) == []
    assert len(run(rule, [make_event("/<script>")])) == 1


def test_regex_pattern_matches_decoded_text() -> None:
    rule = make_rule([(PatternKind.REGEX, "union", r"union\s+select")])
    assert len(run(rule, [make_event("/q?1 UNION   SELECT 2")])) == 1
    assert run(rule, [make_event("/q?1 UNION ALL")]) == []


def test_user_agent_field_is_used() -> None:
    rule = make_rule([(PatternKind.CONTAINS, "sqlmap", "sqlmap")], MatchField.USER_AGENT)
    assert len(run(rule, [make_event(agent="sqlmap/1.7")])) == 1
    assert run(rule, [make_event(url="/sqlmap", agent="Mozilla/5.0")]) == []


def test_decoded_url_rule_ignores_user_agent() -> None:
    rule = make_rule([(PatternKind.CONTAINS, "sqlmap", "sqlmap")])
    assert run(rule, [make_event(agent="sqlmap/1.7")]) == []


def test_evidence_is_unique_and_capped() -> None:
    events = [make_event(f"/../{index % 7}", seconds=index) for index in range(14)]
    (finding,) = run(make_rule([CONTAINS_DOTS]), events)
    assert finding.event_count == 14
    assert finding.evidence == ("/../0", "/../1", "/../2", "/../3", "/../4")


def test_evidence_is_truncated() -> None:
    (finding,) = run(make_rule([CONTAINS_DOTS]), [make_event("/../" + "a" * 5000)])
    assert len(finding.evidence[0]) == 200


def test_out_of_order_events_use_earliest_and_latest() -> None:
    events = [
        make_event("/../a", seconds=50, line=2),
        make_event("/../b", seconds=10, line=1),
        make_event("/../c", seconds=90, line=3),
        make_event("/../d", seconds=30, line=4),
    ]
    (finding,) = run(make_rule([CONTAINS_DOTS]), events)
    assert finding.first_seen == BASE + timedelta(seconds=10)
    assert finding.first_line == 1
    assert finding.last_seen == BASE + timedelta(seconds=90)
    assert finding.last_line == 3


def test_source_limit_drops_new_sources_and_counts_them() -> None:
    detector = PatternDetector(make_rule([CONTAINS_DOTS]), max_sources=2)
    for index, ip in enumerate(["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.1"]):
        detector.feed(make_event("/../x", ip=ip, seconds=index))
    assert detector.tracked_sources == 2
    assert detector.untracked_events == 1
    findings = detector.finish()
    assert {finding.source_ip: finding.event_count for finding in findings} == {
        "203.0.113.1": 2,
        "203.0.113.2": 1,
    }


def test_finish_clears_state() -> None:
    detector = PatternDetector(make_rule([CONTAINS_DOTS]))
    detector.feed(make_event("/../x"))
    assert len(detector.finish()) == 1
    assert detector.tracked_sources == 0
    assert detector.finish() == []


def test_threshold_rule_is_rejected() -> None:
    rule = replace(make_rule([CONTAINS_DOTS]), rule_type=RuleType.THRESHOLD)
    with pytest.raises(ValueError, match="not a pattern rule"):
        PatternDetector(rule)


def test_rule_without_match_section_is_rejected() -> None:
    rule = replace(make_rule([CONTAINS_DOTS]), match=None)
    with pytest.raises(ValueError, match="not a pattern rule"):
        PatternDetector(rule)


def test_invalid_max_sources_is_rejected() -> None:
    with pytest.raises(ValueError, match="max_sources"):
        PatternDetector(make_rule([CONTAINS_DOTS]), max_sources=0)


def test_uncompiled_regex_is_rejected() -> None:
    rule = make_rule([CONTAINS_DOTS])
    assert rule.match is not None
    broken = PatternSpec(kind=PatternKind.REGEX, name="bad", value="x", regex=None)
    rule = replace(rule, match=replace(rule.match, patterns=(broken,)))
    with pytest.raises(ValueError, match="was not compiled"):
        PatternDetector(rule)


def test_default_rule_handles_long_adversarial_input_quickly() -> None:
    detector = PatternDetector(load_default("WEB-002"))
    payloads = [
        "/" + "a" * 8000,
        "/union" + " " * 8000,
        "/" + "union " * 1300,
        "/" + "<" * 8000,
        "/" + "." * 8000,
    ]
    started = time.perf_counter()
    for index, payload in enumerate(payloads * 40):
        detector.feed(make_event(payload, seconds=index))
    assert time.perf_counter() - started < 5.0


def test_sample_attack_strings_rule() -> None:
    events = web_sample()
    (finding,) = run(load_default("WEB-002"), events)
    attacker = "203.0.113.40"
    assert finding.source_ip == attacker
    assert sum(event.source_ip == attacker for event in events) == 8
    assert finding.event_count == 7
    assert finding.matched == ("sqli-union-select", "xss-script-tag", "path-traversal")
    assert finding.first_seen == datetime(2026, 3, 14, 9, 15, 0, tzinfo=UTC)
    assert finding.last_seen == datetime(2026, 3, 14, 9, 16, 0, tzinfo=UTC)
    assert len(finding.evidence) == 5
    assert finding.evidence[0] == "/search?q=1' UNION SELECT NULL,NULL--"


def test_sample_scanner_user_agent_rule() -> None:
    (finding,) = run(load_default("WEB-003"), web_sample())
    assert finding.source_ip == "203.0.113.50"
    assert finding.event_count == 6
    assert finding.matched == ("sqlmap", "nikto", "nmap")
    assert len(finding.evidence) == 3
    assert finding.evidence[0].startswith("sqlmap/1.7.2")
    assert finding.last_seen == datetime(2026, 3, 14, 9, 40, 45, tzinfo=UTC)
