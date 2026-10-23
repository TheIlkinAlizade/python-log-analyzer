import json
from datetime import UTC, datetime
from pathlib import Path

from log_analyzer.models import Finding, LogType, ParseStats, Rule, Severity
from log_analyzer.report import (
    TOP_OFFENDERS,
    AnalysisResult,
    InputSummary,
    build_report,
    count_at_or_above,
    render_json,
    render_text,
)
from log_analyzer.rules import load_rules

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "default.yml"
SSH_TIME = datetime(2026, 3, 14, 8, 30, 0)
WEB_TIME = datetime(2026, 3, 14, 9, 15, 0, tzinfo=UTC)


def rules_by_id() -> dict[str, Rule]:
    return {rule.id: rule for rule in load_rules(DEFAULT_RULES)}


def make_finding(
    rule_id: str,
    severity: Severity,
    ip: str = "203.0.113.5",
    events: int = 3,
    distinct: int | None = None,
    evidence: tuple[str, ...] = ("x",),
    matched: tuple[str, ...] = (),
    moment: datetime = SSH_TIME,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        source_ip=ip,
        first_seen=moment,
        last_seen=moment,
        event_count=events,
        distinct_count=distinct,
        evidence=evidence,
        first_line=1,
        last_line=2,
        matched=matched,
    )


def make_result(findings: list[Finding], rule_ids: list[str] | None = None) -> AnalysisResult:
    rules = rules_by_id()
    ids = rule_ids if rule_ids is not None else sorted({item.rule_id for item in findings})
    stats = ParseStats(total_lines=10, parsed_lines=8, ignored_lines=1, failed_lines=1)
    result = AnalysisResult(
        inputs=[
            InputSummary(
                log_type=LogType.SSH,
                path="auth.log",
                stats=stats,
                year=2026,
                year_assumed=False,
            )
        ]
    )
    for rule_id in ids:
        result.rules.append(rules[rule_id])
        result.findings[rule_id] = [item for item in findings if item.rule_id == rule_id]
    return result


def test_severity_counts_and_threshold_gate() -> None:
    result = make_result(
        [
            make_finding("SSH-001", Severity.HIGH),
            make_finding("WEB-001", Severity.MEDIUM, ip="203.0.113.6", moment=WEB_TIME),
        ]
    )
    report = build_report(result, Severity.HIGH)
    assert report["summary"]["severity_counts"] == {
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 0,
    }
    assert report["summary"]["findings"] == 2
    assert count_at_or_above(result, Severity.LOW) == 2
    assert count_at_or_above(result, Severity.MEDIUM) == 2
    assert count_at_or_above(result, Severity.HIGH) == 1
    assert count_at_or_above(result, Severity.CRITICAL) == 0


def test_failed_flag_follows_fail_on() -> None:
    result = make_result([make_finding("SSH-001", Severity.HIGH)])
    high = build_report(result, Severity.HIGH)
    critical = build_report(result, Severity.CRITICAL)
    assert high["failed"] is True
    assert high["findings_at_or_above_fail_on"] == 1
    assert critical["failed"] is False
    assert critical["findings_at_or_above_fail_on"] == 0


def test_summary_totals_come_from_inputs() -> None:
    summary = build_report(make_result([]), Severity.HIGH)["summary"]
    assert summary["total_lines"] == 10
    assert summary["parsed_lines"] == 8
    assert summary["ignored_lines"] == 1
    assert summary["failed_lines"] == 1
    assert summary["rules_evaluated"] == 0
    assert summary["findings"] == 0


def test_rules_are_ordered_by_severity_then_id() -> None:
    result = make_result([], ["WEB-001", "SSH-002", "SSH-001"])
    report = build_report(result, Severity.HIGH)
    assert [rule["id"] for rule in report["rules"]] == ["SSH-001", "SSH-002", "WEB-001"]
    assert all(rule["finding_count"] == 0 for rule in report["rules"])


def test_top_offenders_are_ranked_and_limited() -> None:
    findings = [
        make_finding("SSH-001", Severity.HIGH, ip="203.0.113.1", events=5),
        make_finding("SSH-002", Severity.HIGH, ip="203.0.113.1", events=7),
        make_finding("SSH-001", Severity.HIGH, ip="203.0.113.2", events=50),
    ]
    findings += [
        make_finding("SSH-001", Severity.HIGH, ip=f"198.51.100.{number}", events=1)
        for number in range(1, 13)
    ]
    report = build_report(make_result(findings), Severity.HIGH)
    offenders = report["top_offenders"]
    assert len(offenders) == TOP_OFFENDERS
    assert [entry["source_ip"] for entry in offenders[:3]] == [
        "203.0.113.1",
        "203.0.113.2",
        "198.51.100.1",
    ]
    assert offenders[0]["findings"] == 2
    assert offenders[0]["events"] == 12
    assert offenders[0]["highest_severity"] == "high"


def test_untrusted_text_is_cleaned_in_every_output() -> None:
    finding = make_finding(
        "SSH-001",
        Severity.HIGH,
        ip="203.0.113.5\x1b[2J",
        evidence=("\x1b[31mroot\x1b[0m\nnext",),
        matched=("a\x07b",),
    )
    report = build_report(make_result([finding]), Severity.HIGH)
    item = report["rules"][0]["findings"][0]
    assert item["source_ip"] == "203.0.113.5"
    assert item["evidence"] == ["root?next"]
    assert item["matched"] == ["a?b"]
    assert report["top_offenders"][0]["source_ip"] == "203.0.113.5"
    for text in (render_text(report), render_json(report)):
        assert "\x1b" not in text
        assert "u001b" not in text
        assert "\x07" not in text


def test_text_report_sections() -> None:
    result = make_result(
        [
            make_finding(
                "SSH-002",
                Severity.HIGH,
                events=30,
                distinct=15,
                evidence=("admin", "test"),
            ),
            make_finding(
                "WEB-003",
                Severity.MEDIUM,
                ip="203.0.113.6",
                events=6,
                evidence=("sqlmap/1.7",),
                matched=("sqlmap",),
                moment=WEB_TIME,
            ),
        ]
    )
    result.warnings.append("year was assumed")
    text = render_text(build_report(result, Severity.HIGH))
    expected_parts = [
        "log-analyzer",
        "Inputs",
        "auth.log",
        "Warnings",
        "! year was assumed",
        "Findings: 2",
        "[HIGH] SSH-002",
        "[MEDIUM] WEB-003",
        "30 events, 15 distinct usernames",
        "MITRE ATT&CK: T1110.003, T1110.004",
        "matched: sqlmap",
        "Fix:",
        "Possible false positives:",
        "Top offending IPs",
        "Result: FAIL",
    ]
    for expected in expected_parts:
        assert expected in text
    assert all(char == "\n" or char.isprintable() for char in text)


def test_text_report_without_findings() -> None:
    text = render_text(build_report(make_result([], ["SSH-001"]), Severity.HIGH))
    assert "No findings." in text
    assert "Result: OK" in text
    assert "none" in text


def test_timestamps_and_time_basis() -> None:
    result = make_result(
        [
            make_finding("SSH-001", Severity.HIGH),
            make_finding("WEB-002", Severity.HIGH, moment=WEB_TIME),
        ]
    )
    report = build_report(result, Severity.HIGH)
    by_id = {rule["id"]: rule for rule in report["rules"]}
    ssh = by_id["SSH-001"]["findings"][0]
    web = by_id["WEB-002"]["findings"][0]
    assert ssh["first_seen"] == "2026-03-14T08:30:00"
    assert ssh["time_basis"] == "server_local"
    assert web["first_seen"] == "2026-03-14T09:15:00+00:00"
    assert web["time_basis"] == "utc"


def test_json_round_trip_and_determinism() -> None:
    result = make_result([make_finding("SSH-001", Severity.HIGH)])
    first = build_report(result, Severity.HIGH)
    second = build_report(result, Severity.HIGH)
    assert first == second
    assert json.loads(render_json(first)) == first
    assert render_json(first) == render_json(second)
