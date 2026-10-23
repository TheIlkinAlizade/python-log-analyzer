import json
from dataclasses import dataclass, field
from typing import Any

from log_analyzer import __version__
from log_analyzer.models import Finding, LogType, ParseStats, Rule, Severity
from log_analyzer.sanitize import clean

TOP_OFFENDERS = 10
TIME_BASIS = {LogType.SSH: "server_local", LogType.ACCESS: "utc"}
TIME_LABEL = {"server_local": "server local time", "utc": "UTC"}
NOTE = (
    "Note: findings come only from the supplied logs and the active rules. "
    "No findings does not prove that no attack happened."
)


@dataclass(frozen=True, slots=True)
class InputSummary:
    log_type: LogType
    path: str
    stats: ParseStats
    year: int | None
    year_assumed: bool


@dataclass(slots=True)
class AnalysisResult:
    inputs: list[InputSummary] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    findings: dict[str, list[Finding]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Offender:
    findings: int = 0
    events: int = 0
    top: Severity = Severity.LOW


def count_at_or_above(result: AnalysisResult, threshold: Severity) -> int:
    return sum(
        1
        for findings in result.findings.values()
        for finding in findings
        if finding.severity.rank >= threshold.rank
    )


def severity_counts(result: AnalysisResult) -> dict[str, int]:
    counts = {severity.value: 0 for severity in reversed(list(Severity))}
    for findings in result.findings.values():
        for finding in findings:
            counts[finding.severity.value] += 1
    return counts


def input_dict(item: InputSummary) -> dict[str, Any]:
    stats = item.stats
    return {
        "log_type": item.log_type.value,
        "path": clean(item.path),
        "total_lines": stats.total_lines,
        "parsed_lines": stats.parsed_lines,
        "ignored_lines": stats.ignored_lines,
        "failed_lines": stats.failed_lines,
        "oversized_lines": stats.oversized_lines,
        "year": item.year,
        "year_assumed": item.year_assumed,
    }


def finding_dict(rule: Rule, finding: Finding) -> dict[str, Any]:
    return {
        "source_ip": clean(finding.source_ip),
        "first_seen": finding.first_seen.isoformat(),
        "last_seen": finding.last_seen.isoformat(),
        "time_basis": TIME_BASIS[rule.log_type],
        "event_count": finding.event_count,
        "distinct_count": finding.distinct_count,
        "matched": [clean(item) for item in finding.matched],
        "evidence": [clean(item) for item in finding.evidence],
        "first_line": finding.first_line,
        "last_line": finding.last_line,
    }


def rule_dict(rule: Rule, findings: list[Finding]) -> dict[str, Any]:
    return {
        "id": clean(rule.id),
        "title": clean(rule.title),
        "description": clean(rule.description),
        "severity": rule.severity.value,
        "log_type": rule.log_type.value,
        "mitre_attack": [clean(item) for item in rule.mitre_attack],
        "remediation": clean(rule.remediation),
        "false_positive_notes": clean(rule.false_positive_notes),
        "finding_count": len(findings),
        "findings": [finding_dict(rule, finding) for finding in findings],
    }


def offender_table(result: AnalysisResult) -> list[dict[str, Any]]:
    table: dict[str, Offender] = {}
    for findings in result.findings.values():
        for finding in findings:
            entry = table.setdefault(finding.source_ip, Offender())
            entry.findings += 1
            entry.events += finding.event_count
            if finding.severity.rank > entry.top.rank:
                entry.top = finding.severity
    ranked = sorted(
        table.items(),
        key=lambda item: (-item[1].top.rank, -item[1].findings, -item[1].events, item[0]),
    )
    return [
        {
            "source_ip": clean(ip),
            "highest_severity": entry.top.value,
            "findings": entry.findings,
            "events": entry.events,
        }
        for ip, entry in ranked[:TOP_OFFENDERS]
    ]


def build_report(result: AnalysisResult, fail_on: Severity) -> dict[str, Any]:
    ordered = sorted(result.rules, key=lambda rule: (-rule.severity.rank, rule.id))
    gated = count_at_or_above(result, fail_on)
    stats = [item.stats for item in result.inputs]
    return {
        "tool": "log-analyzer",
        "version": __version__,
        "inputs": [input_dict(item) for item in result.inputs],
        "summary": {
            "total_lines": sum(item.total_lines for item in stats),
            "parsed_lines": sum(item.parsed_lines for item in stats),
            "ignored_lines": sum(item.ignored_lines for item in stats),
            "failed_lines": sum(item.failed_lines for item in stats),
            "rules_evaluated": len(result.rules),
            "findings": sum(len(findings) for findings in result.findings.values()),
            "severity_counts": severity_counts(result),
        },
        "fail_on": fail_on.value,
        "findings_at_or_above_fail_on": gated,
        "failed": gated > 0,
        "warnings": [clean(item) for item in result.warnings],
        "rules": [rule_dict(rule, result.findings.get(rule.id, [])) for rule in ordered],
        "top_offenders": offender_table(result),
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2)


def input_lines(item: dict[str, Any]) -> list[str]:
    lines = [
        f"  {item['log_type']:<7} {item['path']}",
        f"          lines {item['total_lines']}, parsed {item['parsed_lines']}, "
        f"ignored {item['ignored_lines']}, failed {item['failed_lines']} "
        f"(oversized {item['oversized_lines']})",
    ]
    if item["year"] is not None:
        origin = "assumed, use --year to set it" if item["year_assumed"] else "set with --year"
        lines.append(f"          year {item['year']} ({origin})")
    return lines


def finding_lines(finding: dict[str, Any]) -> list[str]:
    label = TIME_LABEL[finding["time_basis"]]
    head = f"  - {finding['source_ip']}: {finding['event_count']} events"
    if finding["distinct_count"] is not None:
        head += f", {finding['distinct_count']} distinct usernames"
    lines = [
        head,
        f"    {finding['first_seen']} -> {finding['last_seen']} ({label}), "
        f"log lines {finding['first_line']}-{finding['last_line']}",
    ]
    if finding["matched"]:
        lines.append(f"    matched: {', '.join(finding['matched'])}")
    if finding["evidence"]:
        lines.append("    examples:")
        lines.extend(f"      {item}" for item in finding["evidence"])
    return lines


def rule_lines(rule: dict[str, Any]) -> list[str]:
    count = rule["finding_count"]
    noun = "finding" if count == 1 else "findings"
    lines = [
        "",
        f"[{rule['severity'].upper()}] {rule['id']}  {rule['title']}  ({count} {noun})",
        f"  {rule['description']}",
    ]
    if rule["mitre_attack"]:
        lines.append(f"  MITRE ATT&CK: {', '.join(rule['mitre_attack'])}")
    for finding in rule["findings"]:
        lines.extend(finding_lines(finding))
    lines.append(f"  Fix: {rule['remediation']}")
    lines.append(f"  Possible false positives: {rule['false_positive_notes']}")
    return lines


def render_text(report: dict[str, Any]) -> str:
    summary = report["summary"]
    title = f"log-analyzer {report['version']}"
    lines = [title, "=" * len(title), "", "Inputs"]
    for item in report["inputs"]:
        lines.extend(input_lines(item))
    lines.append(
        f"  total   lines {summary['total_lines']}, parsed {summary['parsed_lines']}, "
        f"ignored {summary['ignored_lines']}, failed {summary['failed_lines']}"
    )
    if report["warnings"]:
        lines.extend(["", "Warnings"])
        lines.extend(f"  ! {warning}" for warning in report["warnings"])
    counts = ", ".join(f"{name} {count}" for name, count in summary["severity_counts"].items())
    lines.extend(["", f"Findings: {summary['findings']}  ({counts})"])
    fired = [rule for rule in report["rules"] if rule["finding_count"] > 0]
    if not fired:
        lines.append("  No findings.")
    for rule in fired:
        lines.extend(rule_lines(rule))
    lines.extend(["", "Top offending IPs"])
    offenders = report["top_offenders"]
    if not offenders:
        lines.append("  none")
    for position, entry in enumerate(offenders, start=1):
        lines.append(
            f"  {position}. {entry['source_ip']}  highest {entry['highest_severity']}, "
            f"findings {entry['findings']}, events {entry['events']}"
        )
    lines.append("")
    if report["failed"]:
        lines.append(
            f"Result: FAIL - {report['findings_at_or_above_fail_on']} finding(s) "
            f"at or above '{report['fail_on']}'"
        )
    else:
        lines.append(f"Result: OK - no findings at or above '{report['fail_on']}'")
    lines.append(NOTE)
    return "\n".join(lines)
