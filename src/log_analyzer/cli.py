import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from log_analyzer import __version__
from log_analyzer.detectors.pattern import PatternDetector
from log_analyzer.detectors.threshold import ThresholdDetector
from log_analyzer.models import LogType, ParseStats, Rule, RuleType, Severity
from log_analyzer.parsers.access import parse_access_file
from log_analyzer.parsers.ssh import YearResolver, parse_ssh_file
from log_analyzer.report import (
    AnalysisResult,
    InputSummary,
    build_report,
    count_at_or_above,
    render_json,
    render_text,
)
from log_analyzer.rules import RuleError, load_rules
from log_analyzer.sanitize import clean

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
DEFAULT_RULES_PATH = Path("rules/default.yml")
MIN_YEAR = 1970
MAX_YEAR = 2100

Detector = ThresholdDetector | PatternDetector


def year_type(value: str) -> int:
    try:
        year = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid year: {value!r}") from error
    if not MIN_YEAR <= year <= MAX_YEAR:
        raise argparse.ArgumentTypeError(f"year must be between {MIN_YEAR} and {MAX_YEAR}")
    return year


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description=(
            "Offline analyzer for web server and SSH logs. Defensive use only. "
            "Reads local files and makes no network requests."
        ),
        epilog=(
            "Exit codes: 0 = no findings at or above --fail-on, "
            "1 = findings at or above --fail-on, 2 = usage or input error."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--access-log", type=Path, metavar="PATH", help="nginx/Apache combined access log"
    )
    parser.add_argument("--ssh-log", type=Path, metavar="PATH", help="SSH auth.log (syslog format)")
    parser.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULES_PATH,
        metavar="PATH",
        help="rules file (default: rules/default.yml, relative to the current directory)",
    )
    parser.add_argument(
        "--year",
        type=year_type,
        metavar="YYYY",
        help="year of the first line of the SSH log (syslog timestamps have no year)",
    )
    parser.add_argument(
        "--fail-on",
        choices=[severity.value for severity in Severity],
        default=Severity.HIGH.value,
        help="exit with code 1 if any finding has at least this severity (default: high)",
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    return parser


def emit(text: str, stream: TextIO) -> None:
    line = f"{text}\n"
    try:
        stream.write(line)
    except UnicodeEncodeError:
        encoding = stream.encoding or "ascii"
        stream.write(line.encode(encoding, errors="replace").decode(encoding))


def print_error(message: str) -> None:
    print(f"error: {clean(message)}", file=sys.stderr)


def input_problems(access_log: Path | None, ssh_log: Path | None) -> list[str]:
    problems: list[str] = []
    for label, path in (("--access-log", access_log), ("--ssh-log", ssh_log)):
        if path is not None and not path.is_file():
            problems.append(f"{label}: not a readable file: {path}")
    return problems


def select_rules(rules: list[Rule], log_type: LogType) -> list[Rule]:
    return [rule for rule in rules if rule.enabled and rule.log_type is log_type]


def finish_detectors(detectors: Sequence[Detector], result: AnalysisResult) -> None:
    for detector in detectors:
        result.rules.append(detector.rule)
        result.findings[detector.rule.id] = detector.finish()
        if isinstance(detector, PatternDetector) and detector.untracked_events > 0:
            result.warnings.append(
                f"rule {detector.rule.id}: {detector.untracked_events} matching events from "
                "additional sources were not tracked (source limit reached)"
            )


def warn_if_unparseable(label: str, stats: ParseStats, result: AnalysisResult) -> None:
    if stats.total_lines > 0 and stats.parsed_lines == 0 and stats.ignored_lines == 0:
        result.warnings.append(
            f"no line of the {label} log could be parsed; "
            "check that the file matches the expected format"
        )


def run_ssh(path: Path, year: int | None, rules: list[Rule], result: AnalysisResult) -> None:
    stats = ParseStats()
    resolver = YearResolver(year=year)
    detectors = [ThresholdDetector(rule) for rule in select_rules(rules, LogType.SSH)]
    for event in parse_ssh_file(path, stats, resolver):
        for detector in detectors:
            detector.feed(event)
    finish_detectors(detectors, result)
    assumed = resolver.year_assumed and resolver.first_year is not None
    result.inputs.append(
        InputSummary(
            log_type=LogType.SSH,
            path=str(path),
            stats=stats,
            year=resolver.first_year,
            year_assumed=assumed,
        )
    )
    if assumed:
        result.warnings.append(
            f"SSH log timestamps have no year; assumed {resolver.first_year} for the first "
            "line. Use --year to set it explicitly."
        )
    warn_if_unparseable("SSH", stats, result)


def run_access(path: Path, rules: list[Rule], result: AnalysisResult) -> None:
    stats = ParseStats()
    detectors: list[Detector] = []
    for rule in select_rules(rules, LogType.ACCESS):
        if rule.rule_type is RuleType.THRESHOLD:
            detectors.append(ThresholdDetector(rule))
        else:
            detectors.append(PatternDetector(rule))
    for event in parse_access_file(path, stats):
        for detector in detectors:
            detector.feed(event)
    finish_detectors(detectors, result)
    result.inputs.append(
        InputSummary(
            log_type=LogType.ACCESS,
            path=str(path),
            stats=stats,
            year=None,
            year_assumed=False,
        )
    )
    warn_if_unparseable("access", stats, result)


def analyze(
    rules: list[Rule], access_log: Path | None, ssh_log: Path | None, year: int | None
) -> AnalysisResult:
    result = AnalysisResult()
    if ssh_log is not None:
        run_ssh(ssh_log, year, rules, result)
    if access_log is not None:
        run_access(access_log, rules, result)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    access_log: Path | None = args.access_log
    ssh_log: Path | None = args.ssh_log
    year: int | None = args.year
    if access_log is None and ssh_log is None:
        parser.error("at least one of --access-log or --ssh-log is required")
    if year is not None and ssh_log is None:
        parser.error("--year can only be used together with --ssh-log")
    problems = input_problems(access_log, ssh_log)
    if problems:
        for problem in problems:
            print_error(problem)
        return EXIT_ERROR
    fail_on = Severity(args.fail_on)
    try:
        rules = load_rules(args.rules)
        result = analyze(rules, access_log, ssh_log, year)
    except RuleError as error:
        for message in error.errors:
            print_error(message)
        return EXIT_ERROR
    except OSError as error:
        print_error(f"cannot read input: {error}")
        return EXIT_ERROR
    report = build_report(result, fail_on)
    emit(render_json(report) if args.json else render_text(report), sys.stdout)
    return EXIT_FINDINGS if count_at_or_above(result, fail_on) > 0 else EXIT_OK
