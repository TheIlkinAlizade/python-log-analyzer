from pathlib import Path
from typing import Any

import pytest
import yaml

from log_analyzer.models import (
    LogType,
    MatchField,
    PatternKind,
    Rule,
    RuleType,
    Severity,
    SshEventType,
)
from log_analyzer.rules import MAX_RULES_FILE_BYTES, RuleError, load_rules

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "default.yml"
MISSING = object()


def build(base: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in changes.items():
        if value is MISSING:
            result.pop(key, None)
        else:
            result[key] = value
    return result


def threshold_section(**changes: Any) -> dict[str, Any]:
    base = {
        "events": ["failed_password", "invalid_user"],
        "group_by": "source_ip",
        "count": 5,
        "window_minutes": 5,
    }
    return build(base, changes)


def web_threshold_section(**changes: Any) -> dict[str, Any]:
    base = {"status": [404], "group_by": "source_ip", "count": 30, "window_minutes": 2}
    return build(base, changes)


def pattern(**changes: Any) -> dict[str, Any]:
    return build({"kind": "contains", "name": "p1", "value": "../"}, changes)


def match_section(**changes: Any) -> dict[str, Any]:
    base = {"field": "decoded_url", "case_insensitive": True, "patterns": [pattern()]}
    return build(base, changes)


def ssh_rule(**changes: Any) -> dict[str, Any]:
    base = {
        "id": "SSH-100",
        "title": "Test rule",
        "description": "Test description",
        "severity": "high",
        "log_type": "ssh",
        "type": "threshold",
        "mitre_attack": ["T1110.001"],
        "threshold": threshold_section(),
        "remediation": "Fix it",
        "false_positive_notes": "Could be benign",
    }
    return build(base, changes)


def web_threshold_rule(**changes: Any) -> dict[str, Any]:
    base = ssh_rule(id="WEB-100", log_type="access", threshold=web_threshold_section())
    return build(base, changes)


def pattern_rule(**changes: Any) -> dict[str, Any]:
    base = ssh_rule(
        id="WEB-200",
        log_type="access",
        type="pattern",
        threshold=MISSING,
        match=match_section(),
    )
    return build(base, changes)


def write_rules(tmp_path: Path, *rules: dict[str, Any]) -> Path:
    path = tmp_path / "rules.yml"
    path.write_text(yaml.safe_dump({"rules": list(rules)}), encoding="utf-8")
    return path


def load(tmp_path: Path, *rules: dict[str, Any]) -> list[Rule]:
    return load_rules(write_rules(tmp_path, *rules))


def error_text(tmp_path: Path, *rules: dict[str, Any]) -> str:
    with pytest.raises(RuleError) as info:
        load(tmp_path, *rules)
    return str(info.value)


def default_rules_by_id() -> dict[str, Rule]:
    return {rule.id: rule for rule in load_rules(DEFAULT_RULES)}


INVALID_RULES: list[tuple[dict[str, Any], str]] = [
    (ssh_rule(severity="urgent"), "severity: must be one of low, medium, high, critical"),
    (ssh_rule(log_type="nginx"), "log_type: must be one of ssh, access"),
    (ssh_rule(type="magic"), "type: must be one of threshold, pattern"),
    (ssh_rule(id="bad id!"), "id: must be 1-32 characters"),
    (ssh_rule(id="x" * 40), "id: must be 1-32 characters"),
    (ssh_rule(id="A-1\n"), "id: must be 1-32 characters"),
    (ssh_rule(title=MISSING), "missing required field 'title'"),
    (ssh_rule(title="  "), "title: must be a non-empty string"),
    (ssh_rule(title=5), "title: must be a non-empty string"),
    (ssh_rule(description="x" * 1001), "too long (maximum 1000 characters)"),
    (ssh_rule(treshold={}), "unknown field 'treshold'"),
    (ssh_rule(enabled="yes"), "enabled: must be true or false"),
    (ssh_rule(mitre_attack="T1110"), "mitre_attack: must be a list"),
    (ssh_rule(mitre_attack=["t1110"]), "must look like T1110 or T1110.001"),
    (ssh_rule(mitre_attack=["T11"]), "must look like T1110 or T1110.001"),
    (ssh_rule(mitre_attack=["T1110.1"]), "must look like T1110 or T1110.001"),
    (ssh_rule(mitre_attack=["T1110", "T1110"]), "duplicate 'T1110'"),
    (ssh_rule(threshold=MISSING), "threshold rules require a 'threshold' section"),
    (ssh_rule(match=match_section()), "threshold rules must not have a 'match' section"),
    (
        ssh_rule(threshold=threshold_section(count=0)),
        ".count: must be an integer between 1 and 1000000",
    ),
    (
        ssh_rule(threshold=threshold_section(count=True)),
        ".count: must be an integer between 1 and 1000000",
    ),
    (
        ssh_rule(threshold=threshold_section(count="5")),
        ".count: must be an integer between 1 and 1000000",
    ),
    (
        ssh_rule(threshold=threshold_section(count=1_000_001)),
        ".count: must be an integer between 1 and 1000000",
    ),
    (
        ssh_rule(threshold=threshold_section(window_minutes=0)),
        ".window_minutes: must be an integer between 1 and 1440",
    ),
    (
        ssh_rule(threshold=threshold_section(window_minutes=1441)),
        ".window_minutes: must be an integer between 1 and 1440",
    ),
    (
        ssh_rule(threshold=threshold_section(window_minutes=5.5)),
        ".window_minutes: must be an integer between 1 and 1440",
    ),
    (ssh_rule(threshold=threshold_section(group_by="username")), "group_by: must be source_ip"),
    (ssh_rule(threshold=threshold_section(events=MISSING)), "missing required field 'events'"),
    (ssh_rule(threshold=threshold_section(events=[])), "events: must be a non-empty list"),
    (
        ssh_rule(threshold=threshold_section(events=["login"])),
        "events[0]: must be one of failed_password, accepted_password, invalid_user",
    ),
    (
        ssh_rule(threshold=threshold_section(events=["failed_password", "failed_password"])),
        "duplicate 'failed_password'",
    ),
    (ssh_rule(threshold=threshold_section(status=[404])), "unknown field 'status'"),
    (
        ssh_rule(threshold=threshold_section(distinct="password")),
        "distinct: must be one of username",
    ),
    (ssh_rule(threshold=threshold_section(bogus=1)), "unknown field 'bogus'"),
    (
        ssh_rule(type="pattern", threshold=MISSING, match=match_section()),
        "pattern rules are only supported for access logs",
    ),
    (
        pattern_rule(threshold=web_threshold_section()),
        "pattern rules must not have a 'threshold' section",
    ),
    (pattern_rule(match=MISSING), "pattern rules require a 'match' section"),
    (
        web_threshold_rule(threshold=web_threshold_section(status=[99])),
        "status[0]: must be an integer between 100 and 599",
    ),
    (
        web_threshold_rule(threshold=web_threshold_section(status=[600])),
        "status[0]: must be an integer between 100 and 599",
    ),
    (
        web_threshold_rule(threshold=web_threshold_section(status=[True])),
        "status[0]: must be an integer between 100 and 599",
    ),
    (
        web_threshold_rule(threshold=web_threshold_section(status=[])),
        "status: must be a non-empty list",
    ),
    (
        web_threshold_rule(threshold=web_threshold_section(status=MISSING)),
        "missing required field 'status'",
    ),
    (
        web_threshold_rule(threshold=web_threshold_section(status=[404, 404])),
        "duplicate 404",
    ),
    (
        web_threshold_rule(threshold=web_threshold_section(events=["failed_password"])),
        "unknown field 'events'",
    ),
    (
        web_threshold_rule(threshold=web_threshold_section(distinct="username")),
        "unknown field 'distinct'",
    ),
    (
        pattern_rule(match=match_section(field="raw_url")),
        "field: must be one of decoded_url, user_agent",
    ),
    (pattern_rule(match=match_section(patterns=[])), "patterns: must be a non-empty list"),
    (pattern_rule(match=match_section(patterns=MISSING)), "missing required field 'patterns'"),
    (
        pattern_rule(match=match_section(case_insensitive="yes")),
        "case_insensitive: must be true or false",
    ),
    (pattern_rule(match=match_section(bogus=1)), "unknown field 'bogus'"),
    (
        pattern_rule(match=match_section(patterns=[pattern(kind="glob")])),
        "patterns[0].kind: must be one of contains, regex",
    ),
    (
        pattern_rule(match=match_section(patterns=[pattern(name=MISSING)])),
        "missing required field 'name'",
    ),
    (
        pattern_rule(match=match_section(patterns=[pattern(name="x" * 65)])),
        "too long (maximum 64 characters)",
    ),
    (
        pattern_rule(match=match_section(patterns=[pattern(value="")])),
        "value: must be a non-empty string",
    ),
    (
        pattern_rule(match=match_section(patterns=[pattern(value="x" * 201)])),
        "too long (maximum 200 characters)",
    ),
    (pattern_rule(match=match_section(patterns=[pattern(bogus=1)])), "unknown field 'bogus'"),
    (
        pattern_rule(match=match_section(patterns=[pattern(), pattern()])),
        "duplicate pattern name 'p1'",
    ),
    (
        pattern_rule(match=match_section(patterns=[pattern(kind="regex", value="(")])),
        "invalid regular expression",
    ),
    (
        pattern_rule(match=match_section(patterns=[pattern(kind="regex", value=".*")])),
        "regular expression matches empty text",
    ),
    (pattern_rule(match=match_section(patterns=["text"])), "patterns[0]: must be a mapping"),
    (
        pattern_rule(
            match=match_section(patterns=[pattern(name=f"p{number}") for number in range(51)])
        ),
        "too many patterns",
    ),
]

INVALID_FILES: list[tuple[str, str]] = [
    ("", "must be a mapping"),
    ("just text", "must be a mapping"),
    ("- a\n- b\n", "must be a mapping"),
    ("rules: 5\n", "rules: must be a non-empty list"),
    ("rules: []\n", "rules: must be a non-empty list"),
    ("other: 1\n", "missing required field 'rules'"),
    ("rules: [{}]\nextra: 1\n", "unknown field 'extra'"),
    ("rules: [unclosed\n", "invalid YAML"),
    ("a: 1\n---\nb: 2\n", "invalid YAML"),
    ("rules: &a [1]\nother: *a\n", "aliases"),
    ("rules: !!python/object/apply:os.system ['echo hi']\n", "invalid YAML"),
    ("[" * 5000 + "]" * 5000, "invalid YAML"),
]


def test_default_rules_file_loads() -> None:
    rules = load_rules(DEFAULT_RULES)
    assert [rule.id for rule in rules] == ["SSH-001", "SSH-002", "WEB-001", "WEB-002", "WEB-003"]
    assert all(rule.enabled for rule in rules)
    assert all(rule.remediation and rule.false_positive_notes for rule in rules)


def test_default_ssh_brute_force_rule() -> None:
    rule = default_rules_by_id()["SSH-001"]
    assert rule.severity is Severity.HIGH
    assert rule.log_type is LogType.SSH
    assert rule.rule_type is RuleType.THRESHOLD
    assert rule.mitre_attack == ("T1110.001",)
    assert rule.match is None
    assert rule.threshold is not None
    assert rule.threshold.count == 5
    assert rule.threshold.window_minutes == 5
    assert rule.threshold.events == (SshEventType.FAILED_PASSWORD,)
    assert rule.threshold.distinct is None


def test_default_spraying_rule() -> None:
    rule = default_rules_by_id()["SSH-002"]
    assert rule.mitre_attack == ("T1110.003", "T1110.004")
    assert rule.threshold is not None
    assert rule.threshold.distinct == "username"
    assert rule.threshold.count == 10
    assert rule.threshold.window_minutes == 10


def test_default_web_scanning_rule() -> None:
    rule = default_rules_by_id()["WEB-001"]
    assert rule.log_type is LogType.ACCESS
    assert rule.severity is Severity.MEDIUM
    assert rule.threshold is not None
    assert rule.threshold.statuses == (404,)
    assert rule.threshold.events == ()


def test_default_attack_string_rule() -> None:
    rule = default_rules_by_id()["WEB-002"]
    assert rule.rule_type is RuleType.PATTERN
    assert rule.threshold is None
    assert rule.match is not None
    assert rule.match.field is MatchField.DECODED_URL
    assert rule.match.case_insensitive is True
    names = [item.name for item in rule.match.patterns]
    assert names == ["sqli-union-select", "xss-script-tag", "path-traversal"]
    regex_pattern = rule.match.patterns[0]
    assert regex_pattern.kind is PatternKind.REGEX
    assert regex_pattern.regex is not None
    assert regex_pattern.regex.search("1 UNION   SELECT") is not None
    assert regex_pattern.regex.search("1 UNION ALL") is None
    assert rule.match.patterns[1].regex is None


def test_default_scanner_user_agent_rule() -> None:
    rule = default_rules_by_id()["WEB-003"]
    assert rule.match is not None
    assert rule.match.field is MatchField.USER_AGENT
    assert [item.name for item in rule.match.patterns] == ["sqlmap", "nikto", "nmap"]


def test_optional_fields_get_defaults(tmp_path: Path) -> None:
    ssh = ssh_rule(mitre_attack=MISSING)
    web = pattern_rule(match=match_section(case_insensitive=MISSING))
    first, second = load(tmp_path, ssh, web)
    assert first.mitre_attack == ()
    assert first.enabled is True
    assert second.match is not None
    assert second.match.case_insensitive is True


def test_disabled_rule_is_loaded(tmp_path: Path) -> None:
    (rule,) = load(tmp_path, ssh_rule(enabled=False))
    assert rule.enabled is False


def test_regex_respects_case_insensitive_flag(tmp_path: Path) -> None:
    sensitive = pattern_rule(
        id="WEB-301",
        match=match_section(
            case_insensitive=False,
            patterns=[pattern(kind="regex", value=r"union\s+select")],
        ),
    )
    insensitive = pattern_rule(
        id="WEB-302",
        match=match_section(
            case_insensitive=True,
            patterns=[pattern(kind="regex", value=r"union\s+select")],
        ),
    )
    first, second = load(tmp_path, sensitive, insensitive)
    assert first.match is not None
    assert second.match is not None
    first_regex = first.match.patterns[0].regex
    second_regex = second.match.patterns[0].regex
    assert first_regex is not None
    assert second_regex is not None
    assert first_regex.search("UNION SELECT") is None
    assert second_regex.search("UNION SELECT") is not None


@pytest.mark.parametrize(
    ("rule", "fragment"), INVALID_RULES, ids=[case[1] for case in INVALID_RULES]
)
def test_invalid_rule_is_rejected(tmp_path: Path, rule: dict[str, Any], fragment: str) -> None:
    assert fragment in error_text(tmp_path, rule)


@pytest.mark.parametrize(("text", "fragment"), INVALID_FILES)
def test_invalid_file_is_rejected(tmp_path: Path, text: str, fragment: str) -> None:
    path = tmp_path / "rules.yml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(RuleError) as info:
        load_rules(path)
    assert fragment in str(info.value)


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    assert "duplicate rule id" in error_text(tmp_path, ssh_rule(), ssh_rule())


def test_all_errors_are_reported_together(tmp_path: Path) -> None:
    first = ssh_rule(id="A-1", severity="urgent")
    second = ssh_rule(id="A-2", log_type="mainframe")
    third = ssh_rule(id="A-3", threshold=threshold_section(count=0))
    text = error_text(tmp_path, first, second, third)
    assert "rule A-1.severity" in text
    assert "rule A-2.log_type" in text
    assert "rule A-3.threshold.count" in text


def test_too_many_rules_are_rejected(tmp_path: Path) -> None:
    rules = [ssh_rule(id=f"R-{number}") for number in range(201)]
    assert "too many rules (maximum 200)" in error_text(tmp_path, *rules)


def test_missing_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(RuleError, match="cannot read rules file"):
        load_rules(tmp_path / "nope.yml")


def test_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(RuleError, match="cannot read rules file"):
        load_rules(tmp_path)


def test_oversized_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "big.yml"
    path.write_bytes(b"#" * (MAX_RULES_FILE_BYTES + 1))
    with pytest.raises(RuleError, match="too large"):
        load_rules(path)


def test_invalid_utf8_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yml"
    path.write_bytes(b"rules: \xff\xfe\n")
    with pytest.raises(RuleError, match="not valid UTF-8"):
        load_rules(path)
