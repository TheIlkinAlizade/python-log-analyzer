import re
from enum import StrEnum
from pathlib import Path
from typing import Any, TypeVar

import yaml

from log_analyzer.models import (
    LogType,
    MatchField,
    MatchSpec,
    PatternKind,
    PatternSpec,
    Rule,
    RuleType,
    Severity,
    SshEventType,
    ThresholdSpec,
)

MAX_RULES_FILE_BYTES = 1_048_576
MAX_RULES = 200
MAX_PATTERNS_PER_RULE = 50
MAX_TEXT_LENGTH = 1000
MAX_NAME_LENGTH = 64
MAX_PATTERN_VALUE_LENGTH = 200
MAX_COUNT = 1_000_000
MAX_WINDOW_MINUTES = 1440

ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}")
MITRE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")

RULE_REQUIRED = frozenset(
    {
        "id",
        "title",
        "description",
        "severity",
        "log_type",
        "type",
        "remediation",
        "false_positive_notes",
    }
)
RULE_OPTIONAL = frozenset({"mitre_attack", "enabled", "threshold", "match"})
THRESHOLD_COMMON = frozenset({"group_by", "count", "window_minutes"})

E = TypeVar("E", bound=StrEnum)


class RuleError(Exception):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("\n".join(errors))
        self.errors = errors


def read_rules_text(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_RULES_FILE_BYTES + 1)
    except OSError as error:
        raise RuleError([f"cannot read rules file: {error.strerror or error}"]) from error
    if len(raw) > MAX_RULES_FILE_BYTES:
        raise RuleError([f"rules file is too large (maximum {MAX_RULES_FILE_BYTES} bytes)"])
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuleError(["rules file is not valid UTF-8"]) from error


def parse_yaml(text: str) -> object:
    try:
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.AliasEvent):
                raise RuleError(["YAML anchors and aliases are not allowed in rules files"])
        return yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise RuleError([f"invalid YAML: {error}"]) from error
    except RecursionError as error:
        raise RuleError(["invalid YAML: nesting is too deep"]) from error


def as_mapping(value: object, where: str, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        errors.append(f"{where}: must be a mapping with text keys")
        return None
    return dict(value)


def check_keys(
    data: dict[str, Any],
    where: str,
    required: frozenset[str],
    optional: frozenset[str],
    errors: list[str],
) -> None:
    for key in sorted(required):
        if key not in data:
            errors.append(f"{where}: missing required field '{key}'")
    for key in sorted(data):
        if key not in required and key not in optional:
            errors.append(f"{where}: unknown field '{key}'")


def get_text(
    data: dict[str, Any],
    key: str,
    where: str,
    errors: list[str],
    max_length: int = MAX_TEXT_LENGTH,
) -> str | None:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{where}.{key}: must be a non-empty string")
        return None
    if len(value) > max_length:
        errors.append(f"{where}.{key}: too long (maximum {max_length} characters)")
        return None
    return value


def get_int(
    data: dict[str, Any], key: str, where: str, errors: list[str], low: int, high: int
) -> int | None:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        errors.append(f"{where}.{key}: must be an integer between {low} and {high}")
        return None
    return value


def get_bool(
    data: dict[str, Any], key: str, default: bool, where: str, errors: list[str]
) -> bool:
    if key not in data:
        return default
    value = data[key]
    if not isinstance(value, bool):
        errors.append(f"{where}.{key}: must be true or false")
        return default
    return value


def get_list(
    data: dict[str, Any], key: str, where: str, errors: list[str], allow_empty: bool
) -> list[Any] | None:
    value = data.get(key)
    if not isinstance(value, list) or (not value and not allow_empty):
        qualifier = "a list" if allow_empty else "a non-empty list"
        errors.append(f"{where}.{key}: must be {qualifier}")
        return None
    return value


def parse_enum(enum_type: type[E], value: object) -> E | None:
    if not isinstance(value, str):
        return None
    try:
        return enum_type(value)
    except ValueError:
        return None


def allowed_values(enum_type: type[E]) -> str:
    return ", ".join(member.value for member in enum_type)


def get_enum(
    data: dict[str, Any], key: str, enum_type: type[E], where: str, errors: list[str]
) -> E | None:
    member = parse_enum(enum_type, data.get(key))
    if member is None:
        errors.append(f"{where}.{key}: must be one of {allowed_values(enum_type)}")
    return member


def get_enum_list(
    data: dict[str, Any], key: str, enum_type: type[E], where: str, errors: list[str]
) -> tuple[E, ...]:
    items = get_list(data, key, where, errors, allow_empty=False)
    if items is None:
        return ()
    result: list[E] = []
    for index, item in enumerate(items):
        member = parse_enum(enum_type, item)
        if member is None:
            errors.append(f"{where}.{key}[{index}]: must be one of {allowed_values(enum_type)}")
        elif member in result:
            errors.append(f"{where}.{key}: duplicate '{member.value}'")
        else:
            result.append(member)
    return tuple(result)


def get_status_list(data: dict[str, Any], where: str, errors: list[str]) -> tuple[int, ...]:
    items = get_list(data, "status", where, errors, allow_empty=False)
    if items is None:
        return ()
    result: list[int] = []
    for index, item in enumerate(items):
        if isinstance(item, bool) or not isinstance(item, int) or not 100 <= item <= 599:
            errors.append(f"{where}.status[{index}]: must be an integer between 100 and 599")
        elif item in result:
            errors.append(f"{where}.status: duplicate {item}")
        else:
            result.append(item)
    return tuple(result)


def get_mitre(data: dict[str, Any], where: str, errors: list[str]) -> tuple[str, ...]:
    if "mitre_attack" not in data:
        return ()
    items = get_list(data, "mitre_attack", where, errors, allow_empty=True)
    if items is None:
        return ()
    result: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, str) or MITRE_PATTERN.fullmatch(item) is None:
            errors.append(f"{where}.mitre_attack[{index}]: must look like T1110 or T1110.001")
        elif item in result:
            errors.append(f"{where}.mitre_attack: duplicate '{item}'")
        else:
            result.append(item)
    return tuple(result)


def build_threshold(
    raw: object, log_type: LogType, where: str, errors: list[str]
) -> ThresholdSpec | None:
    data = as_mapping(raw, where, errors)
    if data is None:
        return None
    before = len(errors)
    is_ssh = log_type is LogType.SSH
    required = THRESHOLD_COMMON | {"events" if is_ssh else "status"}
    optional = frozenset({"distinct"}) if is_ssh else frozenset()
    check_keys(data, where, required, optional, errors)
    if "group_by" in data and data["group_by"] != "source_ip":
        errors.append(f"{where}.group_by: must be source_ip")
    count = get_int(data, "count", where, errors, 1, MAX_COUNT) if "count" in data else None
    window = (
        get_int(data, "window_minutes", where, errors, 1, MAX_WINDOW_MINUTES)
        if "window_minutes" in data
        else None
    )
    events: tuple[SshEventType, ...] = ()
    statuses: tuple[int, ...] = ()
    distinct: str | None = None
    if is_ssh:
        if "events" in data:
            events = get_enum_list(data, "events", SshEventType, where, errors)
        if "distinct" in data:
            if data["distinct"] == "username":
                distinct = "username"
            else:
                errors.append(f"{where}.distinct: must be one of username")
    elif "status" in data:
        statuses = get_status_list(data, where, errors)
    if len(errors) > before or count is None or window is None:
        return None
    return ThresholdSpec(
        count=count,
        window_minutes=window,
        events=events,
        statuses=statuses,
        distinct=distinct,
    )


def build_pattern(
    raw: object,
    index: int,
    case_insensitive: bool,
    seen_names: set[str],
    where: str,
    errors: list[str],
) -> PatternSpec | None:
    label = f"{where}[{index}]"
    data = as_mapping(raw, label, errors)
    if data is None:
        return None
    before = len(errors)
    check_keys(data, label, frozenset({"kind", "name", "value"}), frozenset(), errors)
    kind = get_enum(data, "kind", PatternKind, label, errors) if "kind" in data else None
    name = get_text(data, "name", label, errors, MAX_NAME_LENGTH) if "name" in data else None
    value = (
        get_text(data, "value", label, errors, MAX_PATTERN_VALUE_LENGTH)
        if "value" in data
        else None
    )
    if name is not None:
        if name in seen_names:
            errors.append(f"{label}.name: duplicate pattern name '{name}'")
        seen_names.add(name)
    regex: re.Pattern[str] | None = None
    if kind is PatternKind.REGEX and value is not None:
        flags = re.IGNORECASE if case_insensitive else 0
        try:
            regex = re.compile(value, flags)
        except (re.error, RecursionError, OverflowError) as error:
            errors.append(f"{label}.value: invalid regular expression: {error}")
            regex = None
        else:
            if regex.search("") is not None:
                errors.append(f"{label}.value: regular expression matches empty text")
    if len(errors) > before or kind is None or name is None or value is None:
        return None
    return PatternSpec(kind=kind, name=name, value=value, regex=regex)


def build_match(raw: object, where: str, errors: list[str]) -> MatchSpec | None:
    data = as_mapping(raw, where, errors)
    if data is None:
        return None
    before = len(errors)
    check_keys(
        data, where, frozenset({"field", "patterns"}), frozenset({"case_insensitive"}), errors
    )
    field = get_enum(data, "field", MatchField, where, errors) if "field" in data else None
    case_insensitive = get_bool(data, "case_insensitive", True, where, errors)
    patterns: list[PatternSpec] = []
    if "patterns" in data:
        items = get_list(data, "patterns", where, errors, allow_empty=False)
        if items is not None and len(items) > MAX_PATTERNS_PER_RULE:
            errors.append(f"{where}.patterns: too many patterns (maximum {MAX_PATTERNS_PER_RULE})")
        elif items is not None:
            seen_names: set[str] = set()
            for index, item in enumerate(items):
                pattern = build_pattern(
                    item, index, case_insensitive, seen_names, f"{where}.patterns", errors
                )
                if pattern is not None:
                    patterns.append(pattern)
    if len(errors) > before or field is None:
        return None
    return MatchSpec(field=field, case_insensitive=case_insensitive, patterns=tuple(patterns))


def build_rule(raw: object, index: int, seen_ids: set[str], errors: list[str]) -> Rule | None:
    where = f"rule #{index}"
    data = as_mapping(raw, where, errors)
    if data is None:
        return None
    before = len(errors)
    rule_id: str | None = None
    if "id" in data:
        candidate = data["id"]
        if isinstance(candidate, str) and ID_PATTERN.fullmatch(candidate) is not None:
            rule_id = candidate
            where = f"rule {candidate}"
            if candidate in seen_ids:
                errors.append(f"{where}: duplicate rule id")
            seen_ids.add(candidate)
        else:
            errors.append(
                f"{where}.id: must be 1-32 characters: letters, digits, '_' or '-', "
                "starting with a letter or digit"
            )
    check_keys(data, where, RULE_REQUIRED, RULE_OPTIONAL, errors)
    title = get_text(data, "title", where, errors) if "title" in data else None
    description = get_text(data, "description", where, errors) if "description" in data else None
    remediation = get_text(data, "remediation", where, errors) if "remediation" in data else None
    notes = (
        get_text(data, "false_positive_notes", where, errors)
        if "false_positive_notes" in data
        else None
    )
    severity = get_enum(data, "severity", Severity, where, errors) if "severity" in data else None
    log_type = get_enum(data, "log_type", LogType, where, errors) if "log_type" in data else None
    rule_type = get_enum(data, "type", RuleType, where, errors) if "type" in data else None
    enabled = get_bool(data, "enabled", True, where, errors)
    mitre = get_mitre(data, where, errors)
    threshold: ThresholdSpec | None = None
    match: MatchSpec | None = None
    if rule_type is RuleType.THRESHOLD:
        if "match" in data:
            errors.append(f"{where}: threshold rules must not have a 'match' section")
        if "threshold" not in data:
            errors.append(f"{where}: threshold rules require a 'threshold' section")
        elif log_type is not None:
            threshold = build_threshold(data["threshold"], log_type, f"{where}.threshold", errors)
    elif rule_type is RuleType.PATTERN:
        if "threshold" in data:
            errors.append(f"{where}: pattern rules must not have a 'threshold' section")
        if "match" not in data:
            errors.append(f"{where}: pattern rules require a 'match' section")
        elif log_type is not None and log_type is not LogType.ACCESS:
            errors.append(f"{where}: pattern rules are only supported for access logs")
        elif log_type is not None:
            match = build_match(data["match"], f"{where}.match", errors)
    if (
        len(errors) > before
        or rule_id is None
        or title is None
        or description is None
        or remediation is None
        or notes is None
        or severity is None
        or log_type is None
        or rule_type is None
    ):
        return None
    return Rule(
        id=rule_id,
        title=title,
        description=description,
        severity=severity,
        log_type=log_type,
        rule_type=rule_type,
        remediation=remediation,
        false_positive_notes=notes,
        mitre_attack=mitre,
        enabled=enabled,
        threshold=threshold,
        match=match,
    )


def build_rules(data: object) -> list[Rule]:
    errors: list[str] = []
    root = as_mapping(data, "rules file", errors)
    if root is None:
        raise RuleError(errors)
    check_keys(root, "rules file", frozenset({"rules"}), frozenset(), errors)
    rules: list[Rule] = []
    if "rules" in root:
        items = get_list(root, "rules", "rules file", errors, allow_empty=False)
        if items is not None and len(items) > MAX_RULES:
            errors.append(f"rules file.rules: too many rules (maximum {MAX_RULES})")
        elif items is not None:
            seen_ids: set[str] = set()
            for index, item in enumerate(items, start=1):
                rule = build_rule(item, index, seen_ids, errors)
                if rule is not None:
                    rules.append(rule)
    if errors:
        raise RuleError(errors)
    return rules


def load_rules(path: Path) -> list[Rule]:
    return build_rules(parse_yaml(read_rules_text(path)))