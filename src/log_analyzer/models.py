import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class SshEventType(StrEnum):
    FAILED_PASSWORD = "failed_password"
    ACCEPTED_PASSWORD = "accepted_password"
    INVALID_USER = "invalid_user"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(type(self)).index(self)


class LogType(StrEnum):
    SSH = "ssh"
    ACCESS = "access"


class RuleType(StrEnum):
    THRESHOLD = "threshold"
    PATTERN = "pattern"


class PatternKind(StrEnum):
    CONTAINS = "contains"
    REGEX = "regex"


class MatchField(StrEnum):
    DECODED_URL = "decoded_url"
    USER_AGENT = "user_agent"


@dataclass(frozen=True, slots=True)
class AccessEvent:
    line_number: int
    source_ip: str
    timestamp: datetime
    method: str
    raw_url: str
    decoded_url: str
    protocol: str
    status: int
    size: int
    referer: str
    user_agent: str


@dataclass(frozen=True, slots=True)
class SshEvent:
    line_number: int
    timestamp: datetime
    hostname: str
    pid: int | None
    event_type: SshEventType
    username: str
    source_ip: str
    port: int | None


@dataclass(slots=True)
class ParseStats:
    total_lines: int = 0
    parsed_lines: int = 0
    ignored_lines: int = 0
    failed_lines: int = 0
    oversized_lines: int = 0


@dataclass(frozen=True, slots=True)
class ThresholdSpec:
    count: int
    window_minutes: int
    events: tuple[SshEventType, ...]
    statuses: tuple[int, ...]
    distinct: str | None


@dataclass(frozen=True, slots=True)
class PatternSpec:
    kind: PatternKind
    name: str
    value: str
    regex: re.Pattern[str] | None


@dataclass(frozen=True, slots=True)
class MatchSpec:
    field: MatchField
    case_insensitive: bool
    patterns: tuple[PatternSpec, ...]


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    description: str
    severity: Severity
    log_type: LogType
    rule_type: RuleType
    remediation: str
    false_positive_notes: str
    mitre_attack: tuple[str, ...]
    enabled: bool
    threshold: ThresholdSpec | None
    match: MatchSpec | None


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    distinct_count: int | None
    evidence: tuple[str, ...]
    first_line: int
    last_line: int
