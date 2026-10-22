from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class SshEventType(StrEnum):
    FAILED_PASSWORD = "failed_password"
    ACCEPTED_PASSWORD = "accepted_password"
    INVALID_USER = "invalid_user"


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
