from dataclasses import dataclass
from datetime import datetime


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


@dataclass(slots=True)
class ParseStats:
    total_lines: int = 0
    parsed_lines: int = 0
    failed_lines: int = 0
    oversized_lines: int = 0
