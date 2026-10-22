from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from log_analyzer.models import AccessEvent, Finding, Rule, RuleType, SshEvent, ThresholdSpec

MAX_DISTINCT_WINDOW_ENTRIES = 50_000
MAX_EVIDENCE_ITEMS = 5
MAX_EVIDENCE_LENGTH = 200
DEFAULT_CLEANUP_INTERVAL = 10_000

Entry = tuple[datetime, str, int]
Event = SshEvent | AccessEvent


@dataclass(slots=True)
class Burst:
    first_seen: datetime
    last_seen: datetime
    first_line: int
    last_line: int
    event_count: int
    peak_distinct: int
    evidence: list[str]


@dataclass(slots=True)
class KeyState:
    window: deque[Entry] = field(default_factory=deque)
    values: Counter[str] = field(default_factory=Counter)
    last_seen: datetime | None = None
    burst: Burst | None = None


def add_evidence(evidence: list[str], value: str) -> None:
    if len(evidence) < MAX_EVIDENCE_ITEMS and value not in evidence:
        evidence.append(value)


def collect_evidence(window: deque[Entry]) -> list[str]:
    evidence: list[str] = []
    for _, value, _ in window:
        add_evidence(evidence, value)
    return evidence


class ThresholdDetector:
    def __init__(self, rule: Rule, cleanup_interval: int = DEFAULT_CLEANUP_INTERVAL) -> None:
        if rule.rule_type is not RuleType.THRESHOLD or rule.threshold is None:
            raise ValueError(f"rule {rule.id} is not a threshold rule")
        if cleanup_interval < 1:
            raise ValueError("cleanup_interval must be at least 1")
        self.rule = rule
        self.spec: ThresholdSpec = rule.threshold
        self.window = timedelta(minutes=self.spec.window_minutes)
        self.track_distinct = self.spec.distinct is not None
        self.capacity = (
            max(self.spec.count, MAX_DISTINCT_WINDOW_ENTRIES)
            if self.track_distinct
            else self.spec.count
        )
        self.cleanup_interval = cleanup_interval
        self.states: dict[str, KeyState] = {}
        self.findings: list[Finding] = []
        self.processed = 0
        self.latest: datetime | None = None

    @property
    def tracked_sources(self) -> int:
        return len(self.states)

    def extract(self, event: Event) -> str | None:
        if isinstance(event, SshEvent):
            if event.event_type not in self.spec.events:
                return None
            return event.username[:MAX_EVIDENCE_LENGTH]
        if event.status not in self.spec.statuses:
            return None
        return event.decoded_url[:MAX_EVIDENCE_LENGTH]

    def measure(self, state: KeyState) -> int:
        return len(state.values) if self.track_distinct else len(state.window)

    def pop_oldest(self, state: KeyState) -> None:
        _, value, _ = state.window.popleft()
        if self.track_distinct:
            state.values[value] -= 1
            if state.values[value] <= 0:
                del state.values[value]

    def feed(self, event: Event) -> None:
        value = self.extract(event)
        if value is None:
            return
        key = event.source_ip
        state = self.states.get(key)
        if state is None:
            state = KeyState()
            self.states[key] = state
        moment = event.timestamp
        if state.last_seen is not None and moment < state.last_seen:
            moment = state.last_seen
        if state.burst is not None and moment - state.burst.last_seen > self.window:
            self.close_burst(key, state)
        cutoff = moment - self.window
        while state.window and state.window[0][0] < cutoff:
            self.pop_oldest(state)
        if len(state.window) >= self.capacity:
            self.pop_oldest(state)
        state.window.append((moment, value, event.line_number))
        if self.track_distinct:
            state.values[value] += 1
        state.last_seen = moment
        self.advance(state, moment, value, event.line_number)
        self.tick(moment)

    def advance(self, state: KeyState, moment: datetime, value: str, line: int) -> None:
        reached = self.measure(state)
        burst = state.burst
        if burst is None:
            if reached >= self.spec.count:
                first = state.window[0]
                state.burst = Burst(
                    first_seen=first[0],
                    last_seen=moment,
                    first_line=first[2],
                    last_line=line,
                    event_count=len(state.window),
                    peak_distinct=reached,
                    evidence=collect_evidence(state.window),
                )
            return
        burst.last_seen = moment
        burst.last_line = line
        burst.event_count += 1
        burst.peak_distinct = max(burst.peak_distinct, reached)
        add_evidence(burst.evidence, value)

    def close_burst(self, key: str, state: KeyState) -> None:
        burst = state.burst
        if burst is None:
            return
        state.burst = None
        self.findings.append(
            Finding(
                rule_id=self.rule.id,
                severity=self.rule.severity,
                source_ip=key,
                first_seen=burst.first_seen,
                last_seen=burst.last_seen,
                event_count=burst.event_count,
                distinct_count=burst.peak_distinct if self.track_distinct else None,
                evidence=tuple(burst.evidence),
                first_line=burst.first_line,
                last_line=burst.last_line,
            )
        )

    def tick(self, moment: datetime) -> None:
        self.processed += 1
        if self.latest is None or moment > self.latest:
            self.latest = moment
        if self.processed % self.cleanup_interval == 0:
            self.cleanup()

    def cleanup(self) -> None:
        if self.latest is None:
            return
        cutoff = self.latest - self.window
        stale = [
            key
            for key, state in self.states.items()
            if state.last_seen is not None and state.last_seen < cutoff
        ]
        for key in stale:
            self.close_burst(key, self.states.pop(key))

    def finish(self) -> list[Finding]:
        for key, state in list(self.states.items()):
            self.close_burst(key, state)
        self.states.clear()
        self.findings.sort(key=lambda finding: (finding.first_seen, finding.source_ip))
        result = self.findings
        self.findings = []
        return result
