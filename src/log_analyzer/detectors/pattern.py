import re
from dataclasses import dataclass, field
from datetime import datetime

from log_analyzer.models import (
    AccessEvent,
    Finding,
    MatchField,
    MatchSpec,
    PatternKind,
    PatternSpec,
    Rule,
    RuleType,
)

MAX_TRACKED_SOURCES = 100_000
MAX_EVIDENCE_ITEMS = 5
MAX_EVIDENCE_LENGTH = 200

Needle = str | re.Pattern[str]


@dataclass(slots=True)
class SourceState:
    first_seen: datetime
    last_seen: datetime
    first_line: int
    last_line: int
    event_count: int = 0
    matched: set[int] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)


def prepare_needle(spec: PatternSpec, fold: bool) -> Needle:
    if spec.kind is PatternKind.REGEX:
        if spec.regex is None:
            raise ValueError(f"regex pattern '{spec.name}' was not compiled")
        return spec.regex
    return spec.value.casefold() if fold else spec.value


class PatternDetector:
    def __init__(self, rule: Rule, max_sources: int = MAX_TRACKED_SOURCES) -> None:
        if rule.rule_type is not RuleType.PATTERN or rule.match is None:
            raise ValueError(f"rule {rule.id} is not a pattern rule")
        if max_sources < 1:
            raise ValueError("max_sources must be at least 1")
        self.rule = rule
        self.match: MatchSpec = rule.match
        self.fold = self.match.case_insensitive
        self.needles = tuple(prepare_needle(spec, self.fold) for spec in self.match.patterns)
        self.max_sources = max_sources
        self.states: dict[str, SourceState] = {}
        self.untracked_events = 0

    @property
    def tracked_sources(self) -> int:
        return len(self.states)

    def field_value(self, event: AccessEvent) -> str:
        if self.match.field is MatchField.DECODED_URL:
            return event.decoded_url
        return event.user_agent

    def matching(self, text: str) -> list[int]:
        haystack = text.casefold() if self.fold else text
        hits: list[int] = []
        for index, needle in enumerate(self.needles):
            if isinstance(needle, str):
                found = needle in haystack
            else:
                found = needle.search(text) is not None
            if found:
                hits.append(index)
        return hits

    def feed(self, event: AccessEvent) -> None:
        text = self.field_value(event)
        hits = self.matching(text)
        if not hits:
            return
        key = event.source_ip
        state = self.states.get(key)
        if state is None:
            if len(self.states) >= self.max_sources:
                self.untracked_events += 1
                return
            state = SourceState(
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                first_line=event.line_number,
                last_line=event.line_number,
            )
            self.states[key] = state
        state.event_count += 1
        if event.timestamp < state.first_seen:
            state.first_seen = event.timestamp
            state.first_line = event.line_number
        if event.timestamp >= state.last_seen:
            state.last_seen = event.timestamp
            state.last_line = event.line_number
        state.matched.update(hits)
        snippet = text[:MAX_EVIDENCE_LENGTH]
        if len(state.evidence) < MAX_EVIDENCE_ITEMS and snippet not in state.evidence:
            state.evidence.append(snippet)

    def finish(self) -> list[Finding]:
        findings = [
            Finding(
                rule_id=self.rule.id,
                severity=self.rule.severity,
                source_ip=key,
                first_seen=state.first_seen,
                last_seen=state.last_seen,
                event_count=state.event_count,
                distinct_count=None,
                evidence=tuple(state.evidence),
                first_line=state.first_line,
                last_line=state.last_line,
                matched=tuple(self.match.patterns[index].name for index in sorted(state.matched)),
            )
            for key, state in self.states.items()
        ]
        self.states.clear()
        findings.sort(key=lambda finding: (finding.first_seen, finding.source_ip))
        return findings
