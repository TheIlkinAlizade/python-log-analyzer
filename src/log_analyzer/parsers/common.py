from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

DEFAULT_MAX_LINE_LENGTH = 8192


class RawLine(NamedTuple):
    number: int
    text: str
    oversized: bool


def iter_lines(path: Path, max_line_length: int = DEFAULT_MAX_LINE_LENGTH) -> Iterator[RawLine]:
    if max_line_length < 1:
        raise ValueError("max_line_length must be at least 1")
    with path.open("r", encoding="utf-8", errors="replace", newline=None) as handle:
        number = 0
        while True:
            chunk = handle.readline(max_line_length + 1)
            if not chunk:
                return
            number += 1
            if chunk.endswith("\n"):
                yield RawLine(number, chunk[:-1], False)
                continue
            if len(chunk) <= max_line_length:
                yield RawLine(number, chunk, False)
                continue
            while True:
                rest = handle.readline(max_line_length + 1)
                if not rest or rest.endswith("\n"):
                    break
            yield RawLine(number, "", True)
