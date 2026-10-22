from pathlib import Path

import pytest

from log_analyzer.parsers.common import RawLine, iter_lines


def write(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


def test_reads_lines_with_numbers(tmp_path: Path) -> None:
    path = write(tmp_path / "a.log", b"one\ntwo\nthree\n")
    assert list(iter_lines(path)) == [
        RawLine(1, "one", False),
        RawLine(2, "two", False),
        RawLine(3, "three", False),
    ]


def test_last_line_without_newline_is_kept(tmp_path: Path) -> None:
    path = write(tmp_path / "a.log", b"one\ntwo")
    assert list(iter_lines(path)) == [RawLine(1, "one", False), RawLine(2, "two", False)]


def test_crlf_line_endings(tmp_path: Path) -> None:
    path = write(tmp_path / "a.log", b"one\r\ntwo\r\n")
    assert [line.text for line in iter_lines(path)] == ["one", "two"]


def test_empty_file(tmp_path: Path) -> None:
    path = write(tmp_path / "a.log", b"")
    assert list(iter_lines(path)) == []


def test_line_at_limit_is_kept(tmp_path: Path) -> None:
    path = write(tmp_path / "a.log", b"a" * 10 + b"\n")
    assert list(iter_lines(path, max_line_length=10)) == [RawLine(1, "a" * 10, False)]


def test_line_over_limit_is_flagged_and_next_line_survives(tmp_path: Path) -> None:
    path = write(tmp_path / "a.log", b"a" * 11 + b"\nnext\n")
    assert list(iter_lines(path, max_line_length=10)) == [
        RawLine(1, "", True),
        RawLine(2, "next", False),
    ]


def test_oversized_final_line_without_newline(tmp_path: Path) -> None:
    path = write(tmp_path / "a.log", b"ok\n" + b"a" * 50)
    assert list(iter_lines(path, max_line_length=10)) == [
        RawLine(1, "ok", False),
        RawLine(2, "", True),
    ]


def test_huge_line_does_not_break_following_lines(tmp_path: Path) -> None:
    path = write(tmp_path / "a.log", b"a" * 5_000_000 + b"\nafter\n")
    assert list(iter_lines(path, max_line_length=100)) == [
        RawLine(1, "", True),
        RawLine(2, "after", False),
    ]


def test_invalid_utf8_is_replaced(tmp_path: Path) -> None:
    path = write(tmp_path / "a.log", b"ab\xff\xfecd\n")
    assert [line.text for line in iter_lines(path)] == ["ab\ufffd\ufffdcd"]


def test_invalid_limit_is_rejected(tmp_path: Path) -> None:
    path = write(tmp_path / "a.log", b"one\n")
    with pytest.raises(ValueError, match="max_line_length"):
        list(iter_lines(path, max_line_length=0))
