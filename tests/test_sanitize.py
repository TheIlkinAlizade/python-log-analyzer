import time

import pytest

from log_analyzer.sanitize import DEFAULT_MAX_LENGTH, clean


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("plain text", "plain text"),
        ("", ""),
        ("\x1b[31mred\x1b[0m", "red"),
        ("\x1b[2J\x1b[Hcleared", "cleared"),
        ("\x1b[1;38;5;196mbold\x1b[m", "bold"),
        ("\x1b]0;evil title\x07text", "text"),
        ("\x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\", "link"),
        ("\x1b(Bx", "x"),
        ("a\x1bcb", "ab"),
        ("a\x1b1b", "a?1b"),
        ("abc\x1b", "abc?"),
        ("a\nb\rc\td\x00e\x7ff", "a?b?c?d?e?f"),
        ("\x9b31m", "?31m"),
        ("\u202eevil\u202c", "?evil?"),
        ("a\u2028b\u2029c", "a?b?c"),
        ("\u200bzero", "?zero"),
        ("caf\u00e9 \u65e5\u672c", "caf\u00e9 \u65e5\u672c"),
    ],
)
def test_clean_text(raw: str, expected: str) -> None:
    assert clean(raw) == expected


def test_long_text_is_truncated_with_ellipsis() -> None:
    assert clean("a" * 50, 10) == "a" * 7 + "..."


def test_text_at_the_limit_is_unchanged() -> None:
    assert clean("a" * 10, 10) == "a" * 10


def test_tiny_limit_has_no_ellipsis() -> None:
    assert clean("abcdef", 3) == "abc"


def test_limit_applies_after_stripping_escape_sequences() -> None:
    assert clean("\x1b[31m" + "a" * 10, 10) == "a" * 10


def test_default_limit_is_applied() -> None:
    assert len(clean("a" * 5000)) == DEFAULT_MAX_LENGTH


def test_invalid_limit_is_rejected() -> None:
    with pytest.raises(ValueError, match="max_length"):
        clean("x", 0)


def test_adversarial_input_finishes_quickly() -> None:
    samples = [
        ("\x1b[" + "0" * 50) * 4000,
        "\x1b]" + "a" * 200_000,
        "\x1b" * 200_000,
        "\x1b(" * 100_000,
    ]
    started = time.perf_counter()
    for sample in samples:
        clean(sample, 100)
    assert time.perf_counter() - started < 5.0
