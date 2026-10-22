from datetime import datetime

from log_analyzer.parsers.ssh import YearResolver

NOW = datetime(2026, 10, 22, 12, 0, 0)


def test_explicit_year_is_used_and_not_marked_as_assumed() -> None:
    resolver = YearResolver(year=2024, now=NOW)
    assert resolver.resolve(3, 1, 8, 0, 0) == datetime(2024, 3, 1, 8, 0, 0)
    assert resolver.year_assumed is False
    assert resolver.first_year == 2024


def test_guess_uses_current_year_when_not_in_the_future() -> None:
    resolver = YearResolver(now=NOW)
    assert resolver.resolve(10, 21, 14, 3, 11) == datetime(2026, 10, 21, 14, 3, 11)
    assert resolver.year_assumed is True


def test_guess_uses_previous_year_when_timestamp_would_be_in_the_future() -> None:
    resolver = YearResolver(now=datetime(2026, 1, 10))
    assert resolver.resolve(12, 31, 23, 59, 0) == datetime(2025, 12, 31, 23, 59, 0)


def test_guess_finds_most_recent_leap_year_for_feb_29() -> None:
    resolver = YearResolver(now=NOW)
    assert resolver.resolve(2, 29, 10, 0, 0) == datetime(2024, 2, 29, 10, 0, 0)


def test_impossible_date_is_rejected_without_changing_state() -> None:
    resolver = YearResolver(now=NOW)
    assert resolver.resolve(2, 30, 10, 0, 0) is None
    assert resolver.first_year is None
    assert resolver.current_year is None


def test_explicit_year_rejects_feb_29_in_non_leap_year() -> None:
    resolver = YearResolver(year=2025, now=NOW)
    assert resolver.resolve(2, 29, 1, 0, 0) is None


def test_rollover_from_december_to_january() -> None:
    resolver = YearResolver(year=2025, now=NOW)
    assert resolver.resolve(12, 31, 23, 59, 0) == datetime(2025, 12, 31, 23, 59, 0)
    assert resolver.resolve(1, 1, 0, 1, 0) == datetime(2026, 1, 1, 0, 1, 0)
    assert resolver.resolve(1, 2, 0, 1, 0) == datetime(2026, 1, 2, 0, 1, 0)


def test_rollover_with_a_gap_in_months() -> None:
    resolver = YearResolver(year=2025, now=NOW)
    assert resolver.resolve(11, 30, 10, 0, 0) == datetime(2025, 11, 30, 10, 0, 0)
    assert resolver.resolve(1, 2, 10, 0, 0) == datetime(2026, 1, 2, 10, 0, 0)


def test_small_backward_steps_do_not_roll_the_year() -> None:
    resolver = YearResolver(year=2026, now=NOW)
    assert resolver.resolve(10, 25, 2, 30, 0) == datetime(2026, 10, 25, 2, 30, 0)
    assert resolver.resolve(10, 25, 1, 30, 0) == datetime(2026, 10, 25, 1, 30, 0)
    assert resolver.resolve(11, 1, 0, 0, 0) == datetime(2026, 11, 1, 0, 0, 0)
    assert resolver.resolve(10, 31, 23, 0, 0) == datetime(2026, 10, 31, 23, 0, 0)


def test_failed_rollover_does_not_corrupt_state() -> None:
    resolver = YearResolver(year=2025, now=NOW)
    assert resolver.resolve(12, 31, 23, 0, 0) == datetime(2025, 12, 31, 23, 0, 0)
    assert resolver.resolve(2, 29, 0, 0, 0) is None
    assert resolver.resolve(1, 1, 0, 0, 0) == datetime(2026, 1, 1, 0, 0, 0)
