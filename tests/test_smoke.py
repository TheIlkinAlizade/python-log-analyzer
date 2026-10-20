import pytest

from log_analyzer import __version__
from log_analyzer.cli import EXIT_ERROR, EXIT_OK, main


def test_version_is_set() -> None:
    assert __version__


def test_main_without_arguments_returns_ok() -> None:
    assert main([]) == EXIT_OK


def test_unknown_option_exits_with_usage_error() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--does-not-exist"])
    assert excinfo.value.code == EXIT_ERROR
