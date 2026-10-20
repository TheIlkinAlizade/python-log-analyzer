import argparse
from collections.abc import Sequence

from log_analyzer import __version__

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Offline analyzer for web server and SSH logs. Defensive use only.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    return EXIT_OK
