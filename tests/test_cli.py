import io
import json
from pathlib import Path
from typing import Any

import pytest

from log_analyzer.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, emit, main

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules" / "default.yml"
ACCESS = ROOT / "tests" / "data" / "access.log"
AUTH = ROOT / "tests" / "data" / "auth.log"

NORMAL_LINE = (
    '203.0.113.5 - - [14/Mar/2026:08:00:01 +0000] "GET /index.html HTTP/1.1" '
    '200 512 "-" "Mozilla/5.0"'
)

DISABLED_RULES = """\
rules:
  - id: WEB-900
    title: Disabled rule
    description: A rule that is switched off.
    severity: high
    log_type: access
    type: pattern
    enabled: false
    match:
      field: decoded_url
      patterns:
        - kind: contains
          name: dots
          value: '../'
    remediation: None needed.
    false_positive_notes: None.
"""


def sample_args(*extra: str) -> list[str]:
    return [
        "--access-log",
        str(ACCESS),
        "--ssh-log",
        str(AUTH),
        "--rules",
        str(RULES),
        "--year",
        "2026",
        *extra,
    ]


def run_json(capsys: pytest.CaptureFixture[str], argv: list[str]) -> tuple[int, dict[str, Any]]:
    code = main([*argv, "--json"])
    report: dict[str, Any] = json.loads(capsys.readouterr().out)
    return code, report


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--access-log", str(ACCESS), "--year", "2026"],
        ["--ssh-log", str(AUTH), "--year", "1800"],
        ["--ssh-log", str(AUTH), "--year", "abc"],
        ["--ssh-log", str(AUTH), "--fail-on", "urgent"],
        ["--ssh-log"],
    ],
)
def test_usage_errors_exit_with_code_two(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as info:
        main(argv)
    assert info.value.code == EXIT_ERROR


def test_missing_inputs_message(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main([])
    assert "at least one of --access-log or --ssh-log" in capsys.readouterr().err


def test_missing_input_file_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["--access-log", str(tmp_path / "missing.log"), "--rules", str(RULES)])
    captured = capsys.readouterr()
    assert code == EXIT_ERROR
    assert "not a readable file" in captured.err
    assert captured.out == ""


def test_directory_as_input_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["--ssh-log", str(tmp_path), "--rules", str(RULES)])
    assert code == EXIT_ERROR
    assert "not a readable file" in capsys.readouterr().err


def test_invalid_rules_file_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: 5\n", encoding="utf-8")
    code = main(["--access-log", str(ACCESS), "--rules", str(rules)])
    captured = capsys.readouterr()
    assert code == EXIT_ERROR
    assert "rules: must be a non-empty list" in captured.err
    assert captured.out == ""


def test_missing_rules_file_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["--access-log", str(ACCESS), "--rules", str(tmp_path / "none.yml")])
    assert code == EXIT_ERROR
    assert "cannot read rules file" in capsys.readouterr().err


def test_sample_logs_fail_at_the_default_threshold(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(sample_args())
    out = capsys.readouterr().out
    assert code == EXIT_FINDINGS
    assert "Result: FAIL" in out


def test_fail_on_critical_passes_for_the_samples(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(sample_args("--fail-on", "critical"))
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "Result: OK" in out


def test_fail_on_medium_fails_for_the_samples() -> None:
    assert main(sample_args("--fail-on", "medium")) == EXIT_FINDINGS


def test_ssh_only_run_evaluates_only_ssh_rules(capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["--ssh-log", str(AUTH), "--rules", str(RULES), "--year", "2026"]
    code, report = run_json(capsys, argv)
    assert code == EXIT_FINDINGS
    assert {rule["id"] for rule in report["rules"]} == {"SSH-001", "SSH-002"}
    assert [item["log_type"] for item in report["inputs"]] == ["ssh"]


def test_access_only_run_evaluates_only_web_rules(capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["--access-log", str(ACCESS), "--rules", str(RULES)]
    code, report = run_json(capsys, argv)
    assert code == EXIT_FINDINGS
    assert {rule["id"] for rule in report["rules"]} == {"WEB-001", "WEB-002", "WEB-003"}


def test_json_report_for_the_samples(capsys: pytest.CaptureFixture[str]) -> None:
    code, report = run_json(capsys, sample_args())
    summary = report["summary"]
    assert code == EXIT_FINDINGS
    assert report["failed"] is True
    assert report["fail_on"] == "high"
    assert report["warnings"] == []
    assert summary["total_lines"] == 589
    assert summary["parsed_lines"] == 589
    assert summary["ignored_lines"] == 0
    assert summary["failed_lines"] == 0
    assert summary["findings"] == 7
    assert summary["severity_counts"] == {"critical": 0, "high": 4, "medium": 3, "low": 0}
    assert report["findings_at_or_above_fail_on"] == 4
    assert [rule["id"] for rule in report["rules"]] == [
        "SSH-001",
        "SSH-002",
        "WEB-002",
        "WEB-001",
        "WEB-003",
    ]
    assert [entry["source_ip"] for entry in report["top_offenders"]] == [
        "203.0.113.20",
        "203.0.113.10",
        "203.0.113.40",
        "203.0.113.30",
        "198.51.100.99",
        "203.0.113.50",
    ]
    assert report["top_offenders"][0]["findings"] == 2
    assert report["top_offenders"][0]["events"] == 45


def test_text_report_for_the_samples(capsys: pytest.CaptureFixture[str]) -> None:
    main(sample_args())
    out = capsys.readouterr().out
    for expected in [
        "SSH-001",
        "SSH-002",
        "WEB-001",
        "WEB-002",
        "WEB-003",
        "Top offending IPs",
        "203.0.113.20",
        "198.51.100.99",
        "Fix:",
        "Possible false positives:",
        "Result: FAIL",
    ]:
        assert expected in out


def test_output_is_deterministic(capsys: pytest.CaptureFixture[str]) -> None:
    main(sample_args())
    first = capsys.readouterr().out
    main(sample_args())
    second = capsys.readouterr().out
    assert first == second


def test_assumed_year_is_reported_as_a_warning(capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["--ssh-log", str(AUTH), "--rules", str(RULES)]
    code, report = run_json(capsys, argv)
    assert code == EXIT_FINDINGS
    assert len(report["warnings"]) == 1
    assert "assumed" in report["warnings"][0]
    assert "--year" in report["warnings"][0]
    assert report["inputs"][0]["year_assumed"] is True


def test_clean_log_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = tmp_path / "access.log"
    log.write_text(NORMAL_LINE + "\n", encoding="utf-8")
    code = main(["--access-log", str(log), "--rules", str(RULES)])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "No findings." in out


def test_unparseable_file_produces_a_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = tmp_path / "bad.log"
    log.write_text("garbage\nmore garbage\n", encoding="utf-8")
    code, report = run_json(capsys, ["--access-log", str(log), "--rules", str(RULES)])
    assert code == EXIT_OK
    assert report["summary"]["failed_lines"] == 2
    assert any("could be parsed" in warning for warning in report["warnings"])


def test_disabled_rules_are_not_evaluated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rules = tmp_path / "rules.yml"
    rules.write_text(DISABLED_RULES, encoding="utf-8")
    code, report = run_json(capsys, ["--access-log", str(ACCESS), "--rules", str(rules)])
    assert code == EXIT_OK
    assert report["rules"] == []
    assert report["summary"]["findings"] == 0


def test_escape_sequences_in_access_logs_never_reach_the_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    line = (
        '203.0.113.7 - - [14/Mar/2026:08:00:01 +0000] "GET /a/../\x1b[2Jb HTTP/1.1" '
        '200 5 "-" "Mozilla"\n'
    )
    log = tmp_path / "access.log"
    log.write_text(line, encoding="utf-8")
    argv = ["--access-log", str(log), "--rules", str(RULES)]
    assert main(argv) == EXIT_FINDINGS
    text = capsys.readouterr().out
    assert "/a/../b" in text
    assert "\x1b" not in text
    assert "[2J" not in text
    assert all(char == "\n" or char.isprintable() for char in text)
    code, report = run_json(capsys, argv)
    assert code == EXIT_FINDINGS
    assert report["rules"][0]["id"] == "WEB-002"
    assert report["rules"][0]["findings"][0]["evidence"] == ["/a/../b"]


def test_escape_sequences_in_ssh_logs_never_reach_the_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prefix = "web01 sshd[1]: Failed password for "
    suffix = " from 203.0.113.9 port 22 ssh2"
    lines = [f"Mar 14 08:00:0{number} {prefix}\x1b[31mroot{suffix}" for number in range(1, 6)]
    log = tmp_path / "auth.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    argv = ["--ssh-log", str(log), "--rules", str(RULES), "--year", "2026"]
    assert main(argv) == EXIT_FINDINGS
    text = capsys.readouterr().out
    assert "root" in text
    assert "\x1b" not in text
    assert "[31m" not in text
    assert all(char == "\n" or char.isprintable() for char in text)
    code, report = run_json(capsys, argv)
    assert code == EXIT_FINDINGS
    assert report["rules"][0]["id"] == "SSH-001"
    assert report["rules"][0]["findings"][0]["evidence"] == ["root"]


def test_emit_replaces_characters_the_stream_cannot_encode() -> None:
    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="ascii", newline="\n")
    emit("caf\u00e9", stream)
    stream.flush()
    assert buffer.getvalue() == b"caf?\n"
