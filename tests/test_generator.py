import importlib.util
import ipaddress
import re
from pathlib import Path
from types import ModuleType

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "generate_sample_logs.py"
OUTPUT_FILES = ("access.log", "auth.log", "auth_rollover.log")
RESERVED_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
AUTH_IP = re.compile(r"from (\S+) port")
SYSLOG_LINE = re.compile(r"^[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d web01 sshd\[\d+\]: \S")


def load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_sample_logs", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def is_reserved(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return any(address in network for network in RESERVED_NETWORKS)


def test_output_is_deterministic(tmp_path: Path) -> None:
    generator = load_generator()
    first = tmp_path / "first"
    second = tmp_path / "second"
    assert generator.main(["--out-dir", str(first)]) == 0
    assert generator.main(["--out-dir", str(second)]) == 0
    for name in OUTPUT_FILES:
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_different_seed_changes_output(tmp_path: Path) -> None:
    generator = load_generator()
    first = tmp_path / "first"
    second = tmp_path / "second"
    generator.main(["--seed", "1", "--out-dir", str(first)])
    generator.main(["--seed", "2", "--out-dir", str(second)])
    assert (first / "access.log").read_bytes() != (second / "access.log").read_bytes()


def test_only_reserved_documentation_ips(tmp_path: Path) -> None:
    generator = load_generator()
    generator.main(["--out-dir", str(tmp_path)])
    access_lines = (tmp_path / "access.log").read_text(encoding="utf-8").splitlines()
    assert access_lines
    for line in access_lines:
        assert is_reserved(line.split(" ", 1)[0])
    for name in ("auth.log", "auth_rollover.log"):
        text = (tmp_path / name).read_text(encoding="utf-8")
        found = AUTH_IP.findall(text)
        assert found
        for value in found:
            assert is_reserved(value)


def test_auth_lines_use_syslog_format(tmp_path: Path) -> None:
    generator = load_generator()
    generator.main(["--out-dir", str(tmp_path)])
    for name in ("auth.log", "auth_rollover.log"):
        lines = (tmp_path / name).read_text(encoding="utf-8").splitlines()
        assert lines
        for line in lines:
            assert SYSLOG_LINE.match(line), line


def test_rollover_file_crosses_new_year(tmp_path: Path) -> None:
    generator = load_generator()
    generator.main(["--out-dir", str(tmp_path)])
    lines = (tmp_path / "auth_rollover.log").read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("Dec 31 ")
    assert lines[-1].startswith("Jan  1 ")
