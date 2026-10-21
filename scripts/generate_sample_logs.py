import argparse
import random
from collections.abc import Sequence
from datetime import datetime, timedelta
from pathlib import Path

Entry = tuple[datetime, str]

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

DEFAULT_SEED = 42
START = datetime(2026, 3, 14, 8, 0, 0)
SPAN_SECONDS = 2 * 60 * 60
HOSTNAME = "web01"

NORMAL_NETWORKS = ("192.0.2.", "198.51.100.")

SSH_BRUTE_IP = "203.0.113.10"
SSH_SPRAY_IP = "203.0.113.20"
WEB_SCAN_IP = "203.0.113.30"
WEB_ATTACK_IP = "203.0.113.40"
SCANNER_UA_IP = "203.0.113.50"
ROLLOVER_IP = "203.0.113.60"
CRAWLER_IP = "198.51.100.99"

NORMAL_USERS = ("alice", "bob", "carol", "dave")
BRUTE_USERS = ("root", "deploy")
SPRAY_USERS = (
    "admin",
    "test",
    "user",
    "oracle",
    "postgres",
    "ubuntu",
    "guest",
    "git",
    "ftp",
    "www",
    "support",
    "jenkins",
    "info",
    "pi",
    "backup",
)

NORMAL_PATHS = (
    "/",
    "/index.html",
    "/about",
    "/contact",
    "/products",
    "/products/1",
    "/blog/hello-world",
    "/static/app.js",
    "/static/style.css",
    "/api/items",
    "/login",
    "/search?q=shoes",
    "/favicon.ico",
)
MISSING_PATHS = ("/old-page", "/missing.png", "/promo-2019", "/assets/old.css")
NORMAL_STATUSES = (200, 304, 301, 404, 500)
NORMAL_STATUS_WEIGHTS = (80, 8, 4, 7, 1)

NORMAL_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Safari/604.1",
)
GENERIC_UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"
CRAWLER_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
SCANNER_USER_AGENTS = (
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.5.0",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
)

WORDLIST = (
    "admin",
    "login",
    "wp-login.php",
    ".env",
    "backup.zip",
    "config.php",
    "phpmyadmin",
    "server-status",
    ".git/config",
    "api/v1/users",
    "old",
    "test",
    "dev",
    "uploads",
    "cgi-bin/test.cgi",
)

ATTACK_PATHS = (
    "/search?q=1%27%20UNION%20SELECT%20NULL,NULL--",
    "/product?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
    "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/comment?text=%3CSCRIPT%3Ealert(document.cookie)%3C/SCRIPT%3E",
    "/download?file=..%2F..%2F..%2Fetc%2Fpasswd",
    "/static/..%2f..%2f..%2fetc%2fhosts",
    "/view?page=../../../../etc/passwd",
    "/search?q=UN%2F%2A%2A%2FION%20SEL%2F%2A%2A%2FECT%20password",
)


def access_timestamp(moment: datetime) -> str:
    month = MONTHS[moment.month - 1]
    return f"{moment.day:02d}/{month}/{moment.year}:{moment:%H:%M:%S} +0000"


def syslog_timestamp(moment: datetime) -> str:
    return f"{MONTHS[moment.month - 1]} {moment.day:2d} {moment:%H:%M:%S}"


def access_entry(
    moment: datetime, ip: str, path: str, status: int, size: int, user_agent: str
) -> Entry:
    line = (
        f'{ip} - - [{access_timestamp(moment)}] "GET {path} HTTP/1.1" '
        f'{status} {size} "-" "{user_agent}"'
    )
    return moment, line


def ssh_entry(moment: datetime, pid: int, message: str) -> Entry:
    return moment, f"{syslog_timestamp(moment)} {HOSTNAME} sshd[{pid}]: {message}"


def normal_ip(rng: random.Random) -> str:
    return f"{rng.choice(NORMAL_NETWORKS)}{rng.randint(10, 60)}"


def random_moment(rng: random.Random) -> datetime:
    return START + timedelta(seconds=rng.randrange(SPAN_SECONDS))


def random_pid(rng: random.Random) -> int:
    return rng.randint(1000, 30000)


def random_port(rng: random.Random) -> int:
    return rng.randint(30000, 60000)


def generate_normal_access(rng: random.Random) -> list[Entry]:
    entries: list[Entry] = []
    for _ in range(400):
        moment = random_moment(rng)
        status = rng.choices(NORMAL_STATUSES, weights=NORMAL_STATUS_WEIGHTS)[0]
        path = rng.choice(MISSING_PATHS) if status == 404 else rng.choice(NORMAL_PATHS)
        size = rng.randint(200, 20000) if status == 200 else rng.randint(0, 600)
        entries.append(
            access_entry(moment, normal_ip(rng), path, status, size, rng.choice(NORMAL_USER_AGENTS))
        )
    return entries


def generate_crawler_404s() -> list[Entry]:
    base = START + timedelta(minutes=10)
    return [
        access_entry(
            base + timedelta(seconds=index * 3),
            CRAWLER_IP,
            f"/removed/page-{index}",
            404,
            153,
            CRAWLER_UA,
        )
        for index in range(32)
    ]


def generate_web_scan() -> list[Entry]:
    base = START + timedelta(minutes=45)
    entries: list[Entry] = []
    for index in range(45):
        word = WORDLIST[index % len(WORDLIST)]
        suffix = "" if index < len(WORDLIST) else f"-{index}"
        entries.append(
            access_entry(
                base + timedelta(seconds=index),
                WEB_SCAN_IP,
                f"/{word}{suffix}",
                404,
                153,
                GENERIC_UA,
            )
        )
    return entries


def generate_attack_strings() -> list[Entry]:
    base = START + timedelta(minutes=75)
    return [
        access_entry(
            base + timedelta(seconds=index * 10), WEB_ATTACK_IP, path, 200, 512, GENERIC_UA
        )
        for index, path in enumerate(ATTACK_PATHS)
    ]


def generate_scanner_user_agents() -> list[Entry]:
    base = START + timedelta(minutes=100)
    entries: list[Entry] = []
    for index, user_agent in enumerate(SCANNER_USER_AGENTS):
        for offset, path in enumerate(("/", "/index.html")):
            moment = base + timedelta(seconds=index * 20 + offset * 5)
            entries.append(access_entry(moment, SCANNER_UA_IP, path, 200, 1024, user_agent))
    return entries


def generate_normal_ssh(rng: random.Random) -> list[Entry]:
    entries: list[Entry] = []
    for _ in range(40):
        moment = random_moment(rng)
        message = (
            f"Accepted password for {rng.choice(NORMAL_USERS)} "
            f"from {normal_ip(rng)} port {random_port(rng)} ssh2"
        )
        entries.append(ssh_entry(moment, random_pid(rng), message))
    for _ in range(8):
        moment = random_moment(rng)
        user = rng.choice(NORMAL_USERS)
        ip = normal_ip(rng)
        failed = f"Failed password for {user} from {ip} port {random_port(rng)} ssh2"
        accepted = f"Accepted password for {user} from {ip} port {random_port(rng)} ssh2"
        entries.append(ssh_entry(moment, random_pid(rng), failed))
        entries.append(ssh_entry(moment + timedelta(seconds=6), random_pid(rng), accepted))
    return entries


def generate_ssh_brute_force(rng: random.Random) -> list[Entry]:
    base = START + timedelta(minutes=30)
    entries: list[Entry] = []
    for index in range(12):
        user = BRUTE_USERS[index % len(BRUTE_USERS)]
        message = f"Failed password for {user} from {SSH_BRUTE_IP} port {random_port(rng)} ssh2"
        entries.append(ssh_entry(base + timedelta(seconds=index * 7), random_pid(rng), message))
    return entries


def generate_ssh_spray(rng: random.Random) -> list[Entry]:
    base = START + timedelta(minutes=60)
    entries: list[Entry] = []
    for index, user in enumerate(SPRAY_USERS):
        moment = base + timedelta(seconds=index * 15)
        pid = random_pid(rng)
        port = random_port(rng)
        invalid = f"Invalid user {user} from {SSH_SPRAY_IP} port {port}"
        failed = f"Failed password for invalid user {user} from {SSH_SPRAY_IP} port {port} ssh2"
        entries.append(ssh_entry(moment, pid, invalid))
        entries.append(ssh_entry(moment + timedelta(seconds=1), pid, failed))
    return entries


def generate_rollover(rng: random.Random) -> list[Entry]:
    base = datetime(2025, 12, 31, 23, 58, 30)
    entries: list[Entry] = []
    for index in range(8):
        message = f"Failed password for root from {ROLLOVER_IP} port {random_port(rng)} ssh2"
        entries.append(ssh_entry(base + timedelta(seconds=index * 20), random_pid(rng), message))
    return entries


def write_lines(path: Path, entries: list[Entry]) -> None:
    ordered = sorted(entries, key=lambda entry: entry[0])
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for _, line in ordered:
            handle.write(f"{line}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="generate_sample_logs",
        description="Generate deterministic sample logs using reserved documentation IP ranges.",
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="random seed")
    parser.add_argument("--out-dir", type=Path, default=Path("tests/data"), help="output directory")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rng = random.Random(args.seed)
    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    access = [
        *generate_normal_access(rng),
        *generate_crawler_404s(),
        *generate_web_scan(),
        *generate_attack_strings(),
        *generate_scanner_user_agents(),
    ]
    auth = [
        *generate_normal_ssh(rng),
        *generate_ssh_brute_force(rng),
        *generate_ssh_spray(rng),
    ]
    rollover = generate_rollover(rng)

    write_lines(out_dir / "access.log", access)
    write_lines(out_dir / "auth.log", auth)
    write_lines(out_dir / "auth_rollover.log", rollover)

    print(f"seed={args.seed} out_dir={out_dir}")
    print(f"access.log: {len(access)} lines")
    print(f"auth.log: {len(auth)} lines")
    print(f"auth_rollover.log: {len(rollover)} lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
