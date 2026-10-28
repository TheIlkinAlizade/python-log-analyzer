# python-log-analyzer

![CI](https://github.com/TheIlkinAlizade/python-log-analyzer/actions/workflows/ci.yml/badge.svg)

Offline CLI that analyzes web server and SSH logs for suspicious activity using editable YAML detection rules, with severity ratings, explanations, and fix advice. Defensive and educational.

> **Do not publish real logs.** Real logs contain IP addresses, usernames and other personal data. Use only generated or properly anonymized logs in issues, screenshots, tests and pull requests. This repository's sample logs are generated and use only the reserved documentation IP ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24. Reports from this tool also contain IPs and usernames, so treat them as sensitive too.

## What it does and who it's for

`log-analyzer` reads nginx/Apache access logs (combined format) and SSH `auth.log` files, applies detection rules from a YAML file, and prints a summary of suspicious activity. Each finding has a severity, an explanation, fix advice and notes about likely false positives.

It is for students, junior SOC analysts and engineers who want a small, readable example of log-based detection, and for anyone who wants a quick first look at a log file. It is not a SIEM, an IDS or a replacement for either.

Everything runs locally. The tool only reads the files you give it. It makes no network requests and sends nothing anywhere.

## Install

Requires Python 3.11 or newer. The only dependency is PyYAML. The project is not published on PyPI, so install from source:

```bash
git clone https://github.com/TheIlkinAlizade/python-log-analyzer.git
cd python-log-analyzer
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`. For development (tests, ruff, mypy) use `pip install -e ".[dev]"`.

## Usage

```bash
log-analyzer --access-log access.log --ssh-log auth.log --year 2026
```

| Option | Meaning |
|---|---|
| `--access-log PATH` | nginx/Apache combined-format access log |
| `--ssh-log PATH` | SSH `auth.log` in traditional syslog format |
| `--rules PATH` | rules file (default `rules/default.yml`, relative to the current directory) |
| `--year YYYY` | year of the first line of the SSH log (see "Syslog has no year") |
| `--fail-on LEVEL` | `low`, `medium`, `high` or `critical`; default `high` |
| `--json` | print the report as JSON |
| `--version` | print the version |

At least one of `--access-log` or `--ssh-log` is required. `--year` only applies to the SSH log. Because the default rules path is relative, run the tool from the repository root or pass `--rules` explicitly.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | no findings at or above `--fail-on` |
| 1 | at least one finding at or above `--fail-on` |
| 2 | usage or input error (missing file, bad option, invalid rules file) |

This makes it usable in scripts: `log-analyzer --access-log access.log --fail-on medium || echo "review needed"`.

## Sample data and sample output

Sample logs live in `tests/data/` and are produced by a seeded generator, so they are identical on every run:

```bash
python scripts/generate_sample_logs.py
```

They contain normal traffic plus injected attacks, one crawler that looks like a scanner (a deliberate false positive), and one request that evades the pattern rules (a deliberate miss).

Output for `log-analyzer --access-log tests/data/access.log --ssh-log tests/data/auth.log --year 2026`, captured on Windows PowerShell (so the paths use backslashes):

```text
log-analyzer 0.1.1
==================

Inputs
  ssh     tests\data\auth.log
          lines 98, parsed 98, ignored 0, failed 0 (oversized 0)
          year 2026 (set with --year)
  access  tests\data\access.log
          lines 491, parsed 491, ignored 0, failed 0 (oversized 0)
  total   lines 589, parsed 589, ignored 0, failed 0

Findings: 7  (critical 0, high 4, medium 3, low 0)

[HIGH] SSH-001  SSH brute force  (2 findings)
  Many failed SSH logins from one IP within a short window.
  MITRE ATT&CK: T1110.001
  - 203.0.113.10: 12 events
    2026-03-14T08:30:00 -> 2026-03-14T08:31:17 (server local time), log lines 15-27
    examples:
      root
      deploy
  - 203.0.113.20: 15 events
    2026-03-14T09:00:01 -> 2026-03-14T09:03:31 (server local time), log lines 41-70
    examples:
      admin
      test
      user
      oracle
      postgres
  Fix: Use key-based authentication, disable password login, add fail2ban or rate limiting.
  Possible false positives: A user mistyping a password, or many users behind one corporate NAT address.

[HIGH] SSH-002  Password spraying or credential stuffing  (1 finding)
  One IP trying many different usernames within a short window.
  MITRE ATT&CK: T1110.003, T1110.004
  - 203.0.113.20: 30 events, 15 distinct usernames
    2026-03-14T09:00:00 -> 2026-03-14T09:03:31 (server local time), log lines 40-70
    examples:
      admin
      test
      user
      oracle
      postgres
  Fix: Disable password login, enforce MFA, restrict SSH by IP or VPN.
  Possible false positives: Shared bastion hosts or NAT gateways where many real users log in from one address.

[HIGH] WEB-002  Attack strings in request  (1 finding)
  SQL injection, XSS or path traversal patterns in the decoded URL.
  MITRE ATT&CK: T1190
  - 203.0.113.40: 7 events
    2026-03-14T09:15:00+00:00 -> 2026-03-14T09:16:00+00:00 (UTC), log lines 324-335
    matched: sqli-union-select, xss-script-tag, path-traversal
    examples:
      /search?q=1' UNION SELECT NULL,NULL--
      /product?id=1 UNION SELECT username,password FROM users
      /search?q=<script>alert(1)</script>
      /comment?text=<SCRIPT>alert(document.cookie)</SCRIPT>
      /download?file=../../../etc/passwd
  Fix: Use parameterised queries, output encoding and input validation. Check the application, not just the log.
  Possible false positives: Security scanners you run yourself, and developers pasting payloads into bug reports or search boxes.

[MEDIUM] WEB-001  Web scanning  (2 findings)
  Many 404 responses to one IP within a short window.
  MITRE ATT&CK: T1595.003
  - 198.51.100.99: 32 events
    2026-03-14T08:10:00+00:00 -> 2026-03-14T08:11:33+00:00 (UTC), log lines 28-66
    examples:
      /removed/page-0
      /removed/page-1
      /removed/page-2
      /removed/page-3
      /removed/page-4
  - 203.0.113.30: 45 events
    2026-03-14T08:45:00+00:00 -> 2026-03-14T08:45:44+00:00 (UTC), log lines 173-221
    examples:
      /admin
      /login
      /wp-login.php
      /.env
      /backup.zip
  Fix: Rate-limit or block the source, and make sure no sensitive paths are exposed.
  Possible false positives: Broken links after a site migration, or search engine crawlers hitting removed pages.

[MEDIUM] WEB-003  Known scanner user agent  (1 finding)
  Request sent with a user agent that names a known scanning tool.
  MITRE ATT&CK: T1595.002
  - 203.0.113.50: 6 events
    2026-03-14T09:40:00+00:00 -> 2026-03-14T09:40:45+00:00 (UTC), log lines 404-411
    matched: sqlmap, nikto, nmap
    examples:
      sqlmap/1.7.2#stable (https://sqlmap.org)
      Nikto/2.5.0
      Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
  Fix: Block or rate-limit the source and review what it requested.
  Possible false positives: Your own authorised scans. Attackers can trivially change the user agent, so absence of a match proves nothing.

Top offending IPs
  1. 203.0.113.20  highest high, findings 2, events 45
  2. 203.0.113.10  highest high, findings 1, events 12
  3. 203.0.113.40  highest high, findings 1, events 7
  4. 203.0.113.30  highest medium, findings 1, events 45
  5. 198.51.100.99  highest medium, findings 1, events 32
  6. 203.0.113.50  highest medium, findings 1, events 6

Result: FAIL - 4 finding(s) at or above 'high'
Note: findings come only from the supplied logs and the active rules. No findings does not prove that no attack happened.
```

## Rules in v0.1.1

| ID | Severity | Log | What it detects | Default thresholds | MITRE ATT&CK |
|---|---|---|---|---|---|
| SSH-001 | high | ssh | SSH brute force: many failed password logins from one IP | 5 `failed_password` events within 5 minutes | T1110.001 |
| SSH-002 | high | ssh | Password spraying or credential stuffing: one IP trying many usernames | 10 distinct usernames (from `failed_password` and `invalid_user` events) within 10 minutes | T1110.003, T1110.004 |
| WEB-001 | medium | access | Web scanning: many 404 responses to one IP | 30 responses with status 404 within 2 minutes | T1595.003 |
| WEB-002 | high | access | Attack strings in the decoded URL: SQL injection (`union\s+select`), XSS (`<script`), path traversal (`../`) | one matching request | T1190 |
| WEB-003 | medium | access | Known scanner user agents: `sqlmap`, `nikto`, `nmap` | one matching request | T1595.002 |

SSH-002 lists both T1110.003 and T1110.004 because `auth.log` never contains the passwords. The tool can see many usernames from one IP but cannot tell spraying from stuffing. WEB-002 maps to T1190 because the log shows an attempt, not a successful exploit.

The MITRE IDs were checked against attack.mitre.org. The tool itself only checks that an ID looks like `T1234` or `T1234.567`; it does not verify that the technique exists.

## How detection works

- **Parsing.** Files are streamed line by line (never loaded whole), decoded as UTF-8 with invalid bytes replaced, and each line is capped at 8192 characters. Every line ends up as parsed, ignored (valid syslog the tool does not track, such as CRON) or failed. Counts of each are shown in the report.
- **Threshold rules** (`type: threshold`). For each source IP, the tool keeps a sliding window of timestamps in a `collections.deque`. Old entries fall out of the window, and when the count (or the number of distinct usernames) reaches the threshold, a burst starts. Later events from that IP extend the burst, and it ends after a quiet gap longer than the window. One burst produces one finding, not one per line.
- **Pattern rules** (`type: pattern`). Each request is checked against the rule's patterns, either literal substrings (`contains`) or regular expressions. URLs are percent-decoded once before matching. There is one finding per source IP and rule, with the request count, matched pattern names and up to five examples.
- **Rules are data.** Rules live in a YAML file. You can edit or add rules without changing code.

### Rule format

```yaml
- id: SSH-001
  title: SSH brute force
  description: Many failed SSH logins from one IP within a short window.
  severity: high
  log_type: ssh
  type: threshold
  mitre_attack: [T1110.001]
  threshold:
    events: [failed_password]
    group_by: source_ip
    count: 5
    window_minutes: 5
  remediation: Use key-based authentication, disable password login, add fail2ban or rate limiting.
  false_positive_notes: A user mistyping a password, or many users behind one corporate NAT address.
```

Unknown fields, wrong types and out-of-range numbers are rejected with a message that names the rule and field. All errors in a file are reported together. Pattern rules are supported for access logs only.

### Syslog has no year

SSH `auth.log` lines look like `Oct  1 14:03:11 web01 sshd[1234]: ...`. There is no year and no timezone.

- Use `--year` to give the year of the first line. Without it, the tool assumes the most recent year in which the first timestamp is not in the future, and prints a warning saying so. Close to New Year, or for logs from another timezone, set `--year` explicitly.
- If the month number drops by more than six between lines (for example December to January), the year is incremented, so a file that crosses New Year is handled. Small backward steps, such as a DST change, do not trigger this.
- SSH timestamps are shown as server local time, as logged. Access log timestamps carry an offset and are converted to UTC. The report never compares the two.
- A `Feb 29` line in a non-leap year counts as a parse failure.

## Security design

- Log contents are untrusted input. The parsers count bad lines and skip them. They do not crash on malformed lines, invalid UTF-8, huge lines, or very large numbers.
- The parsers' regular expressions are written without nested or overlapping quantifiers, and tests feed adversarial lines and check that parsing stays fast.
- Everything printed from a log (IPs, usernames, URLs, user agents) passes through a sanitiser that removes ANSI escape sequences and replaces control, format and line-separator characters with `?`. This applies to the terminal report and to the JSON output.
- Rules files are loaded with `yaml.safe_load`. YAML anchors and aliases are rejected, the file size is capped, and regular expressions are length-limited, compiled at load time and rejected if they match empty text.
- Memory is bounded: thresholds keep a fixed-size window per IP, pattern rules track at most 100,000 sources, and each finding keeps at most five examples.

## False positives

Findings are indicators to investigate, not proof of an attack.

- **A user mistyping a password** can trigger SSH-001, and so can a script using an expired password or key.
- **A corporate NAT, VPN exit or shared bastion host** puts many real users behind one IP. This can trigger SSH-001, SSH-002 and WEB-001.
- **A search engine crawler** that requests removed pages can look like a scanner to WEB-001. The sample data includes one on purpose (`198.51.100.99`).
- **Broken links after a site migration** produce bursts of 404s from normal visitors.
- **Your own security scans** trigger WEB-002 and WEB-003, as do developers pasting payloads into search boxes or bug reports.
- **Monitoring and load testing tools** can produce bursts that look like scanning.

Each rule has a `false_positive_notes` field that appears in the report.

## Limitations

- **Coverage is small.** Five rules, password-based SSH events only (`Failed password`, `Accepted password`, `Invalid user`). Public key and keyboard-interactive events are not analyzed.
- **No log rotation handling.** One plain-text file per log type per run. Compressed or rotated logs must be combined beforehand.
- **Formats.** Only the combined access log format and the traditional syslog timestamp format. ISO 8601 timestamps in `auth.log` are not supported.
- **rsyslog "message repeated N times" lines are ignored**, so a real brute force can be undercounted.
- **IP addresses are not identities.** The tool groups by the address in the log. Behind a reverse proxy or CDN every request may show the proxy's address (`X-Forwarded-For` is not used), NAT merges users, and an attacker using many IPs stays under per-IP thresholds.
- **Pattern rules are easy to evade.** URLs are decoded once, so double encoding is missed. Inline comments such as `UN/**/ION SEL/**/ECT`, unusual spacing, other encodings and many other tricks defeat the default patterns. The sample data contains one such request that is deliberately not detected. A scanner can change its user agent. A match on a pattern means "someone tried", never "the application is vulnerable".
- **Thresholds are guesses.** The defaults suit the sample data, not your traffic. Tune them.
- **Bursts end after a quiet gap**, so a slow trickle after a burst stays in the same finding.
- **The "Top offending IPs" table adds up events across rules.** The same log line can count in more than one rule, so its `events` column is not a count of distinct log lines.
- **Rule regexes are not analyzed for catastrophic backtracking.** Python's `re` has no timeout, so a badly written custom regex can be slow. Keep patterns simple.
- **Reports are sanitized, not byte-exact.** Control characters appear as `?`. Use the line numbers to look at the original line.
- **The default rules path is relative to the current directory**, and the rules file is not bundled into an installed package.
- **No findings does not mean no attack.** It means the supplied logs matched none of the active rules.

## Threat model

**What is protected:** the analyst's terminal and machine, and the honesty of the report.

**Attacker model:** the attacker controls the content of log lines (usernames, URLs, user agents, line length and count) because they choose what they send to the server. They may try to crash or slow the tool, to inject terminal escape sequences or fake lines into the report, to stay under thresholds, or to evade patterns. The command line and the rules file are treated as trusted operator input, but the rules file is still validated.

**What the tool does about it:** streaming with a line-length cap, bounded memory, bad lines counted and skipped, output sanitising, safe YAML loading with validation, and tests for malformed and adversarial input.

**Out of scope:** an attacker who can edit the logs themselves (log tampering), real-time detection or blocking, host compromise, spoofed log sources, and forensic completeness. The tool does not prevent anything. It reports.

## Development

```bash
pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy
pytest
```

CI runs the same checks on Python 3.11, 3.12 and 3.13, and checks that the committed sample logs match the generator output.

## Project status

This is a hobby and portfolio project, released as is. It will not receive regular updates, and bugs or security issues may stay unfixed. Pull requests and forks are welcome. The Limitations section lists what the tool does not do, so read it before relying on any result.

## Disclaimer

Use this tool only on logs you are authorized to analyze. It is provided as is, without warranty, for defensive and educational purposes. It is not a substitute for a SIEM, an IDS, a WAF or professional incident response. Findings are indicators, not proof, and absence of findings is not proof of safety. There is no guarantee of maintenance, support or fixes.

## License

MIT. See `LICENSE`.