# Security policy

## Project status

This is a hobby and portfolio project. It is provided as is and is not actively maintained. There is no commitment to fix bugs or security issues, and no response time is guaranteed. Pull requests are welcome but may never be reviewed. You are free to fork it under the MIT license.

## Reporting a problem

Open a public issue on GitHub:
https://github.com/TheIlkinAlizade/python-log-analyzer/issues

Include the version and the steps to reproduce, and use a small synthetic input. Never attach real logs or real IP addresses, usernames or other personal data.

The tool only reads local files and makes no network requests, so most problems are crashes, hangs or wrong output, not remote attacks.

## What counts as a security issue

- A crafted log line that crashes the parser, hangs it, or makes it use unbounded memory or time
- Log content that reaches the terminal or JSON report with control or escape characters intact
- A rules file that bypasses validation or causes code execution
- A false statement in the documentation about what the tool detects or protects against

## What does not count

- Attacks the tool does not detect. Detection coverage is deliberately small and documented in the README under Limitations.
- Findings produced on logs you analyzed without permission.