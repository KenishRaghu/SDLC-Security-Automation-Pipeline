# Secure coding guidelines (short)

This project pairs **lightweight guardrails in code review** with **automated checks in CI**. The goal is predictable behavior: validate untrusted input, keep secrets out of source, and know when dependencies drift into vulnerable versions.

## Input validation

Treat anything that crosses a trust boundary—HTTP parameters, headers, file uploads, webhook payloads—as **untrusted**.

- Prefer **allow-lists** (known good patterns) over **deny-lists** (trying to block “bad” strings).
- Reject unexpected types early; parse and validate before business logic runs.
- Avoid dangerous sinks with user data: `eval`, `exec`, dynamic `pickle`, unsanitized HTML rendering, and shell invocation with concatenated strings.

In the demo app, `/evaluate` and `/ping` are deliberately unsafe so **Bandit** can show what *not* to do.

## Dependency scanning

Dependencies are one of the largest real-world attack surfaces.

- Pin ranges or versions in `requirements.txt` for reproducible builds.
- Run **`pip audit`** or your org’s equivalent on a schedule (this repo keeps scope small and does not wire that in, but it is the natural next step after Bandit/ZAP).
- Review upgrades like code changes: read changelogs, especially for auth, crypto, and HTTP stacks.

## Secret management

**Never commit secrets** (passwords, API keys, private keys, session signing secrets).

- Use your platform’s secret store (GitHub Actions secrets, cloud KMS/secret manager, etc.).
- For local development, use `.env` files that are **git-ignored**, or a secrets helper—never hard-code values in Python modules.
- Rotate credentials if they ever appear in git history; removing the line is not enough.

The sample `DEMO_ADMIN_PASSWORD` in `app/vulnerable_app.py` exists only to trigger static analysis in a controlled demo.

## How this pipeline fits the SDLC

| Phase | What happens |
| --- | --- |
| **Develop** | Engineers follow this guide; risky patterns are caught in review. |
| **Commit / PR** | GitHub Actions runs **Bandit** (SAST) on the Python tree. |
| **Running app** | The same workflow starts the Flask app and runs **ZAP Baseline** (passive DAST) against a URL. |
| **Report** | `scripts/vuln_parser.py` normalizes outputs; `scripts/vuln_tracker.py` compares to `known_issues.json` and writes `reports/vuln_report.md`. |

That loop gives you a **documented, repeatable** security signal on every change—without standing up extra infrastructure.
