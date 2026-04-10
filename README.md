# SDLC Security Automation Pipeline

A weaving **security testing into CI/CD**—the same rhythm as unit tests, but for common web and Python risks. Everything is **open source**, **file-based** (JSON + Markdown), and **easy to narrate**: static analysis catches dangerous APIs in code; a passive DAST scan catches issues visible over HTTP.

## Why this exists

Modern SDLC security is not a single gate at release. It is a **steady signal** on every change: fast feedback for developers, auditable artifacts for reviewers, and a clear story for stakeholders (“we run Bandit on the Python tree and OWASP ZAP Baseline against the running app”).

This repo shows that story **without** Terraform, paid SaaS scanners, or databases—just GitHub Actions, Bandit, ZAP’s official Docker image, and ~200 lines of Python to normalize and track findings.

## Architecture

```text
┌─────────────────┐     ┌──────────────────┐
│  Bandit (SAST)  │     │ ZAP baseline (DAST)│
│  Python AST     │     │ Passive HTTP scan  │
└────────┬────────┘     └─────────┬──────────┘
         │                        │
         ▼                        ▼
   bandit-report.json      zap-report.json
         │                        │
         └──────────┬─────────────┘
                    ▼
          scripts/vuln_parser.py
          (unified_findings.json)
                    ▼
          scripts/vuln_tracker.py
          + known_issues.json
                    ▼
          reports/vuln_report.md
```

| Component | Role in securing the SDLC |
| --- | --- |
| `.github/workflows/security-pipeline.yml` | Automates scans on **push** and **pull_request**; uploads JSON/Markdown artifacts. |
| `app/vulnerable_app.py` | **Intentionally weak** Flask sample so scans have real findings to discuss. |
| `scripts/vuln_parser.py` | Turns heterogeneous tool output into **one schema** (severity, location, recommendation). |
| `scripts/vuln_tracker.py` | Diffs scans against **`known_issues.json`** and labels items **new / existing / resolved**. |
| `known_issues.json` | Human-edited **baseline** for accepted risk or temporary exceptions. |
| `docs/secure_coding_guidelines.md` | Ties controls (input validation, secrets, dependencies) to the pipeline. |
| `docs/pipeline_usage_guide.md` | Operational doc: how to read reports, update the baseline, run locally. |

## Quick start

1. Push this repository to GitHub (or use it as a template).
2. Open **Actions → Security pipeline** and inspect the latest run.
3. Download the **`security-reports`** artifact: Bandit JSON, ZAP JSON, unified findings, and `vuln_report.md`.

To run the same steps on your machine, see [docs/pipeline_usage_guide.md](docs/pipeline_usage_guide.md).


## Limits (by design)

- Not a full AppSec program: no IAST, no manual pen-test findings, no cloud posture management.
- ZAP Baseline is **shallow** compared to a full ZAP GUI session—appropriate for fast CI signal.
- Bandit focuses on **Python patterns**; it does not replace dependency CVE scanners (documented as a next step in the secure coding guide).
