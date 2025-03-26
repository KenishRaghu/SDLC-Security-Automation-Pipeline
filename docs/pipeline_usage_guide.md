# Pipeline usage guide

This repository demonstrates **SAST + DAST in CI** using only free, widely recognized tools: **Bandit** and **OWASP ZAP** (baseline scan via Docker in GitHub Actions).

## What runs in CI

Workflow file: `.github/workflows/security-pipeline.yml`

1. **Install** Python dependencies from `requirements.txt`.
2. **Start** the sample Flask app on `0.0.0.0:5000` so it is reachable from the ZAP container.
3. **SAST:** `bandit -r app -f json -o reports/bandit-report.json`
4. **DAST:** `zaproxy/action-baseline` targets `DAST_TARGET_URL` (default `http://host.docker.internal:5000`) and writes `reports/zap-report.json` (`-J` flag). `-I` avoids failing the ZAP script on WARN-level alerts so the job can still publish artifacts.
5. **Normalize:** `python scripts/vuln_parser.py --bandit ... --zap-json ... -o reports/unified_findings.json`
6. **Track:** `python scripts/vuln_tracker.py --findings ... --baseline known_issues.json -o reports/vuln_report.md`
7. **Artifacts:** `security-reports` zip on the workflow run contains JSON + Markdown.

Triggers: **push** and **pull_request** to `main` or `master`.

## Reading the Markdown report

Open `reports/vuln_report.md` after a run (locally or from the artifact). Sections:

- **New:** Findings whose **fingerprint** is not listed in `known_issues.json`.
- **Existing:** Still present, and explicitly acknowledged in the baseline file.
- **Resolved:** Listed in the baseline before, but absent from the latest unified scan—usually means fixed or no longer reachable.

Fingerprints are stable strings produced by `vuln_parser.py` (for example `bandit:B307:file.py:12`). Copy them exactly into the baseline when accepting risk.

## Handling flagged vulnerabilities

1. **Confirm it is real** — read the tool’s description and the affected file or URL.
2. **Fix in code** — remove dangerous APIs, validate input, use safe libraries, add headers, etc.
3. **If you must defer** — add an entry to `known_issues.json` under `issues` with `fingerprint` and a short `note` (owner, ticket, expiry). This is your lightweight “exception register” without a database.
4. **Re-run** the workflow; the finding should move from **New** to **Existing** (if baselined) or disappear (if fixed).

Optional gate: run `python scripts/vuln_tracker.py ... --fail-on-new` in CI when you are ready to break the build on unapproved findings.

## Running locally (optional)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
mkdir -p reports
bandit -r app -f json -o reports/bandit-report.json
flask --app app.vulnerable_app run --host=127.0.0.1 --port=5000
```

In another terminal, run ZAP baseline with Docker (from the repo root):

```bash
docker run --rm -v "$(pwd):/zap/wrk/:rw" -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://host.docker.internal:5000 -J reports/zap-report.json -I
```

On Linux, if `host.docker.internal` is missing, add `--add-host=host.docker.internal:host-gateway` to the `docker run` command, or target your LAN IP.

Then merge and report:

```bash
python scripts/vuln_parser.py \
  --bandit reports/bandit-report.json \
  --zap-json reports/zap-report.json \
  -o reports/unified_findings.json

python scripts/vuln_tracker.py \
  --findings reports/unified_findings.json \
  --baseline known_issues.json \
  -o reports/vuln_report.md
```

## Troubleshooting

| Symptom | Likely cause | What to try |
| --- | --- | --- |
| ZAP cannot reach Flask | Docker ↔ host networking | Set `DAST_TARGET_URL` in the workflow to `http://172.17.0.1:5000` or your runner’s host alias. |
| Empty `zap-report.json` | Scan failed before write | Inspect the ZAP step log; confirm Flask health check passed. |
| Bandit step “fails” but JSON exists | Non-zero exit when issues found | Workflow uses `continue-on-error` so later steps still run. |
