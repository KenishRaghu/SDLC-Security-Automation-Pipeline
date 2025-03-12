#!/usr/bin/env python3
"""
Normalize Bandit (SAST) and OWASP ZAP (DAST) reports into one JSON schema.

Bandit input: JSON from `bandit -f json`.
ZAP input: JSON from `zap-baseline.py -J` or XML from `-x` (traditional report).

This script is intentionally small: read files, map fields, write JSON.
"""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class UnifiedFinding:
    """Single finding in a tool-agnostic shape for diffing and reporting."""

    fingerprint: str
    tool: str
    severity: str
    title: str
    description: str
    location: str
    recommendation: str
    raw_rule_id: str


def _bandit_severity(issue_severity: str) -> str:
    """Map Bandit's issue_severity to our unified scale (one number per finding)."""
    sev = (issue_severity or "").upper()
    if sev == "HIGH":
        return "high"
    if sev == "MEDIUM":
        return "medium"
    if sev == "LOW":
        return "low"
    return "info"


def parse_bandit(path: Path) -> list[UnifiedFinding]:
    if not path.is_file():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    results = data.get("results") or []
    out: list[UnifiedFinding] = []
    for item in results:
        filename = item.get("filename") or ""
        line = item.get("line_number")
        test_id = item.get("test_id") or "unknown"
        test_name = item.get("test_name") or "finding"
        title = f"{test_name} [{test_id}]"
        desc = item.get("issue_text") or ""
        more = item.get("more_info") or ""
        recommendation = more if more else "See Bandit test documentation for remediation guidance."

        location = f"{filename}:{line}" if line is not None else filename
        fingerprint = f"bandit:{test_id}:{filename}:{line}"

        out.append(
            UnifiedFinding(
                fingerprint=fingerprint,
                tool="bandit",
                severity=_bandit_severity(str(item.get("issue_severity") or "")),
                title=str(title),
                description=str(desc),
                location=location,
                recommendation=str(recommendation),
                raw_rule_id=str(test_id),
            )
        )
    return out


def _zap_risk_to_severity(riskcode: str | None, riskdesc: str | None) -> str:
    code = (riskcode or "").strip()
    # ZAP traditional reports use numeric riskcode (0–3).
    mapping = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    if code in mapping:
        return mapping[code]
    desc = (riskdesc or "").lower()
    if "high" in desc:
        return "high"
    if "medium" in desc:
        return "medium"
    if "low" in desc:
        return "low"
    return "info"


def _zap_alerts_from_json_obj(data: Any) -> Iterable[dict[str, Any]]:
    """
    ZAP JSON can nest sites/alerts differently across versions; walk defensively.
    """
    if isinstance(data, dict):
        if "site" in data:
            sites = data["site"]
            if isinstance(sites, list):
                for site in sites:
                    if isinstance(site, dict) and "alerts" in site:
                        alerts = site["alerts"]
                        if isinstance(alerts, list):
                            for alert in alerts:
                                if isinstance(alert, dict):
                                    yield alert
            elif isinstance(sites, dict) and "alerts" in sites:
                alerts = sites["alerts"]
                if isinstance(alerts, list):
                    for alert in alerts:
                        if isinstance(alert, dict):
                            yield alert
        # Some exports are a flat list of alerts
        if "alerts" in data and isinstance(data["alerts"], list):
            for alert in data["alerts"]:
                if isinstance(alert, dict):
                    yield alert


def parse_zap_json(path: Path) -> list[UnifiedFinding]:
    if not path.is_file():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    out: list[UnifiedFinding] = []
    for alert in _zap_alerts_from_json_obj(data):
        pluginid = str(
            alert.get("pluginid") or alert.get("pluginId") or alert.get("id") or "unknown"
        )
        name = str(alert.get("name") or alert.get("alert") or "ZAP alert")
        desc = str(alert.get("desc") or alert.get("description") or "")
        solution = str(alert.get("solution") or alert.get("recommendation") or "")
        riskcode = str(alert.get("riskcode") or "") or None
        riskdesc = str(alert.get("riskdesc") or "") or None

        instances = alert.get("instances") or alert.get("instance") or []
        first_uri = ""
        if isinstance(instances, list) and instances:
            inst0 = instances[0]
            if isinstance(inst0, dict):
                first_uri = str(inst0.get("uri") or inst0.get("url") or "")
        elif isinstance(instances, dict):
            first_uri = str(instances.get("uri") or instances.get("url") or "")

        location = first_uri or "see ZAP report for URLs"
        fingerprint = f"zap:{pluginid}:{name}:{first_uri}"

        out.append(
            UnifiedFinding(
                fingerprint=fingerprint,
                tool="zap",
                severity=_zap_risk_to_severity(riskcode, riskdesc),
                title=name,
                description=desc,
                location=location,
                recommendation=solution or "Review ZAP alert guidance and fix server or client headers/config.",
                raw_rule_id=pluginid,
            )
        )
    return out


def parse_zap_xml(path: Path) -> list[UnifiedFinding]:
    """
    Parse ZAP traditional XML report (`-x`); handy if your pipeline only keeps XML.
    """
    if not path.is_file():
        return []

    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return []

    root = tree.getroot()
    out: list[UnifiedFinding] = []

    # Typical structure: <OWASPZAPReport><site><alerts><alert>...</alert>
    for alert in root.iter("alert"):
        pluginid = (alert.findtext("pluginid") or "").strip() or "unknown"
        name = (alert.findtext("name") or alert.findtext("alert") or "ZAP alert").strip()
        desc = (alert.findtext("desc") or "").strip()
        solution = (alert.findtext("solution") or "").strip()
        riskcode = (alert.findtext("riskcode") or "").strip() or None
        riskdesc = (alert.findtext("riskdesc") or "").strip() or None

        uri = ""
        instances = alert.find("instances")
        if instances is not None:
            inst0 = instances.find("instance")
            if inst0 is not None:
                uri = (inst0.findtext("uri") or "").strip()

        location = uri or "see ZAP report for URLs"
        fingerprint = f"zap:{pluginid}:{name}:{uri}"
        out.append(
            UnifiedFinding(
                fingerprint=fingerprint,
                tool="zap",
                severity=_zap_risk_to_severity(riskcode, riskdesc),
                title=name,
                description=desc,
                location=location,
                recommendation=solution or "Review ZAP alert guidance and fix server or client headers/config.",
                raw_rule_id=pluginid,
            )
        )
    return out


def findings_to_jsonable(findings: list[UnifiedFinding]) -> list[dict[str, Any]]:
    return [asdict(f) for f in findings]


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge Bandit + ZAP into unified findings JSON.")
    parser.add_argument("--bandit", type=Path, help="Path to bandit JSON report")
    parser.add_argument("--zap-json", type=Path, help="Path to ZAP JSON report (-J)")
    parser.add_argument("--zap-xml", type=Path, help="Path to ZAP XML report (-x)")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Output path for unified JSON (list of findings)",
    )
    args = parser.parse_args()

    merged: list[UnifiedFinding] = []
    if args.bandit:
        merged.extend(parse_bandit(args.bandit))
    if args.zap_json:
        merged.extend(parse_zap_json(args.zap_json))
    if args.zap_xml:
        merged.extend(parse_zap_xml(args.zap_xml))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(findings_to_jsonable(merged), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(merged)} unified finding(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
