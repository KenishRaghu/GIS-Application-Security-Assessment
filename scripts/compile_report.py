"""
Compile automated scan + manual findings into final reports.
Merges duplicates, prioritizes by risk, generates metrics.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from vulnerability_scanner import load_burp_scan_results, summarize_findings


def load_manual_findings(path: Path) -> list[dict]:
    """Load manual findings from JSON file."""
    if not path.exists():
        return []
    with open(path) as f:
        data = json.load(f)
    return data if isinstance(data, list) else data.get("findings", [])


def deduplicate(findings: list[dict], key_fields: list[str] = None) -> list[dict]:
    """Remove duplicates by description/url/type."""
    key_fields = key_fields or ["name", "url", "description", "type"]
    seen = set()
    out = []
    for f in findings:
        key = tuple(str(f.get(k, "")) for k in key_fields)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def prioritize(findings: list[dict]) -> list[dict]:
    """Sort by severity: critical > high > medium > low > info."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def key(f):
        return order.get((f.get("severity") or "info").lower(), 99)

    return sorted(findings, key=key)


def _finding_to_dict(f) -> dict:
    """Convert Finding object or dict to standard dict."""
    if isinstance(f, dict):
        return {**f, "source": f.get("source", "manual")}
    return {
        "source": "automated",
        "name": getattr(f, "name", str(f)),
        "severity": getattr(f, "severity", "info"),
        "url": getattr(f, "url", ""),
        "description": getattr(f, "description", ""),
        "remediation": getattr(f, "remediation", ""),
    }


def generate_penetration_report(
    automated: list,
    manual: list[dict],
    out_path: Path,
) -> str:
    """Generate penetration-testing-findings.md content."""
    all_findings = [_finding_to_dict(a) for a in automated]
    for m in manual:
        all_findings.append(_finding_to_dict(m))
    all_findings = deduplicate(all_findings)
    all_findings = prioritize(all_findings)

    lines = [
        "# GIS web application - penetration testing findings",
        "",
        "## Scope",
        "",
        "Penetration testing performed on the GIS web application with focus on:",
        "- Authentication and authorization",
        "- Session management",
        "- API access control",
        "- IDOR and privilege escalation",
        "- Security misconfigurations",
        "",
        "## Summary",
        "",
    ]

    summary = {}
    for f in all_findings:
        sev = (f.get("severity") or "info").lower()
        summary[sev] = summary.get(sev, 0) + 1
    for sev in ["critical", "high", "medium", "low", "info"]:
        c = summary.get(sev, 0)
        if c:
            lines.append(f"- **{sev.upper()}:** {c}")

    lines.extend([
        "",
        "## Findings",
        "",
    ])

    for i, f in enumerate(all_findings, 1):
        sev = (f.get("severity") or "info").upper()
        src = f.get("source", "")
        lines.extend([
            f"### {i}. {f.get('name', 'Unknown')} [{sev}] ({src})",
            "",
            f"- **URL:** {f.get('url', 'N/A')}",
            f"- **Description:** {f.get('description', '')}",
            f"- **Remediation:** {f.get('remediation', '')}",
            "",
            "---",
            "",
        ])

    lines.extend([
        "## Recommendations",
        "",
        "- Enforce MFA for admin and elevated roles",
        "- Implement RBAC and server-side authorization on every API call",
        "- Invalidate sessions on privilege change; use secure session binding",
        "- Use LDAPS with certificate pinning",
        "- Fix all critical and high findings before production",
        "",
    ])

    content = "\n".join(lines)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as fp:
        fp.write(content)
    return content


def compute_metrics(
    automated_count: int,
    manual_count: int,
    manual_hours_estimate: float = 20,
) -> dict:
    """Compute time-saved metrics. Automation ~50% time savings."""
    total = automated_count + manual_count
    auto_share = automated_count / max(total, 1)
    saved_hours = manual_hours_estimate * 0.5 * auto_share
    return {
        "automated_findings": automated_count,
        "manual_findings": manual_count,
        "total": total,
        "manual_testing_hours_estimate": manual_hours_estimate,
        "automation_saved_hours": round(saved_hours, 1),
        "efficiency_note": "Automation runs overnight; manual testing during day.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile scan and manual findings into reports")
    parser.add_argument("-b", "--burp", help="BurpSuite JSON results path")
    parser.add_argument("-m", "--manual", help="Manual findings JSON path")
    parser.add_argument("-o", "--output-dir", default=".", help="Output directory for reports")
    parser.add_argument("--manual-hours", type=float, default=20, help="Estimated manual test hours")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    if out_dir == Path("."):
        out_dir = Path(__file__).parent.parent

    automated = []
    if args.burp:
        automated = load_burp_scan_results(args.burp)

    manual = []
    if args.manual:
        manual = load_manual_findings(Path(args.manual))

    # Generate penetration report
    pt_path = out_dir / "docs" / "penetration-testing-findings.md"
    generate_penetration_report(automated, manual, pt_path)
    print(f"Report: {pt_path}")

    # Metrics
    metrics = compute_metrics(len(automated), len(manual), args.manual_hours)
    metrics_path = out_dir / "results" / "metrics.json"
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print("Metrics:", json.dumps(metrics, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
