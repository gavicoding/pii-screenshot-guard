"""Command-line interface for pii-screenshot-guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .detectors import DLPScanner
from .github_integration import GitHubPRClient
from .models import ScanReport, Severity
from .redactor import redact_text


def _format_table(report: ScanReport) -> str:
    if not report.findings:
        return "CLEAN: 0 DLP findings detected."

    lines = [
        f"ALERT: {report.total_findings} finding(s) detected across {len(report.targets)} target(s).",
        "SEVERITY | RULE_ID                   | SOURCE:LINE        | MASKED_VALUE",
        "---------+---------------------------+--------------------+----------------------",
    ]
    for f in report.findings:
        loc = f"{Path(f.source).name}:{f.line}"
        lines.append(f"{f.severity.value.upper():<8} | {f.rule_id:<25} | {loc:<18} | {f.masked_match}")
    return "\n".join(lines)


def _format_markdown(report: ScanReport) -> str:
    if not report.findings:
        return "**CLEAN** - `0` DLP findings detected."

    lines = [
        f"### Zero-Trust DLP Report ({report.total_findings} finding(s))",
        "",
        "| Severity | Rule | Location | Masked Preview |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for f in report.findings:
        loc = f"`{Path(f.source).name}:{f.line}`"
        lines.append(f"| **{f.severity.value.upper()}** | `{f.rule_id}` | {loc} | `{f.masked_match}` |")
    return "\n".join(lines)


def _format_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


FORMATTERS = {
    "table": _format_table,
    "markdown": _format_markdown,
    "json": _format_json,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii-guard",
        description="Zero-Trust DLP scanner for LGPD/GDPR PII, credentials, and internal IPs.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser("scan", help="Scan files, directories, or stdin ('-') for leaks.")
    scan_cmd.add_argument("paths", nargs="+", help="Files, directories, or '-' for stdin.")
    scan_cmd.add_argument(
        "--format",
        choices=("table", "json", "markdown"),
        default="table",
        help="Output report format (default: table).",
    )
    scan_cmd.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical"),
        default="low",
        help="Minimum severity that triggers exit code 1 (default: low).",
    )
    scan_cmd.add_argument(
        "--ignore",
        action="append",
        default=[],
        help="Regex pattern to ignore false positives (can be passed multiple times).",
    )

    redact_cmd = sub.add_parser("redact", help="Mask detected PII/secrets in a file.")
    redact_cmd.add_argument("file", help="Path to text/log file to redact.")
    redact_cmd.add_argument("-o", "--output", help="Write redacted text to file instead of stdout.")

    gh_cmd = sub.add_parser(
        "github-pr",
        help="Fetch and audit added lines in a GitHub Pull Request via REST API.",
    )
    gh_cmd.add_argument("--repo", required=True, help="Target repository in 'owner/name' format.")
    gh_cmd.add_argument("--pr", required=True, type=int, help="Pull Request number.")
    gh_cmd.add_argument(
        "--format",
        choices=("table", "json", "markdown"),
        default="table",
        help="Output report format (default: table).",
    )
    gh_cmd.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical"),
        default="low",
        help="Minimum severity that triggers exit code 1 (default: low).",
    )
    gh_cmd.add_argument(
        "--ignore",
        action="append",
        default=[],
        help="Regex pattern to ignore false positives (can be passed multiple times).",
    )
    gh_cmd.add_argument(
        "--comment",
        action="store_true",
        help="Post a masked DLP report comment back to the Pull Request if findings exist.",
    )
    gh_cmd.add_argument(
        "--token",
        default=None,
        help="GitHub API token (defaults to GITHUB_TOKEN environment variable).",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        scanner = DLPScanner(ignore_patterns=args.ignore)
        report = ScanReport()
        file_paths: list[str] = []

        for item in args.paths:
            if item == "-":
                stdin_text = sys.stdin.read()
                report.targets.append("<stdin>")
                report.findings.extend(scanner.scan_text(stdin_text, source="<stdin>"))
            else:
                file_paths.append(item)

        if file_paths:
            path_report = scanner.scan_paths(file_paths)
            report.targets.extend(path_report.targets)
            report.findings.extend(path_report.findings)

        print(FORMATTERS[args.format](report))
        threshold = Severity(args.fail_on)
        return 1 if report.has_findings_at_or_above(threshold) else 0

    if args.command == "redact":
        source_path = Path(args.file)
        text = source_path.read_text(encoding="utf-8", errors="replace")
        scanner = DLPScanner()
        findings = scanner.scan_text(text, source=str(source_path))
        redacted = redact_text(text, findings=findings)

        if args.output:
            Path(args.output).write_text(redacted, encoding="utf-8")
        else:
            print(redacted, end="")
        return 0

    if args.command == "github-pr":
        scanner = DLPScanner(ignore_patterns=args.ignore)
        client = GitHubPRClient(token=args.token)
        report = client.audit_pull_request(
            repo=args.repo,
            pr_number=args.pr,
            post_comment=args.comment,
            scanner=scanner,
        )
        print(FORMATTERS[args.format](report))
        threshold = Severity(args.fail_on)
        return 1 if report.has_findings_at_or_above(threshold) else 0

    return 2
