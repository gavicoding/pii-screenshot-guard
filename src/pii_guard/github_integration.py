"""GitHub REST API integration for auditing Pull Request diffs before merge."""

from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import replace
from typing import Any
from urllib.error import HTTPError

from .detectors import DLPScanner
from .models import ScanReport

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_added_diff_lines(diff_text: str) -> list[tuple[str, int, str]]:
    """Extract (file_path, new_line_number, line_content) for added lines in a unified diff."""
    added: list[tuple[str, int, str]] = []
    current_file = "<diff>"
    current_line = 0
    in_hunk = False

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("diff --git "):
            in_hunk = False
            continue
        if raw_line.startswith("+++ "):
            target = raw_line[4:].strip()
            if target != "/dev/null":
                current_file = target[2:] if target.startswith("b/") else target
            continue
        if raw_line.startswith("--- "):
            continue

        hunk_match = _HUNK_RE.match(raw_line)
        if hunk_match:
            current_line = int(hunk_match.group(1))
            in_hunk = True
            continue

        if not in_hunk:
            continue

        if raw_line.startswith("+"):
            added.append((current_file, current_line, raw_line[1:]))
            current_line += 1
        elif raw_line.startswith("-"):
            continue
        elif raw_line.startswith("\\"):
            continue
        else:
            current_line += 1

    return added


def scan_pr_diff(diff_text: str, scanner: DLPScanner | None = None) -> ScanReport:
    """Scan only added lines in a unified GitHub Pull Request diff."""
    active_scanner = scanner or DLPScanner()
    report = ScanReport()
    seen_targets: set[str] = set()

    for file_path, line_no, line_text in parse_added_diff_lines(diff_text):
        if file_path not in seen_targets:
            seen_targets.add(file_path)
            report.targets.append(file_path)

        for finding in active_scanner.scan_text(line_text, source=file_path):
            report.findings.append(replace(finding, line=line_no))

    return report


def format_pr_comment(report: ScanReport) -> str:
    """Render a zero-exposure Markdown summary suitable for GitHub PR comments."""
    if not report.findings:
        return "### 🛡️ pii-screenshot-guard\n\n**CLEAN** — `0` DLP findings detected in this PR diff."

    lines = [
        f"### 🛡️ pii-screenshot-guard — {report.total_findings} DLP finding(s) detected",
        "",
        "| Severity | Rule | File & Line | Masked Preview |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for f in report.findings:
        lines.append(
            f"| **{f.severity.value.upper()}** | `{f.rule_id}` | `{f.source}:{f.line}` | `{f.masked_match}` |"
        )
    lines.append("")
    lines.append(
        "_Masked previews are truncated automatically to avoid echoing secrets into PR logs._"
    )
    return "\n".join(lines)


class GitHubPRClient:
    """Minimal stdlib GitHub REST API client for auditing Pull Request diffs."""

    def __init__(
        self,
        token: str | None = None,
        api_base: str = "https://api.github.com",
        timeout_seconds: float = 20.0,
    ) -> None:
        self.token = token if token is not None else os.environ.get("GITHUB_TOKEN", "")
        self.api_base = api_base.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def _request(
        self,
        method: str,
        path: str,
        accept: str,
        payload: dict[str, Any] | None = None,
    ) -> str:
        url = f"{self.api_base}{path}"
        headers = {
            "Accept": accept,
            "User-Agent": "pii-screenshot-guard/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        data: bytes | None = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub API {method} {path} failed ({exc.code}): {detail}") from exc

    def fetch_pr_diff(self, repo: str, pr_number: int) -> str:
        """Fetch raw unified diff for `<owner>/<repo>` PR `#pr_number`."""
        return self._request(
            "GET",
            f"/repos/{repo}/pulls/{pr_number}",
            accept="application/vnd.github.v3.diff",
        )

    def post_pr_comment(self, repo: str, pr_number: int, body: str) -> dict[str, Any]:
        """Post a comment on `<owner>/<repo>` PR `#pr_number` via the Issues API."""
        raw = self._request(
            "POST",
            f"/repos/{repo}/issues/{pr_number}/comments",
            accept="application/vnd.github+json",
            payload={"body": body},
        )
        return json.loads(raw) if raw else {}

    def audit_pull_request(
        self,
        repo: str,
        pr_number: int,
        post_comment: bool = False,
        scanner: DLPScanner | None = None,
    ) -> ScanReport:
        """Fetch PR diff, run DLP scan on added lines, and optionally post a summary comment."""
        diff_text = self.fetch_pr_diff(repo, pr_number)
        report = scan_pr_diff(diff_text, scanner=scanner)
        if post_comment and report.findings:
            self.post_pr_comment(repo, pr_number, format_pr_comment(report))
        return report
