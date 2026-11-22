"""Rule-based DLP scanner for LGPD/GDPR PII, credentials, and internal IPs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

from .models import Finding, ScanReport, Severity
from .validators import is_rfc1918_ipv4, is_valid_cnpj, is_valid_cpf, is_valid_luhn

PLACEHOLDER_VALUES = {
    "changeme",
    "your_api_key",
    "your-api-key",
    "your_token_here",
    "example",
    "placeholder",
    "replace_me",
    "dummy",
    "null",
    "none",
    "true",
    "false",
}


def mask_sensitive_value(value: str) -> str:
    """Return a safely masked preview without ever exposing the raw secret."""
    clean = value.strip()
    if len(clean) <= 6:
        return "*" * len(clean)
    return f"{clean[:3]}***{clean[-2:]}"


@dataclass(frozen=True)
class RuleSpec:
    """Defines a single DLP detection rule with optional deterministic validator."""

    rule_id: str
    category: str
    severity: Severity
    description: str
    pattern: re.Pattern[str]
    capture_group: int = 0
    validator: Callable[[str], bool] | None = None


DEFAULT_RULES: tuple[RuleSpec, ...] = (
    RuleSpec(
        rule_id="PRIVATE_KEY_BLOCK",
        category="secrets",
        severity=Severity.CRITICAL,
        description="PEM private key header detected",
        pattern=re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ),
    RuleSpec(
        rule_id="AWS_ACCESS_KEY",
        category="secrets",
        severity=Severity.CRITICAL,
        description="AWS access key identifier",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    RuleSpec(
        rule_id="GITHUB_TOKEN",
        category="secrets",
        severity=Severity.CRITICAL,
        description="GitHub personal access or fine-grained token",
        pattern=re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    RuleSpec(
        rule_id="DB_CONNECTION_STRING",
        category="secrets",
        severity=Severity.CRITICAL,
        description="Database URI containing embedded credentials",
        pattern=re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mssql|sqlserver|mongodb(?:\+srv)?|redis)://"
            r"[^\s:@/]+:[^\s@/]+@[^\s/]+"
        ),
    ),
    RuleSpec(
        rule_id="JWT_TOKEN",
        category="secrets",
        severity=Severity.HIGH,
        description="JSON Web Token (JWT) credential",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    RuleSpec(
        rule_id="GENERIC_SECRET_ASSIGNMENT",
        category="secrets",
        severity=Severity.HIGH,
        description="Hardcoded secret, token, or password assignment",
        pattern=re.compile(
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|password|passwd|pwd)\b\s*[:=]\s*['\"]?"
            r"([A-Za-z0-9_/+=\-.!@#$%^&*]{8,})['\"]?"
        ),
        capture_group=1,
        validator=lambda v: v.lower() not in PLACEHOLDER_VALUES and not v.startswith("${"),
    ),
    RuleSpec(
        rule_id="CREDIT_CARD",
        category="pci-pii",
        severity=Severity.HIGH,
        description="Payment card number (Luhn verified)",
        pattern=re.compile(r"\b\d(?:[ -]?\d){12,18}\b"),
        validator=is_valid_luhn,
    ),
    RuleSpec(
        rule_id="BR_CPF",
        category="lgpd-pii",
        severity=Severity.HIGH,
        description="Brazilian CPF personal tax ID (checksum verified)",
        pattern=re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
        validator=is_valid_cpf,
    ),
    RuleSpec(
        rule_id="US_SSN",
        category="gdpr-pii",
        severity=Severity.HIGH,
        description="US Social Security Number pattern",
        pattern=re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    ),
    RuleSpec(
        rule_id="BR_CNPJ",
        category="lgpd-corp",
        severity=Severity.MEDIUM,
        description="Brazilian CNPJ corporate ID (checksum verified)",
        pattern=re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b"),
        validator=is_valid_cnpj,
    ),
    RuleSpec(
        rule_id="INTERNAL_IPV4",
        category="infra-leak",
        severity=Severity.MEDIUM,
        description="Private RFC 1918 internal IPv4 address",
        pattern=re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        validator=is_rfc1918_ipv4,
    ),
    RuleSpec(
        rule_id="EMAIL_ADDRESS",
        category="lgpd-gdpr-pii",
        severity=Severity.LOW,
        description="Email address (personal identifier)",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    RuleSpec(
        rule_id="BR_PHONE",
        category="lgpd-pii",
        severity=Severity.LOW,
        description="Brazilian mobile/landline phone number",
        pattern=re.compile(r"(?:\+55\s?)?\(?\d{2}\)?\s?9\d{4}-\d{4}\b"),
    ),
)


class DLPScanner:
    """Scans text, files, and OCR payloads against Zero-Trust DLP rules."""

    def __init__(
        self,
        rules: Sequence[RuleSpec] = DEFAULT_RULES,
        ignore_patterns: Sequence[str] | None = None,
    ) -> None:
        self.rules = tuple(rules)
        self.ignore_regexes = [re.compile(p) for p in (ignore_patterns or ())]

    def _is_ignored(self, value: str) -> bool:
        return any(rx.search(value) for rx in self.ignore_regexes)

    def scan_text(self, text: str, source: str = "<stdin>") -> list[Finding]:
        """Scan multiline text and return offset-ordered DLP findings."""
        findings: list[Finding] = []
        offset = 0

        for line_no, raw_line in enumerate(text.splitlines(keepends=True), start=1):
            line = raw_line.rstrip("\r\n")
            occupied_spans: list[tuple[int, int]] = []

            for rule in self.rules:
                for match in rule.pattern.finditer(line):
                    group_idx = rule.capture_group
                    matched_value = match.group(group_idx)
                    rel_start, rel_end = match.span(group_idx)

                    if rule.validator and not rule.validator(matched_value):
                        continue
                    if self._is_ignored(matched_value):
                        continue
                    # Prevent lower-severity rules from double-counting inside a higher-severity match
                    # (e.g., email inside a DB connection string).
                    if any(s <= rel_start and rel_end <= e for s, e in occupied_spans):
                        continue

                    occupied_spans.append((rel_start, rel_end))
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            category=rule.category,
                            severity=rule.severity,
                            description=rule.description,
                            masked_match=mask_sensitive_value(matched_value),
                            source=source,
                            line=line_no,
                            start=offset + rel_start,
                            end=offset + rel_end,
                        )
                    )

            offset += len(raw_line)

        findings.sort(key=lambda f: (f.start, -f.severity.rank))
        return findings

    def scan_file(self, path: str | Path) -> list[Finding]:
        """Read a UTF-8/text file and scan its contents."""
        file_path = Path(path)
        content = file_path.read_text(encoding="utf-8", errors="replace")
        return self.scan_text(content, source=str(file_path))

    def scan_paths(self, paths: Iterable[str | Path]) -> ScanReport:
        """Scan files or directories recursively and aggregate into a ScanReport."""
        report = ScanReport()
        for raw in paths:
            p = Path(raw)
            if p.is_dir():
                for child in sorted(p.rglob("*")):
                    if child.is_file():
                        report.targets.append(str(child))
                        report.findings.extend(self.scan_file(child))
            elif p.is_file():
                report.targets.append(str(p))
                report.findings.extend(self.scan_file(p))
        return report
