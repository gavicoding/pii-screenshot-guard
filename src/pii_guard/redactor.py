"""Redaction helpers for scrubbing detected PII and secrets from text."""

from __future__ import annotations

from typing import Sequence

from .detectors import DLPScanner
from .models import Finding


def redact_text(
    text: str,
    findings: Sequence[Finding] | None = None,
    scanner: DLPScanner | None = None,
) -> str:
    """Replace sensitive spans in text with deterministic `[REDACTED:<RULE_ID>]` tokens."""
    detected = list(findings) if findings is not None else (scanner or DLPScanner()).scan_text(text)
    if not detected:
        return text

    ordered = sorted(detected, key=lambda f: (f.start, -f.end))
    parts: list[str] = []
    cursor = 0

    for finding in ordered:
        if finding.start < cursor:
            # Skip overlapping lower-priority match inside an already-redacted span.
            continue
        parts.append(text[cursor : finding.start])
        parts.append(f"[REDACTED:{finding.rule_id}]")
        cursor = finding.end

    parts.append(text[cursor:])
    return "".join(parts)
