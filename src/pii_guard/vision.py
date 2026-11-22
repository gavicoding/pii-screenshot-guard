"""Optional screenshot / image DLP analyzers (local Tesseract OCR or Gemini Vision)."""

from __future__ import annotations

import base64
import json
import mimetypes
import os
import shutil
import subprocess
import urllib.request
from pathlib import Path
from typing import Protocol

from .detectors import DLPScanner
from .models import Finding, Severity

ZERO_TRUST_VISION_PROMPT = (
    "You are a corporate Data Loss Prevention (DLP) auditor. Inspect the image for exposed "
    "API keys, tokens, passwords, private keys, internal RFC1918 IP addresses, emails, "
    "CPFs/SSNs, payment cards, or financial dashboards. "
    "Respond strictly as JSON with a 'findings' array of objects containing "
    "'rule_id', 'category', 'severity' (low|medium|high|critical), 'description', and 'masked_match'. "
    "Never return raw secrets unmasked. Return {\"findings\": []} if safe."
)


class ImageAnalyzer(Protocol):
    """Contract for scanning screenshots or images for sensitive data."""

    def analyze_image(self, image_path: Path) -> list[Finding]:
        """Analyze an image file and return normalized DLP findings."""


class TesseractOCRAnalyzer:
    """Extracts text from screenshots using local Tesseract OCR and scans with DLPScanner."""

    def __init__(self, scanner: DLPScanner | None = None, lang: str = "eng+por") -> None:
        self.scanner = scanner or DLPScanner()
        self.lang = lang

    def analyze_image(self, image_path: Path) -> list[Finding]:
        if not shutil.which("tesseract"):
            raise RuntimeError(
                "Tesseract OCR binary not found on PATH. Install tesseract-ocr to scan images locally."
            )
        proc = subprocess.run(
            ["tesseract", str(image_path), "stdout", "-l", self.lang],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Tesseract failed ({proc.returncode}): {proc.stderr.strip()}")
        return self.scanner.scan_text(proc.stdout, source=str(image_path))


class GeminiVisionAnalyzer:
    """Uses Gemini Vision REST API (stdlib urllib, no third-party SDK) for screenshot DLP."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gemini-2.5-flash",
        timeout_seconds: float = 30.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.model = model
        self.timeout_seconds = timeout_seconds

    def analyze_image(self, image_path: Path) -> list[Finding]:
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY is not set; cannot run GeminiVisionAnalyzer.")

        mime_type, _ = mimetypes.guess_type(str(image_path))
        mime_type = mime_type or "image/png"
        image_b64 = base64.b64encode(image_path.read_bytes()).decode("ascii")

        endpoint = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
            f"?key={self.api_key}"
        )
        body = {
            "contents": [
                {
                    "parts": [
                        {"text": ZERO_TRUST_VISION_PROMPT},
                        {"inline_data": {"mime_type": mime_type, "data": image_b64}},
                    ]
                }
            ],
            "generationConfig": {"responseMimeType": "application/json"},
        }
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
            payload = json.loads(resp.read().decode("utf-8"))

        text = payload["candidates"][0]["content"]["parts"][0]["text"]
        parsed = json.loads(text)
        findings: list[Finding] = []
        for item in parsed.get("findings", []):
            sev_raw = str(item.get("severity", "high")).lower()
            severity = Severity(sev_raw) if sev_raw in Severity._value2member_map_ else Severity.HIGH
            findings.append(
                Finding(
                    rule_id=str(item.get("rule_id", "VISION_DLP")),
                    category=str(item.get("category", "vision-audit")),
                    severity=severity,
                    description=str(item.get("description", "Sensitive visual data detected")),
                    masked_match=str(item.get("masked_match", "***")),
                    source=str(image_path),
                    line=0,
                    start=0,
                    end=0,
                )
            )
        return findings
