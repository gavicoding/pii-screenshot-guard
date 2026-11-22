"""Zero-Trust DLP scanner for LGPD/GDPR PII, credentials, and internal network leaks."""

from .models import Finding, ScanReport, Severity

__all__ = ["Finding", "ScanReport", "Severity"]
__version__ = "1.0.0"
