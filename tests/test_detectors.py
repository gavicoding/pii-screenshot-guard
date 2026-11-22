import unittest

from pii_guard.detectors import DLPScanner
from pii_guard.models import Severity


class TestDLPScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = DLPScanner()

    def test_detects_secrets_with_masked_previews(self):
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        gh_tok = "ghp_" + "A1B2C3D4E5" * 4
        jwt_tok = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        db_uri = "postgresql://" + "appuser:SuperSecret99" + "@db.internal:5432/prod"

        sample = "\n".join([
            f"AWS_ACCESS_KEY_ID={aws_key}",
            f"GITHUB_TOKEN={gh_tok}",
            f"Authorization: Bearer {jwt_tok}",
            f"DATABASE_URL={db_uri}",
            "-----BEGIN RSA " + "PRIVATE KEY-----",
        ])

        findings = self.scanner.scan_text(sample, source="sample.env")
        rule_ids = {f.rule_id for f in findings}

        self.assertIn("AWS_ACCESS_KEY", rule_ids)
        self.assertIn("GITHUB_TOKEN", rule_ids)
        self.assertIn("JWT_TOKEN", rule_ids)
        self.assertIn("DB_CONNECTION_STRING", rule_ids)
        self.assertIn("PRIVATE_KEY_BLOCK", rule_ids)

        # Raw secrets must never leak into masked_match previews
        for finding in findings:
            self.assertNotIn(aws_key, finding.masked_match)
            self.assertNotIn(gh_tok, finding.masked_match)
            self.assertNotIn("SuperSecret99", finding.masked_match)

    def test_detects_lgpd_gdpr_and_internal_ip(self):
        payload = (
            "Cliente CPF 529.982.247-25, CNPJ 11.222.333/0001-81, "
            "email alice.silva@example.com, tel +55 11 99876-5432, "
            "host 192.168.10.24, card 4242-4242-4242-4242."
        )
        findings = self.scanner.scan_text(payload)
        rule_ids = {f.rule_id for f in findings}
        self.assertSetEqual(
            rule_ids,
            {
                "BR_CPF",
                "BR_CNPJ",
                "EMAIL_ADDRESS",
                "BR_PHONE",
                "INTERNAL_IPV4",
                "CREDIT_CARD",
            },
        )

    def test_ignores_placeholders_and_allowlist(self):
        safe_text = (
            "API_KEY=changeme\n"
            "PASSWORD=${DB_PASSWORD}\n"
            "PUBLIC_DNS=8.8.8.8\n"
            "INVALID_CPF=123.456.789-00\n"
        )
        self.assertEqual(self.scanner.scan_text(safe_text), [])

        custom_scanner = DLPScanner(ignore_patterns=[r"10\.0\.0\.1"])
        findings = custom_scanner.scan_text("Allowlisted healthcheck 10.0.0.1 vs leaked 10.0.0.99")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "INTERNAL_IPV4")

    def test_report_threshold_and_summary(self):
        findings = self.scanner.scan_text("Contact: bob@example.org on 10.20.30.40")
        from pii_guard.models import ScanReport

        report = ScanReport(targets=["test.log"], findings=findings)
        self.assertEqual(report.total_findings, 2)
        self.assertTrue(report.has_findings_at_or_above(Severity.MEDIUM))
        self.assertFalse(report.has_findings_at_or_above(Severity.HIGH))


if __name__ == "__main__":
    unittest.main()
