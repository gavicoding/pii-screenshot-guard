import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from pii_guard.cli import main
from pii_guard.redactor import redact_text


class TestRedactorAndCLI(unittest.TestCase):
    def test_redact_text_replaces_all_sensitive_spans(self):
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        text = f"User CPF 529.982.247-25 logged in from 192.168.1.15 using {aws_key}\n"
        scrubbed = redact_text(text)

        self.assertIn("[REDACTED:BR_CPF]", scrubbed)
        self.assertIn("[REDACTED:INTERNAL_IPV4]", scrubbed)
        self.assertIn("[REDACTED:AWS_ACCESS_KEY]", scrubbed)
        self.assertNotIn("529.982.247-25", scrubbed)
        self.assertNotIn("192.168.1.15", scrubbed)
        self.assertNotIn(aws_key, scrubbed)

    def test_cli_scan_json_and_fail_on_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample_file = Path(tmp) / "ticket.log"
            sample_file.write_text("Host 10.1.2.3 leaked email ops@example.com\n", encoding="utf-8")

            out_buf = io.StringIO()
            with contextlib.redirect_stdout(out_buf):
                rc_fail = main(["scan", str(sample_file), "--format", "json", "--fail-on", "medium"])
            self.assertEqual(rc_fail, 1)

            payload = json.loads(out_buf.getvalue())
            self.assertEqual(payload["total_findings"], 2)
            self.assertEqual(payload["summary"]["medium"], 1)
            self.assertEqual(payload["summary"]["low"], 1)

            out_buf_ok = io.StringIO()
            with contextlib.redirect_stdout(out_buf_ok):
                rc_ok = main(["scan", str(sample_file), "--fail-on", "critical"])
            self.assertEqual(rc_ok, 0)

    def test_cli_scan_missing_path_is_an_error_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "nao-existe.log")
            out_buf, err_buf = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
                rc = main(["scan", missing])
            self.assertEqual(rc, 2)
            self.assertNotIn("CLEAN", out_buf.getvalue())
            self.assertIn("path not found", err_buf.getvalue())

    def test_cli_redact_missing_file_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            err_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf):
                rc = main(["redact", str(Path(tmp) / "nao-existe.txt")])
            self.assertEqual(rc, 2)
            self.assertIn("cannot read", err_buf.getvalue())

    def test_cli_redact_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "raw.txt"
            dst = Path(tmp) / "clean.txt"
            src.write_text("Email: dev@example.org | IP: 172.16.5.9\n", encoding="utf-8")

            rc = main(["redact", str(src), "-o", str(dst)])
            self.assertEqual(rc, 0)
            cleaned = dst.read_text(encoding="utf-8")
            self.assertIn("[REDACTED:EMAIL_ADDRESS]", cleaned)
            self.assertIn("[REDACTED:INTERNAL_IPV4]", cleaned)


if __name__ == "__main__":
    unittest.main()
