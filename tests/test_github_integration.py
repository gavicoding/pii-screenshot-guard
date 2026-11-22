import contextlib
import io
import json
import unittest
from unittest.mock import patch

from pii_guard.cli import main
from pii_guard.github_integration import (
    GitHubPRClient,
    format_pr_comment,
    parse_added_diff_lines,
    scan_pr_diff,
)


class _FakeHTTPResponse:
    def __init__(self, body: str) -> None:
        self._body = body.encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class TestGitHubPRIntegration(unittest.TestCase):
    def test_parse_added_diff_lines_tracks_file_and_line_numbers(self):
        sample_diff = (
            "diff --git a/src/app.py b/src/app.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -10,4 +10,5 @@ def load():\n"
            "     keep_line = True\n"
            "-    old_secret = 'removed'\n"
            "+    new_cpf = '529.982.247-25'\n"
            "+    clean_var = 42\n"
            "     end = True\n"
        )
        added = parse_added_diff_lines(sample_diff)
        self.assertEqual(
            added,
            [
                ("src/app.py", 11, "    new_cpf = '529.982.247-25'"),
                ("src/app.py", 12, "    clean_var = 42"),
            ],
        )

    def test_scan_pr_diff_ignores_removed_lines_and_reports_exact_added_line(self):
        old_key = "AKIA" + "IOSFODNN7OLDKEY1"
        new_tok = "ghp_" + "X9Y8Z7W6V5" * 4
        diff_text = (
            "diff --git a/config.env b/config.env\n"
            "--- a/config.env\n"
            "+++ b/config.env\n"
            "@@ -1,2 +1,3 @@\n"
            f"-AWS_ACCESS_KEY_ID={old_key}\n"
            " HOST=api.example.com\n"
            "+CPF=529.982.247-25\n"
            f"+TOKEN={new_tok}\n"
        )
        report = scan_pr_diff(diff_text)
        self.assertEqual(report.total_findings, 2)
        self.assertEqual([f.line for f in report.findings], [2, 3])
        self.assertEqual({f.rule_id for f in report.findings}, {"BR_CPF", "GITHUB_TOKEN"})

        comment = format_pr_comment(report)
        self.assertIn("src/app.py" if False else "config.env:2", comment)
        self.assertNotIn(new_tok, comment)

    def test_github_pr_client_fetch_and_comment_uses_api_headers(self):
        gh_tok = "ghp_" + "M1N2O3P4Q5" * 4
        sample_diff = (
            "diff --git a/.env.test b/.env.test\n"
            "--- a/.env.test\n"
            "+++ b/.env.test\n"
            "@@ -0,0 +1 @@\n"
            f"+TOKEN={gh_tok}\n"
        )
        recorded_requests = []

        def fake_urlopen(req, timeout=20.0):
            recorded_requests.append((req.get_method(), req.full_url, dict(req.header_items()), req.data))
            if req.get_method() == "GET":
                return _FakeHTTPResponse(sample_diff)
            return _FakeHTTPResponse(json.dumps({"id": 99, "html_url": "https://github.com/o/r/pull/7#issuecomment-99"}))

        with patch("pii_guard.github_integration.urllib.request.urlopen", side_effect=fake_urlopen):
            client = GitHubPRClient(token="test-auth-token")
            report = client.audit_pull_request("gavicoding/demo", 7, post_comment=True)

        self.assertEqual(report.total_findings, 1)
        self.assertEqual(len(recorded_requests), 2)
        get_req, post_req = recorded_requests
        self.assertEqual(get_req[0], "GET")
        self.assertTrue(get_req[1].endswith("/repos/gavicoding/demo/pulls/7"))
        self.assertEqual(get_req[2]["Accept"], "application/vnd.github.v3.diff")
        self.assertEqual(get_req[2]["Authorization"], "Bearer test-auth-token")

        self.assertEqual(post_req[0], "POST")
        self.assertTrue(post_req[1].endswith("/repos/gavicoding/demo/issues/7/comments"))
        posted_payload = json.loads(post_req[3].decode("utf-8"))
        self.assertIn("GITHUB_TOKEN", posted_payload["body"])
        self.assertNotIn(gh_tok, posted_payload["body"])

    def test_cli_github_pr_command(self):
        sample_diff = (
            "diff --git a/app.log b/app.log\n"
            "--- a/app.log\n"
            "+++ b/app.log\n"
            "@@ -1,0 +1,1 @@\n"
            "+Private host 10.10.1.50\n"
        )
        with patch(
            "pii_guard.github_integration.urllib.request.urlopen",
            return_value=_FakeHTTPResponse(sample_diff),
        ):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = main(["github-pr", "--repo", "gavicoding/demo", "--pr", "12", "--format", "json"])
        self.assertEqual(rc, 1)
        data = json.loads(out.getvalue())
        self.assertEqual(data["total_findings"], 1)
        self.assertEqual(data["findings"][0]["rule_id"], "INTERNAL_IPV4")


if __name__ == "__main__":
    unittest.main()
