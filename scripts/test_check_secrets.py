import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import check_secrets


ROOT = Path(__file__).resolve().parent.parent


class SecretRulesTest(unittest.TestCase):
    def test_local_config_paths(self):
        for path in (".env", "cmd/audio-agent/.env.production", "audio-agent.json",
                     "cmd/audio-agent/audio-agent.json"):
            with self.subTest(path=path):
                self.assertTrue(check_secrets.is_local_secret_file(path))

    def test_templates_remain_allowed(self):
        for path in (".env.example", "cmd/.env.production.example",
                     "cmd/audio-agent/audio-agent.json.example", "config.go"):
            with self.subTest(path=path):
                self.assertFalse(check_secrets.is_local_secret_file(path))

    def test_detects_minimax_key_without_echoing_it(self):
        fake_key = "sk-" + "A" * 122
        findings = check_secrets.inspect_file("example.json", (
            '{\n  "api_key": "' + fake_key + '"\n}\n').encode("utf-8"))
        self.assertEqual(findings, [("example.json", 2, "long sk- API key")])
        self.assertNotIn(fake_key, check_secrets.format_finding(findings[0]))

    def test_detects_jwt_credentials(self):
        fake_jwt = "eyJ" + "a" * 15 + "." + "b" * 20 + "." + "c" * 30
        self.assertEqual(check_secrets.inspect_file("config.txt", fake_jwt.encode("utf-8")),
                         [("config.txt", 1, "JWT credential")])

    def test_placeholders_and_empty_values_are_allowed(self):
        self.assertEqual(check_secrets.inspect_file(".env.example",
                         b'MINIMAX_API_KEY=\nOPENAI_API_KEY=sk-your-api-key\n'), [])

    def test_templates_are_still_scanned_for_keys(self):
        content = ("MINIMAX_API_KEY=sk-" + "A" * 122).encode("utf-8")
        self.assertTrue(check_secrets.inspect_file(".env.example", content))

    def test_filenames_are_escaped_and_redacted(self):
        fake_key = "sk-" + "B" * 122
        report = check_secrets.format_finding((fake_key + "\n.json", 1, "long sk- API key"))
        self.assertNotIn(fake_key, report)
        self.assertNotIn("\n", report)
        self.assertIn("[REDACTED]", report)

    def test_cli_reports_findings_without_content(self):
        error = io.StringIO()
        with mock.patch.object(check_secrets, "scan_index", return_value=[
            ("example.json", 2, "long sk- API key")
        ]), contextlib.redirect_stderr(error):
            self.assertEqual(check_secrets.main(), 1)
        self.assertIn("values redacted", error.getvalue())

    def test_cli_fails_closed_when_git_cannot_be_read(self):
        with mock.patch.object(check_secrets, "scan_index", side_effect=ValueError), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(check_secrets.main(), 2)


class GitIndexTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.write(".gitignore", (ROOT / ".gitignore").read_text(encoding="utf-8"))

    def git(self, *args, **kwargs):
        return subprocess.run(["git", *args], cwd=self.root, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, **kwargs)

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def test_gitignore_protects_root_and_nested_secrets(self):
        for path in (".env", ".env.local", "cmd/audio-agent/.env",
                     "cmd/audio-agent/.env.production", "cmd/audio-agent/audio-agent.json"):
            with self.subTest(path=path):
                self.assertEqual(self.git("check-ignore", "-q", "--", path).returncode, 0)

    def test_gitignore_allows_examples(self):
        for path in (".env.example", "cmd/audio-agent/.env.production.example",
                     "cmd/audio-agent/audio-agent.json.example"):
            with self.subTest(path=path):
                self.assertEqual(self.git("check-ignore", "-q", "--", path).returncode, 1)

    def test_force_added_config_is_rejected_even_if_empty(self):
        path = "cmd/audio-agent/audio-agent.json"
        self.write(path, "{}\n")
        self.git("add", "-f", "--", path, check=True)
        self.assertEqual(check_secrets.scan_index(self.root),
                         [(path, None, "local secret configuration")])

    def test_scans_staged_content_not_worktree(self):
        path = "config example.json"
        self.write(path, '{"api_key":"sk-' + "A" * 122 + '"}\n')
        self.git("add", "--", path, check=True)
        self.write(path, '{"api_key":""}\n')
        self.assertEqual(check_secrets.scan_index(self.root),
                         [(path, 1, "long sk- API key")])

    def test_untracked_local_secrets_are_not_read(self):
        self.write(".env", "MINIMAX_API_KEY=sk-" + "A" * 122)
        self.assertEqual(check_secrets.scan_index(self.root), [])

    def test_subdirectory_invocation_checks_the_whole_index(self):
        self.write(".env", "")
        self.git("add", "-f", "--", ".env", check=True)
        subdir = self.root / "nested"
        subdir.mkdir()
        self.assertEqual(check_secrets.scan_index(subdir),
                         [(".env", None, "local secret configuration")])

    def test_clean_index_passes(self):
        self.write(".env.example", "MINIMAX_API_KEY=\n")
        self.git("add", "--", ".env.example", check=True)
        self.assertEqual(check_secrets.scan_index(self.root), [])


if __name__ == "__main__":
    unittest.main()
