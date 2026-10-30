"""Adversarial local acceptance probes for the PR 03 review."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import copy
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from forgestra.assessment import assess, sample
from forgestra.providers import configuration
from forgestra.cli import main
from forgestra_safety import Blocked
import test_pr03 as fixtures


class PR03ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="forgestra-pr03-review-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_explicit_null_provider_configuration_fails_closed(self):
        with self.assertRaises(Blocked):
            configuration(None)

    def test_cli_invalid_utf8_returns_structured_nonzero(self):
        replay = self.root / "invalid.json"
        replay.write_bytes(b"\xff")
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertEqual(main(["assess", str(self.root), "--replay", str(replay)]), 1)
        self.assertEqual(json.loads(stream.getvalue())["status"], "BLOCKED")

    def test_case_variant_environment_file_excluded(self):
        (self.root / ".ENV.PRODUCTION").write_text("synthetic")
        coverage = sample(self.root)
        self.assertEqual(coverage["files"][0]["reason"], "SENSITIVE_FILE")

    def test_shared_coverage_redacts_credential_filename(self):
        secret = "canary-provider-do-not-use"
        (self.root / (secret + ".txt")).write_text("synthetic")
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": secret}):
            result = assess(self.root)
        self.assertNotIn(secret, json.dumps(result))

    def test_escaped_credentials_redacted_before_serialization(self):
        case = fixtures.PR03Tests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        secret = 'synthetic-credential-"-backslash\\-end'
        case.document["findings"][0]["title"] = secret
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": secret}):
            result = assess(case.root, fixtures.fixture(case.document))
        self.assertNotEqual(result["assessment"]["findings"][0]["title"], secret)

    def test_redaction_cannot_create_schema_invalid_success(self):
        case = fixtures.PR03Tests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        other = copy.deepcopy(case.document["findings"][0])
        other["id"] = "other-secret-id"
        case.document["findings"].append(other)
        with patch.dict(
            "os.environ", {"ANTHROPIC_API_KEY": "F-example", "OTHER_TOKEN": "other-secret-id"}
        ):
            result = assess(case.root, fixtures.fixture(case.document))
        self.assertEqual(result["status"], "ERROR")
        self.assertIsNone(result["assessment"])

    def test_directory_errors_are_explicit_exclusions(self):
        (self.root / "unreadable").mkdir()
        original = Path.iterdir

        def denied(path):
            if path.name == "unreadable":
                raise PermissionError("synthetic denial")
            return original(path)

        with patch.object(Path, "iterdir", denied):
            coverage = sample(self.root)
        self.assertEqual(coverage["files"][0]["reason"], "UNREADABLE_DIRECTORY")

    def test_installed_result_false_success_rejected(self):
        from record_pr03_evidence import valid_installed_result

        self.assertFalse(
            valid_installed_result({"status": "SUCCESS_NO_FINDINGS"}, "SUCCESS_NO_FINDINGS", None)
        )
        result = assess(self.root)
        self.assertTrue(valid_installed_result(result, "BLOCKED", None))
        for field, value in (
            ("completion_percentage", 100),
            ("target_tests", "PASSED"),
            ("side_effects", ["published"]),
            ("schema_version", True),
            ("privileged_automation", "ENABLED"),
        ):
            changed = copy.deepcopy(result)
            changed[field] = value
            self.assertFalse(valid_installed_result(changed, "BLOCKED", None))

    def test_redacted_output_remains_valid_json_with_numeric_canary(self):
        replay = self.root / "empty.json"
        replay.write_text(
            json.dumps(fixtures.fixture({"schema_version": 1, "findings": [], "limitations": []}))
        )
        stream = io.StringIO()
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "1"}):
            with contextlib.redirect_stdout(stream):
                code = main(["assess", str(self.root), "--replay", str(replay)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stream.getvalue())["schema_version"], 1)

    def test_directory_listing_is_bounded(self):
        count = 0

        def entries(_path):
            nonlocal count
            for index in range(20000):
                count += 1
                yield self.root / ("file-" + str(index))

        with patch.object(Path, "iterdir", entries):
            with self.assertRaises(Blocked):
                sample(self.root)
        self.assertEqual(count, 10001)

    def test_bounded_reader_rejects_growth_after_stat(self):
        from forgestra.verification import bounded_file

        path = self.root / "large.txt"
        path.write_bytes(b"x" * 100)
        original = Path.stat

        class Stat:
            st_size = 1
            st_mode = 0

        def changed_stat(item, *args, **kwargs):
            actual = original(item, *args, **kwargs)
            if item == path:
                fake = Stat()
                fake.st_mode = actual.st_mode
                return fake
            return actual

        with patch.object(Path, "stat", changed_stat):
            with self.assertRaises(Blocked):
                bounded_file(path, 10)

    def test_recorder_rejects_false_or_malformed_child_without_installing(self):
        import record_pr03_evidence as recorder
        import record_pr02_evidence as previous

        evidence = self.root / "docs/engineering/evidence/pr-03"
        evidence.mkdir(parents=True)
        for name in (
            "accepted-pr02-verification.json",
            "accepted-pr02-tested-files.json",
            "review-baseline.json",
            "review-reproduction.json",
        ):
            (evidence / name).write_text("{}")
        (evidence / "baseline.json").write_text("{}")
        historical = self.root / "docs/engineering/evidence/pr-02"
        historical.mkdir()
        for name in (
            "baseline.json",
            "tool-provenance.json",
            "review-baseline.json",
            "review-reproduction.json",
        ):
            (historical / name).write_text("{}")
        for stage in ("pr-01", "pr-02"):
            directory = self.root / "docs/engineering/evidence" / stage
            directory.mkdir(exist_ok=True)
            for name in ("verification.json", "tested-files.json"):
                (directory / name).write_text("{}")
        audits = self.root / "docs/audit"
        audits.mkdir()
        for name in ("Factory_Production_Open_Source_Audit.md", "Factory_Remediation_Roadmap.md"):
            (audits / name).write_text("Synthetic fixture")
        with patch.object(previous, "ROOT", self.root):
            files = previous.source_hashes("pr-03")
        (evidence / "baseline.json").write_text(
            json.dumps(
                {
                    "accepted_evidence": {
                        name: value
                        for name, value in files.items()
                        if name.startswith(
                            ("docs/engineering/evidence/pr-01/", "docs/engineering/evidence/pr-02/")
                        )
                    },
                    "audit_documents": {
                        name: value
                        for name, value in files.items()
                        if name.startswith("docs/audit/")
                    },
                }
            )
        )
        output = self.root / ".tools/pr02-results"
        output.mkdir(parents=True)
        candidates: list[Any] = [[], {"status": "PASSED_LOCAL", "checks": []}]
        for candidate in candidates:
            (output / "report.json").write_text(json.dumps(candidate))
            with (
                patch.object(recorder, "ROOT", self.root),
                patch.object(previous, "ROOT", self.root),
                patch.object(
                    recorder.subprocess, "run", return_value=SimpleNamespace(returncode=0)
                ),
                patch.object(previous, "clean_install", side_effect=AssertionError("no install")),
                patch.object(recorder, "installed_cli", side_effect=AssertionError("no CLI run")),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(recorder.main(), 1)
            report = json.loads((evidence / "verification.json").read_text())
            self.assertEqual(report["status"], "FAILED")
            self.assertEqual(report["installed_cli"]["status"], "NOT_RUN")

    def test_text_reader_preserves_universal_newlines(self):
        from forgestra.verification import plain_file

        path = self.root / "text.txt"
        path.write_bytes(b"a\r\nb\rc\n")
        self.assertEqual(plain_file(path), "a\nb\nc\n")

    def test_empty_missing_or_foreign_baselines_cannot_pass(self):
        from record_pr03_evidence import baseline_matches

        files = {
            prefix + name: "0" * 64
            for prefix in ("docs/engineering/evidence/pr-01/", "docs/engineering/evidence/pr-02/")
            for name in ("verification.json", "tested-files.json")
        }
        self.assertTrue(baseline_matches({"accepted_evidence": files}, files, "accepted_evidence"))
        values: list[Any] = [
            {},
            {"accepted_evidence": {}},
            {"accepted_evidence": {"../foreign": "0" * 64}},
        ]
        for value in values:
            self.assertFalse(baseline_matches(value, files, "accepted_evidence"))
