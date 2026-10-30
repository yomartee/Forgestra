"""Release checks cannot grant rights, approval or runtime publication authority."""

from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import unittest
import subprocess
from unittest.mock import patch
from typing import Any

from forgestra.cli import main
from forgestra.release import readiness, files, scan, sbom
from forgestra_safety import Blocked, private_output_workspace
from pr11_release_validation import valid_release

ROOT = Path(__file__).resolve().parents[1]


class ReleaseTests(unittest.TestCase):
    def test_quickstart_rejects_forged_inspection_and_workspace_results(self):
        from pr11_release_validation import acceptance

        record = acceptance()
        self.assertTrue(valid_release(record))
        for index, field, value in (
            (2, "files", True),
            (2, "auto_merge", 0),
            (2, "provider", "PASSED"),
            (2, "remote", "PASSED"),
            (3, "execution", "ENABLED"),
            (3, "remote", "PASSED"),
            (3, "workspaces", []),
        ):
            bad = copy.deepcopy(record)
            command = bad["quickstart"][index]
            command["result"][field] = value
            command["stdout"] = json.dumps(command["result"])
            import hashlib

            command["stdout_sha256"] = hashlib.sha256(command["stdout"].encode()).hexdigest()
            self.assertFalse(valid_release(bad), (index, field))

    def test_scan_rejects_different_bytes_between_inventory_and_scan(self):
        import forgestra.release as release

        with private_output_workspace() as p:
            target = p / "a.txt"
            target.write_text("gh" + "p_" + "a" * 36)
            original = release.files

            def changed(root, names):
                inventory = original(root, names)
                target.write_text("ordinary source")
                return inventory

            with patch.object(release, "files", side_effect=changed):
                with self.assertRaises(Blocked):
                    release.scan(p, ["a.txt"])

    def test_launcher_timeout_cleans_parent_owned_temporary_tree(self):
        import run_safety_isolated as launcher

        roots = []

        def timed_out(*args, **kwargs):
            root = Path(kwargs["env"]["TEMP"])
            roots.append(root)
            (root / "child-leftover.txt").write_text("synthetic fixture")
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

        with patch.object(launcher.subprocess, "run", side_effect=timed_out):
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(launcher.main(), 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "FAILED")
        self.assertEqual(len(roots), 1)
        self.assertFalse(roots[0].exists())

    def test_launcher_filters_credentials_and_preserves_bounded_wait(self):
        import run_safety_isolated as launcher
        import os

        def completed(*args, **kwargs):
            self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
            self.assertEqual(kwargs["timeout"], 900)
            self.assertEqual(kwargs["env"]["TMPDIR"], kwargs["env"]["TEMP"])
            self.assertTrue(Path(kwargs["env"]["TEMP"]).is_dir())
            return subprocess.CompletedProcess(args[0], 0)

        with patch.dict(os.environ, {"GITHUB_TOKEN": "synthetic-not-a-credential"}):
            with patch.object(launcher.subprocess, "run", side_effect=completed):
                self.assertEqual(launcher.main(), 0)

    def test_each_gate_remains_blocked(self):
        for gate in ("A", "B", "C"):
            r = readiness(gate)
            self.assertEqual(r["status"], "BLOCKED")
            self.assertEqual(r["publication"], "BLOCKED")
            self.assertTrue(all(v == "DISABLED" for v in r["capabilities"].values()))
            self.assertIn("OWNER_RIGHTS_AND_LICENSE_APPROVAL", r["blockers"])

    def test_unknown_gate_fails_closed(self):
        for gate in ("", "PRODUCTION", True, None):
            with self.assertRaises(Blocked):
                readiness(gate)

    def test_production_adds_real_runtime_acceptance(self):
        self.assertNotIn("REAL_SANDBOX_RUNTIME_AND_RECOVERY_ACCEPTANCE", readiness("A")["blockers"])
        self.assertIn("REAL_SANDBOX_RUNTIME_AND_RECOVERY_ACCEPTANCE", readiness("B")["blockers"])

    def test_cli_is_blocked_with_structured_exit(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["release", "--gate", "A"]), 1)
        self.assertEqual(json.loads(output.getvalue()), readiness("A"))

    def test_mutating_report_cannot_change_policy(self):
        r = readiness("A")
        r["status"] = "APPROVED"
        r["capabilities"]["publication"] = "ENABLED"
        self.assertEqual(readiness("A")["status"], "BLOCKED")
        self.assertEqual(readiness("A")["capabilities"]["publication"], "DISABLED")

    def test_inventory_rejects_traversal_duplicates_and_aliases(self):
        with private_output_workspace() as p:
            (p / "a.txt").write_text("test")
            for names in (
                ["../a.txt"],
                ["a.txt", "a.txt"],
                ["/a.txt"],
                ["C:/a.txt"],
                ["./a.txt"],
                ["a//b"],
                [],
            ):
                with self.assertRaises((Blocked, OSError)):
                    files(p, names)

    def test_inventory_changes_with_actual_bytes(self):
        with private_output_workspace() as p:
            f = p / "a.txt"
            f.write_text("before")
            before = files(p, ["a.txt"])
            f.write_text("after")
            self.assertNotEqual(files(p, ["a.txt"]), before)

    def test_scan_redacts_values_and_sensitive_filenames(self):
        with private_output_workspace() as p:
            value = "gh" + "p_" + "a" * 36
            (p / "sensitive.txt").write_text(value)
            r = scan(p, ["sensitive.txt"])
            self.assertEqual(r["status"], "REVIEW_REQUIRED")
            self.assertEqual(r["files"], 1)
            self.assertNotIn(value, json.dumps(r))
            self.assertNotIn("sensitive.txt", json.dumps(r))

    def test_clean_scan_is_not_security_clearance(self):
        with private_output_workspace() as p:
            (p / "a.txt").write_text("ordinary source")
            r = scan(p, ["a.txt"])
            self.assertEqual(r["status"], "NO_PATTERN_MATCHES")
            self.assertEqual(r["history_tags_assets_logs"], "NOT_RUN")
            self.assertEqual(r["confidentiality_clearance"], "NOT_GRANTED")

    def test_missing_scan_input_fails(self):
        with private_output_workspace() as p:
            with self.assertRaises(OSError):
                scan(p, ["missing.txt"])

    def test_sbom_has_pinned_optional_and_web_versions(self):
        r = sbom(ROOT)
        self.assertEqual(r["bomFormat"], "CycloneDX")
        self.assertTrue(
            any(c["name"] == "mcp" and c["version"] == "2.3.0" for c in r["components"])
        )
        self.assertTrue(
            any(c["name"] == "next" and c["version"] == "16.4.2" for c in r["components"])
        )
        self.assertEqual(len({c["bom-ref"] for c in r["components"]}), len(r["components"]))

    def test_sbom_never_asserts_advisory_or_license_clearance(self):
        text = json.dumps(sbom(ROOT))
        self.assertIn("NOT_RUN", text)
        self.assertIn("NOT_GRANTED", text)
        self.assertNotIn('"licenses"', text)

    def test_summary_and_zero_checks_cannot_pass(self):
        cases: list[dict[str, Any]] = [{}, {"status": "PASSED_LOCAL"}, {"quickstart": []}]
        for r in cases:
            self.assertFalse(valid_release(copy.deepcopy(r)))

    def test_case_alias_inventory_fails_before_second_read(self):
        with private_output_workspace() as p:
            (p / "a.txt").write_text("safe")
            with self.assertRaises(Blocked):
                files(p, ["a.txt", "A.txt"])

    def test_scan_inventory_digest_changes_with_bytes(self):
        with private_output_workspace() as p:
            f = p / "a.txt"
            f.write_text("first")
            before = scan(p, ["a.txt"])["scanned_manifest_sha256"]
            f.write_text("second")
            self.assertNotEqual(before, scan(p, ["a.txt"])["scanned_manifest_sha256"])
