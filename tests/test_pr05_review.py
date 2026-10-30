"""Adversarial review of PR 05 local prerequisite and evidence contracts."""

import contextlib
import copy
import io
import json
import os
from unittest.mock import patch
import unittest

from forgestra.adoption import FIXTURE_CONFIGURATION, local_install_fixture, plan
from forgestra.cli import main
from forgestra_safety import Blocked
from record_pr05_evidence import valid_fixture_output

TAP = (
    "TAP version 13\n# Subtest: test.js\nok 1 - test.js\n  ---\n"
    "  duration_ms: 1.25\n  type: 'test'\n  ...\n1..1\n# tests 1\n# suites 0\n"
    "# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 2.5\n"
)
TEST_ARGV = ["node", "--test", "--test-reporter=tap", "test.js"]


def configuration():
    return {"version": 1, "capabilities": {}, "targets": [], **copy.deepcopy(FIXTURE_CONFIGURATION)}


class PR05ReviewTests(unittest.TestCase):
    def test_explicit_node_workspace_needs_test_command(self):
        with local_install_fixture() as control:
            config = configuration()
            del config["workspaces"][0]["commands"]["test"]
            result = plan(control.current, configuration=config)
            self.assertEqual(result["status"], "REVIEW_REQUIRED")
            self.assertIn("TARGET_TEST_COMMAND_REQUIRED", result["prerequisites"])

    def test_inferred_node_workspace_needs_test_script(self):
        with local_install_fixture() as control:
            (control.current / "requirements.txt").unlink()
            (control.current / "package.json").write_bytes(b'{"scripts":{"build":"node build.js"}}')
            self.assertEqual(plan(control.current)["status"], "REVIEW_REQUIRED")

    def test_declared_build_must_be_in_explicit_validation_commands(self):
        with local_install_fixture() as control:
            config = configuration()
            del config["workspaces"][0]["commands"]["build"]
            result = plan(control.current, configuration=config)
            self.assertEqual(result["status"], "REVIEW_REQUIRED")
            self.assertIn("TARGET_BUILD_COMMAND_REQUIRED", result["prerequisites"])

    def test_python_without_explicit_checks_and_lock_is_incomplete(self):
        with local_install_fixture() as control:
            for name in ("package.json", "package-lock.json", "build.js", "test.js"):
                (control.current / name).unlink()
            result = plan(control.current)
            self.assertEqual(result["status"], "REVIEW_REQUIRED")
            self.assertIn("TARGET_TEST_COMMAND_REQUIRED", result["prerequisites"])
            self.assertIn("TARGET_DEPENDENCY_LOCK_REQUIRED", result["prerequisites"])

    def test_python_test_without_lock_still_requires_review(self):
        with local_install_fixture() as control:
            config = configuration()
            config["workspaces"] = [
                {
                    "path": ".",
                    "language": "python",
                    "manager": "pip",
                    "commands": {"test": ["python", "-m", "unittest"]},
                }
            ]
            result = plan(control.current, configuration=config)
            self.assertEqual(result["status"], "REVIEW_REQUIRED")
            self.assertIn("TARGET_DEPENDENCY_LOCK_REQUIRED", result["prerequisites"])

    def test_public_planner_rejects_invalid_configuration_schema(self):
        with local_install_fixture() as control:
            cases: tuple[dict[str, object], ...] = (
                {},
                {"workspaces": []},
                {"capabilities": {"publication": True}},
            )
            for config in cases:
                with self.assertRaises(Blocked):
                    plan(control.current, configuration=config)

    def test_public_planner_rejects_malformed_command_before_target_scan(self):
        with local_install_fixture() as control:
            config = configuration()
            config["workspaces"][0]["commands"]["test"] = ["sh", "-c", "echo wrong"]
            with patch("forgestra.adoption.read_tree", side_effect=AssertionError("no scan")):
                with self.assertRaises(Blocked):
                    plan(control.current, configuration=config)

    def test_contradictory_tap_is_not_passing_evidence(self):
        self.assertTrue(valid_fixture_output(TEST_ARGV, 0, TAP))
        for suffix in ("# tests 0\n", "# fail 1\n", "# skipped 1\n", "not ok 2 - extra\n"):
            self.assertFalse(valid_fixture_output(TEST_ARGV, 0, TAP + suffix))

    def test_tap_for_unknown_command_or_empty_argv_is_invalid(self):
        for argv in ([], ["node", "unknown.js"], ["sh", "-c", "test.js"]):
            self.assertFalse(valid_fixture_output(argv, 0, TAP))

    def test_redaction_cannot_silently_change_a_hashed_plan(self):
        with local_install_fixture() as control:
            canary = "branch-canary-review-05"
            (control.current / ".git/refs/remotes/origin/HEAD").write_bytes(
                ("ref: refs/remotes/origin/" + canary + "\n").encode()
            )
            config_path = control.parent / "configuration.json"
            config_path.write_text(json.dumps(configuration()), encoding="utf-8")
            with patch.dict(os.environ, {"FORGESTRA_TEST_TOKEN": canary}):
                with self.assertRaises(Blocked):
                    plan(control.current, configuration=configuration())
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(
                        main(["adopt", str(control.current), "--config", str(config_path)]), 1
                    )
                self.assertNotIn(canary, output.getvalue())
                self.assertEqual(json.loads(output.getvalue())["status"], "BLOCKED")
