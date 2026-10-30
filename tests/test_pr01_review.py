"""Independent PR 01 acceptance regressions added during the follow-up review."""

import contextlib
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Any
from unittest.mock import patch

import check_workflows
from check_safety import run_suite, valid_regression_result
from forgestra_safety import (
    Blocked,
    Policy,
    classify_diff,
    private_output_workspace,
    strict_json_loads,
    write_new_tree,
)
from record_pr01_evidence import assess_check, write_evidence
import record_pr01_evidence
import pr01_validation

ROOT = Path(__file__).resolve().parents[1]
# Resolve the OS temp parent before credential-filtered fixtures clear the
# environment; tempfile must not fall back to the product source directory.
TEST_TEMP_PARENT = tempfile.gettempdir()
RUNTIME_ENV = {
    key: value
    for key, value in os.environ.items()
    if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"}
}


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(
            os.environ, {**RUNTIME_ENV, "FORGESTRA_KILL_SWITCH": "0"}, clear=True
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.workspace = private_output_workspace()
        self.parent = self.workspace.__enter__()
        self.addCleanup(self.workspace.__exit__, None, None, None)

    def test_generated_tool_and_permission_controls_are_protected(self):
        for path in [
            ".coderabbit.yaml",
            ".claude/settings.json",
            ".cursor/rules/policy.mdc",
            ".vscode/tasks.json",
            ".gitmodules",
            ".gitconfig",
            ".gitattributes",
            ".gitignore",
            ".npmrc",
            ".pypirc",
            ".netrc",
            ".repo-index/manifest.yaml",
            "scripts/local_generation.py",
            "scripts/record_pr01_evidence.py",
        ]:
            with self.subTest(path=path), self.assertRaises(Blocked):
                write_new_tree(
                    self.parent / "output",
                    [
                        {"path": "valid/nested.txt", "content": "safe"},
                        {"path": path, "content": "unapproved control"},
                    ],
                )
            # Do not weaken this check to permit partial output.
            self.assertFalse((self.parent / "output").exists())

    def test_protected_ancestor_cannot_be_used_as_output_root(self):
        for name in [".codex", ".claude", "config", ".repo-index"]:
            ancestor = self.parent / name
            ancestor.mkdir()
            with self.subTest(name=name), self.assertRaises(Blocked):
                write_new_tree(ancestor / "new", [{"path": "file.txt", "content": "unapproved"}])
            self.assertEqual(list(ancestor.iterdir()), [])

    def test_diff_control_files_cannot_be_downgraded(self):
        for path in [
            ".gitmodules",
            ".gitattributes",
            ".npmrc",
            ".netrc",
            "docs/SECURITY.md",
            ".cursor/rules/test.md",
            "scripts/local_generation.py",
        ]:
            self.assertEqual(classify_diff([{"operation": "modify", "path": path}]), 2, path)

    def test_duplicate_diff_keys_are_rejected_by_real_inspection_cli(self):
        diff = self.parent / "changes.json"
        diff.write_text(
            '[{"operation":"modify","path":".github/CODEOWNERS","path":"docs/test.md"}]'
        )
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/inspect_local.py"),
                str(self.parent),
                "--changes-json",
                str(diff),
            ],
            env={},
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["status"], "BLOCKED")

    def test_zero_executed_tests_fail_even_if_suite_claims_tests(self):
        class EmptyLiar(unittest.TestSuite):
            def countTestCases(self):
                return 1

        result = run_suite(EmptyLiar(), io.StringIO())
        self.assertEqual(result["status"], "FAILED")

    def test_expected_failures_are_not_a_passing_safety_gate(self):
        class ExpectedFailure(unittest.TestCase):
            @unittest.expectedFailure
            def test_safety(self):
                self.fail("known safety failure")

        result = run_suite(
            unittest.defaultTestLoader.loadTestsFromTestCase(ExpectedFailure), io.StringIO()
        )
        self.assertEqual(result["status"], "FAILED")

    def test_cleanup_error_does_not_leak_exception_contents(self):
        output = self.parent / "output"
        with (
            patch.object(Path, "write_text", side_effect=OSError("staging failure")),
            patch(
                "forgestra_safety.shutil.rmtree", side_effect=OSError("canary-cleanup-credential")
            ),
        ):
            with self.assertRaises(Blocked) as error:
                write_new_tree(output, [{"path": "x.txt", "content": "safe"}])
        self.assertNotIn("canary-cleanup-credential", str(error.exception))
        self.assertFalse(output.exists())

    def workflow_fixture(self):
        for directory in [".github/workflows", "templates/workflows"]:
            for source in (ROOT / directory).glob("*.yml"):
                target = self.parent / source.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
        for relative in [
            "growth-engine-workflow.yml",
            ".github/dependabot.yml",
            ".github/copilot-setup-steps.yml",
            ".coderabbit.yaml",
            "mcp.json",
        ]:
            target = self.parent / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)

    def assertWorkflowGateFails(self):
        stream = io.StringIO()
        with patch.object(check_workflows, "ROOT", self.parent), contextlib.redirect_stdout(stream):
            result = check_workflows.main()
        self.assertEqual(result, 1)

    def test_yaml_extension_workflow_cannot_escape_gate(self):
        self.workflow_fixture()
        path = self.parent / ".github/workflows/unapproved.yaml"
        path.write_text(
            json.dumps(
                {
                    "name": "unapproved",
                    "on": {"pull_request_target": None},
                    "permissions": {"contents": "write"},
                    "jobs": {
                        "write": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo unapproved"}]}
                    },
                }
            )
        )
        self.assertWorkflowGateFails()

    def test_extra_steps_in_blocked_workflow_cannot_escape_gate(self):
        self.workflow_fixture()
        path = self.parent / ".github/workflows/claude.yml"
        document = json.loads(path.read_text())
        document["jobs"]["blocked"]["steps"].append({"uses": "unapproved/credentialed-action@v1"})
        path.write_text(json.dumps(document))
        self.assertWorkflowGateFails()

    def test_review_integration_has_no_auto_approval(self):
        document = json.loads((ROOT / ".coderabbit.yaml").read_text())
        self.assertEqual(document, {"reviews": {"auto_review": {"enabled": False}}})

    def test_default_generation_does_not_modify_unapproved_local_target(self):
        with tempfile.TemporaryDirectory(prefix="forgestra-customer-") as directory:
            customer = Path(directory)
            (customer / "custom.txt").write_bytes(b"customer\x00\xff")
            with self.assertRaises(Blocked):
                write_new_tree(
                    customer / "new-output", [{"path": "src/x.py", "content": "unapproved"}]
                )
            self.assertEqual((customer / "custom.txt").read_bytes(), b"customer\x00\xff")
            self.assertEqual([p.name for p in customer.iterdir()], ["custom.txt"])

    def test_private_scope_cannot_be_reused_after_exit(self):
        with private_output_workspace() as parent:
            result = write_new_tree(parent / "valid", [{"path": "nested/x.txt", "content": "safe"}])
            self.assertEqual(result["status"], "LOCAL_OUTPUT_WRITTEN")
        self.assertFalse(parent.exists())
        with self.assertRaises(Blocked):
            write_new_tree(parent / "later", [{"path": "x.txt", "content": "unapproved"}])

    def test_actual_frontend_writer_body_uses_real_manifest_boundary(self):
        # Execute only the retained resource writer body, not the disabled engine
        # or its SDK/import gate. The safety helper and filesystem remain real.
        source = ast.parse((ROOT / "scripts/agents/frontend_engine.py").read_text(encoding="utf-8"))
        method = next(
            node
            for node in ast.walk(source)
            if isinstance(node, ast.FunctionDef) and node.name == "_generate_resource_pages"
        )
        namespace: dict[str, Any] = {}
        exec(
            compile(
                ast.Module(body=[method], type_ignores=[]), "<reviewed-resource-writer>", "exec"
            ),
            namespace,
        )
        engine = type("LocalResourceFixture", (), {"frontend_dir": self.parent / "frontend"})()
        call = namespace["_generate_resource_pages"]
        with self.assertRaises(Blocked):
            call(
                engine,
                {
                    "resources": [
                        {"name": "safe", "label": "Safe"},
                        {"name": "../escape", "label": "Escape"},
                    ]
                },
            )
        self.assertFalse(engine.frontend_dir.exists())
        result = call(engine, {"resources": [{"name": "products", "label": "Products"}]})
        self.assertEqual(result["status"], "LOCAL_OUTPUT_WRITTEN")
        self.assertTrue((engine.frontend_dir / "src/pages/products/list.tsx").is_file())

    def test_private_scope_allocation_checks_kill_switch(self):
        os.environ["FORGESTRA_KILL_SWITCH"] = "1"
        with patch(
            "forgestra_safety.tempfile.TemporaryDirectory",
            side_effect=AssertionError("must not allocate"),
        ):
            with self.assertRaises(Blocked):
                with private_output_workspace():
                    self.fail("kill switch bypass")

    def test_nonfinite_and_null_policy_documents_are_rejected(self):
        policy = self.parent / "policy.json"
        for content in [
            "null",
            '{"version":1,"capabilities":{},"targets":[],"extra":NaN}',
            '{"version":1,"capabilities":{},"targets":[Infinity]}',
        ]:
            policy.write_text(content)
            with self.assertRaises(Blocked):
                Policy.load(policy)

    def test_duplicate_and_nonfinite_json_cannot_hide_diff_evidence(self):
        for content in [
            '[{"operation":"delete","operation":"modify","path":"docs/test.md"}]',
            (
                '[{"operation":"rename","source":".github/CODEOWNERS",'
                '"source":"docs/a.md","path":"docs/b.md"}]'
            ),
            "[NaN]",
            "[Infinity]",
            "[-Infinity]",
        ]:
            with self.assertRaises(ValueError):
                strict_json_loads(content)

    def test_unapproved_diff_shapes_fail_the_real_cli(self):
        diff = self.parent / "diff.json"
        for content in ["null", "{}", '[{"operation":"modify","path":"x","approved":true}]']:
            diff.write_text(content)
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(ROOT / "scripts/inspect_local.py"),
                    str(self.parent),
                    "--changes-json",
                    str(diff),
                ],
                env={},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["status"], "BLOCKED")

    def test_failure_logs_use_shared_redaction(self):
        class LeakyFailure(unittest.TestCase):
            def test_failure(self):
                print("canary-log-credential")
                raise OSError("canary-log-credential")

        output = io.StringIO()
        result = run_suite(unittest.defaultTestLoader.loadTestsFromTestCase(LeakyFailure), output)
        self.assertEqual(result["status"], "FAILED")
        self.assertNotIn("canary-log-credential", output.getvalue())
        self.assertIn("[REDACTED]", output.getvalue())

    def test_exit_zero_does_not_turn_failed_or_zero_tests_into_pass(self):
        passing = {
            "status": "PASSED",
            "collected": 1,
            "tests": 1,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "expected_failures": 0,
            "unexpected_successes": 0,
        }
        self.assertTrue(valid_regression_result(passing))
        self.assertEqual(assess_check("regressions", 0, json.dumps(passing))["status"], "PASSED")
        cases = [
            {**passing, "tests": 0},
            {**passing, "tests": True},
            {**passing, "status": "FAILED"},
            {**passing, "errors": 1},
            {**passing, "skipped": 1},
            {**passing, "expected_failures": 1},
            {**passing, "collected": 2},
            {**passing, "extra": "approved"},
        ]
        for document in cases:
            self.assertFalse(valid_regression_result(document))
            self.assertEqual(
                assess_check("regressions", 0, json.dumps(document))["status"], "FAILED"
            )
        for output in ["", '{"status":"PASSED","tests":1,"tests":0}', "NaN", "{}"]:
            self.assertEqual(assess_check("regressions", 0, output)["status"], "FAILED")
        self.assertEqual(assess_check("regressions", 1, json.dumps(passing))["status"], "FAILED")

    def test_privileged_steps_and_boolean_aliases_fail_workflow_gate(self):
        self.workflow_fixture()
        path = self.parent / ".github/workflows/safety-regressions.yml"
        document = json.loads(path.read_text())
        document["jobs"]["public-product"]["steps"][0]["with"]["persist-credentials"] = 0
        path.write_text(json.dumps(document))
        self.assertWorkflowGateFails()
        document["permissions"]["contents"] = "write"
        path.write_text(json.dumps(document))
        self.assertWorkflowGateFails()

    def test_unknown_yml_and_ambiguous_service_aliases_fail_workflow_gate(self):
        self.workflow_fixture()
        for relative in [".github/workflows/new.yml", ".coderabbit.yml", ".github/dependabot.yaml"]:
            path = self.parent / relative
            path.write_text("{}")
            self.assertWorkflowGateFails()
            path.unlink()

    def test_evidence_writer_does_not_follow_file_links(self):
        outside = self.parent / "customer.txt"
        outside.write_text("customer bytes")
        evidence = self.parent / "evidence"
        evidence.mkdir()
        link = evidence / "linked.log"
        try:
            link.symlink_to(outside)
        except OSError as error:
            self.skipTest("OS symlink creation unavailable: " + type(error).__name__)
        with patch.object(record_pr01_evidence, "EVIDENCE", evidence):
            with self.assertRaises(ValueError):
                write_evidence(link, "unapproved")
        self.assertEqual(outside.read_text(), "customer bytes")

    def test_evidence_recorder_rejects_false_success_and_sanitizes_logs(self):
        root = self.parent / "recording-fixture"
        evidence = root / "docs/engineering/evidence/pr-01"
        evidence.mkdir(parents=True)
        files = {}
        for name in ["Factory_Production_Open_Source_Audit.md", "Factory_Remediation_Roadmap.md"]:
            path = root / "docs/audit" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("independent audit fixture")
            files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        (evidence / "baseline.json").write_text(json.dumps({"files": files}))
        (evidence / "containment.json").write_text("{}")

        # A broken wrapper returning zero and a claimed PASS must not pass evidence.
        def completed(argv, **_kwargs):
            return subprocess.CompletedProcess(
                argv, 0, '{"status":"PASSED","tests":0}', "canary-log-credential"
            )

        with (
            patch.object(record_pr01_evidence, "ROOT", root),
            patch.object(record_pr01_evidence, "EVIDENCE", evidence),
            patch.object(pr01_validation, "ROOT", root),
            patch.object(record_pr01_evidence.subprocess, "run", completed),
            patch.object(record_pr01_evidence.shutil, "which", return_value=None),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(record_pr01_evidence.main(), 1)
        report = json.loads((evidence / "verification.json").read_text())
        self.assertEqual(report["status"], "FAILED_OR_BLOCKED")
        self.assertEqual(report["commands"][0]["exit_code"], 0)
        self.assertEqual(report["commands"][0]["status"], "FAILED")
        for name, digest in report["artifact_sha256"].items():
            content = (evidence / name).read_bytes()
            self.assertNotIn(b"canary-log-credential", content)
            self.assertEqual(hashlib.sha256(content).hexdigest(), digest)

    def test_linked_source_is_not_hashed_or_executed_as_reviewed_code(self):
        root = self.parent / "source-fixture"
        root.mkdir()
        outside = self.parent / "unrelated.py"
        outside.write_text('raise AssertionError("unrelated code must not run")')
        link = root / "linked.py"
        try:
            link.symlink_to(outside)
        except OSError as error:
            self.skipTest("OS symlink creation unavailable: " + type(error).__name__)
        with patch.object(record_pr01_evidence, "ROOT", root):
            with self.assertRaises(ValueError):
                record_pr01_evidence.source_hashes()


if __name__ == "__main__":
    unittest.main()
