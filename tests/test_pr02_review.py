"""PR 02 acceptance probes: real validators, mocked process boundaries only."""

import contextlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import hashlib
import sys
from unittest.mock import patch

from forgestra.cli import main, doctor
from forgestra.configuration import load
from forgestra.workspaces import plan
from forgestra_safety import Blocked
import bootstrap
import ci
import record_pr02_evidence as recorder

ROOT = Path(__file__).resolve().parents[1]


class PR02ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="forgestra-pr02-review-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def source_fixture(self):
        from forgestra.verification import REQUIRED_SOURCE

        for name in REQUIRED_SOURCE:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

    def config(self, argv, path=".", **extra):
        file = self.root / "configuration.json"
        file.write_text(
            json.dumps(
                {
                    "version": 1,
                    "capabilities": {},
                    "targets": [],
                    "workspaces": [
                        {
                            "path": path,
                            "language": "javascript",
                            "manager": "npm",
                            "commands": {"build": argv},
                            **extra,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return file

    def test_incomplete_or_non_build_npm_commands_fail_configuration(self):
        for argv in (["npm"], ["npm", "run"], ["npm", "publish"], ["npm", "run", "--if-present"]):
            with self.subTest(argv=argv), self.assertRaises(Blocked):
                load(self.config(argv))

    def test_windows_alias_paths_fail_before_workspace_access(self):
        for path in ("web.", "web/aux", "web/CON.txt", "web/folder."):
            with self.subTest(path=path), self.assertRaises(Blocked):
                load(self.config(["npm", "run", "build"], path))

    def test_explicit_missing_npm_script_cannot_be_a_valid_plan(self):
        (self.root / "package.json").write_text('{"scripts":{"test":"never run"}}')
        (self.root / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{"":{}}}')
        configuration = load(self.config(["npm", "run", "absent"]))
        with self.assertRaises(Blocked):
            plan(self.root, configuration)

    def test_invalid_python_project_does_not_report_a_valid_plan(self):
        (self.root / "pyproject.toml").write_text("this is not TOML")
        with self.assertRaises((Blocked, ValueError)):
            plan(self.root, load())

    def test_invalid_lock_and_conflicting_declared_manager_are_blocking(self):
        package = self.root / "package.json"
        package.write_text('{"scripts":{"build":"never run"}}')
        lock = self.root / "package-lock.json"
        for payload in ("not JSON", "{}", '{"lockfileVersion":true,"packages":{}}'):
            lock.write_text(payload)
            with self.assertRaises((Blocked, ValueError)):
                plan(self.root, load())
        lock.write_text('{"lockfileVersion":3,"packages":{"":{}}}')
        package.write_text('{"packageManager":"pnpm@10.0.0","scripts":{"build":"never run"}}')
        with self.assertRaises(Blocked):
            plan(self.root, load())

    def test_doctor_rejects_invalid_required_workflow(self):
        self.source_fixture()
        (self.root / ".github/workflows/safety-regressions.yml").write_text('{"jobs":')
        self.assertEqual(doctor(load(), source=self.root)["status"], "BLOCKED")

    def test_ci_inputs_cannot_exclude_files_or_change_build_backend(self):
        self.source_fixture()
        from forgestra.verification import validate_source

        (self.root / "config/pr01-black.toml").write_text('[tool.black]\nforce-exclude=".*"\n')
        with self.assertRaises((Blocked, ValueError)):
            validate_source(self.root)
        shutil.copyfile(ROOT / "config/pr01-black.toml", self.root / "config/pr01-black.toml")
        project = self.root / "pyproject.toml"
        project.write_text(
            project.read_text().replace("setuptools.build_meta", "unreviewed.backend")
        )
        with self.assertRaises((Blocked, ValueError)):
            validate_source(self.root)

    def test_bootstrap_rejects_unreviewed_setup_before_creating_environment(self):
        self.source_fixture()
        (self.root / "setup.py").write_text('raise AssertionError("must never execute")')
        with patch.object(bootstrap, "ROOT", self.root), patch(
            "subprocess.run", side_effect=AssertionError("no process before validation")
        ):
            with self.assertRaises((Blocked, ValueError)):
                bootstrap.bootstrap(self.root)

    def test_bootstrap_rejects_exit_zero_blocked_doctor(self):
        self.source_fixture()
        import subprocess

        fake = subprocess.CompletedProcess([], 0, stdout='{"status":"BLOCKED"}', stderr="")
        with patch.object(bootstrap, "ROOT", self.root), patch("subprocess.run", return_value=fake):
            with self.assertRaises((Blocked, ValueError)):
                bootstrap.bootstrap(self.root)

    def test_ci_status_only_documents_are_not_passing_results(self):
        for name, document in (
            ("doctor", {"status": "READY_OFFLINE"}),
            ("workflow-policy", {"status": "PASSED"}),
            ("offline-inspection", {"status": "INSPECTED_LOCAL"}),
        ):
            self.assertFalse(ci.assess(name, 0, json.dumps(document)))
        self.assertFalse(ci.assess("unrecognized-check", 0, ""))

    def test_evidence_missing_hashes_or_duplicate_checks_fail(self):
        from record_pr02_evidence import valid_report

        report = self.passing_report()
        self.assertTrue(valid_report(report, self.root))
        report["checks"].append(dict(report["checks"][0]))
        self.assertFalse(valid_report(report, self.root))
        report = self.passing_report()
        del report["checks"][0]["log_sha256"]
        self.assertFalse(valid_report(report, self.root))

    def test_evidence_destination_links_are_not_followed(self):
        from record_pr02_evidence import write_artifact

        destination = self.root / "evidence"
        destination.mkdir()
        outside = self.root / "original.txt"
        outside.write_bytes(b"preserve")
        (destination / "verification.json").symlink_to(outside)
        with self.assertRaises((OSError, ValueError)):
            write_artifact(destination, "verification.json", b"untrusted")
        self.assertEqual(outside.read_bytes(), b"preserve")

    def passing_report(self):
        regression = {
            "status": "PASSED",
            "tests": 1,
            "collected": 1,
            "errors": 0,
            "failures": 0,
            "skipped": 0,
            "expected_failures": 0,
            "unexpected_successes": 0,
        }
        documents = {
            "regressions": regression,
            "doctor": doctor(load()),
            "installed-doctor": doctor(load()),
            "source-contract": doctor(load()),
            "workflow-policy": {"status": "PASSED", "files": 19, "yaml_files": 18},
            "offline-inspection": {
                "status": "INSPECTED_LOCAL",
                "files": 0,
                "auto_merge": False,
                "risk_tier": 1,
                "provider": "NOT_RUN",
                "remote": "NOT_RUN",
            },
        }
        checks = []
        for name in sorted(recorder.REQUIRED_CHECKS):
            payload = (json.dumps(documents[name]) if name in documents else "") + "\n"
            path = self.root / (name + ".log")
            path.write_text(payload, encoding="utf-8", newline="\n")
            check = {
                "name": name,
                "argv": [sys.executable, "reviewed-fixture"],
                "status": "PASSED",
                "exit_code": 0,
                "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            if name == "regressions":
                check["result"] = regression
            checks.append(check)
        return {
            "status": "PASSED_LOCAL",
            "run_id": "00000000-0000-4000-8000-000000000001",
            "checks": checks,
            "python_lint_scope": list(ci.SCOPE),
            "privileged_automation": "DISABLED",
            "hosted_workflows": "NOT_RUN",
        }

    def test_stale_or_semantically_invalid_evidence_does_not_pass(self):
        report = self.passing_report()
        self.assertFalse(
            recorder.valid_report(report, self.root, "00000000-0000-4000-8000-000000000002")
        )
        check = next(c for c in report["checks"] if c["name"] == "doctor")
        path = self.root / "doctor.log"
        path.write_bytes(b'{"status":"READY_OFFLINE"}\n')
        check["log_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertFalse(recorder.valid_report(report, self.root))

    def test_explicit_python_lock_is_visible_and_invalid_directives_block(self):
        (self.root / "pyproject.toml").write_text('[project]\nname="fixture"\n')
        lock = self.root / "dependencies.lock"
        lock.write_text("fixturelib==1.0 --hash=sha256:" + "0" * 64 + "\n")
        file = self.root / "configuration.json"
        file.write_text(
            json.dumps(
                {
                    "version": 1,
                    "capabilities": {},
                    "targets": [],
                    "workspaces": [
                        {
                            "path": ".",
                            "language": "python",
                            "manager": "pip",
                            "lockfile": lock.name,
                            "commands": {"test": ["python", "-m", "unittest"]},
                        }
                    ],
                }
            )
        )
        workspace = plan(self.root, load(file))["workspaces"][0]
        self.assertEqual(workspace["lockfile"], lock.name)
        self.assertIn("--require-hashes", workspace["setup"])
        lock.write_text("--index-url https://example.invalid\n")
        with self.assertRaises(Blocked):
            plan(self.root, load(file))

    def test_cli_invalid_utf8_is_sanitized_and_nonzero(self):
        file = self.root / "input.json"
        file.write_bytes(b"\xff\xfe")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["doctor", "--config", str(file)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "BLOCKED")
