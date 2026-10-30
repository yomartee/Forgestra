"""PR 02 offline contracts; fixtures never execute candidate target commands."""

import contextlib
import importlib.metadata
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from forgestra.cli import main, doctor, DEV_PACKAGES
from forgestra.configuration import load
from forgestra.workspaces import plan
from forgestra_safety import Blocked, CAPABILITIES, Policy, validate_manifest, classify_diff
import bootstrap
import acquire_tools
import ci


class PackagingContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="forgestra-pr02-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def cli(self, argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(argv)
        return code, json.loads(output.getvalue())

    def config(self, document):
        path = self.root / "forgestra.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def node(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "package.json").write_text(
            json.dumps(
                {
                    "scripts": {
                        "build": "evil; never executed",
                        "test": "exit 99",
                        "lint": "$(never)",
                        "custom-build": "never run",
                    }
                }
            )
        )
        (directory / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{"":{}}}')

    def test_core_doctor_is_offline_without_credentials_or_optional_imports(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), patch(
            "subprocess.run", side_effect=AssertionError("process forbidden")
        ):
            code, result = self.cli(["doctor"])
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "READY_OFFLINE")
        self.assertEqual(result["connectivity"], "NOT_RUN")
        self.assertNotIn("mcp", sys.modules)
        self.assertNotIn("anthropic", sys.modules)

    def test_doctor_missing_dependencies_fails_without_importing_them(self):
        with patch(
            "importlib.metadata.version", side_effect=importlib.metadata.PackageNotFoundError
        ):
            result = doctor(load(), development=True)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(len(result["issues"]), len(DEV_PACKAGES))

    def test_missing_source_command_or_workflow_blocks_doctor(self):
        code, result = self.cli(["doctor", "--source", str(self.root)])
        self.assertEqual(code, 1)
        self.assertIn("MISSING_SOURCE_COMMAND_OR_WORKFLOW", result["issues"])
        self.assertFalse(list(self.root.iterdir()))

    def test_ci_rejects_zero_test_and_false_success_results(self):
        for document in ({"status": "PASSED", "tests": 0}, {"status": "BLOCKED"}, {}):
            self.assertFalse(ci.assess("regressions", 0, json.dumps(document)))
        for name in ("doctor", "installed-doctor", "workflow-policy", "offline-inspection"):
            self.assertFalse(ci.assess(name, 0, '{"status":"BLOCKED"}'))

    def test_native_archive_tampering_is_rejected_before_extraction(self):
        with self.assertRaises(ValueError):
            acquire_tools.extract_verified(b"not a tool", {"sha256": "0" * 64})

    def test_runtime_and_authenticated_connectivity_are_not_fabricated(self):
        with patch("forgestra.cli.sys.version_info", (3, 13, 0)):
            self.assertIn("UNSUPPORTED_RUNTIME", doctor(load())["issues"])
            code, unsupported = self.cli(["inspect", str(self.root)])
            self.assertEqual(code, 1)
            self.assertEqual(unsupported["reason_code"], "UNSUPPORTED_RUNTIME")
        code, result = self.cli(["doctor", "--connectivity"])
        self.assertEqual(code, 1)
        self.assertEqual(result["connectivity"], "NOT_RUN")

    def test_missing_and_malformed_config_are_blocking_and_sanitized(self):
        path = self.root / "missing.json"
        code, missing = self.cli(["doctor", "--config", str(path)])
        self.assertEqual(code, 1)
        self.assertEqual(missing["reason_code"], "MISSING_CONFIGURATION")
        for text in ["null", '{"version":1,"version":1}', "NaN", "{}"]:
            path.write_text(text)
            code, result = self.cli(["doctor", "--config", str(path)])
            self.assertEqual(code, 1)
            self.assertNotIn(str(path), json.dumps(result))

    def test_configuration_cannot_enable_any_privileged_capability(self):
        for capability in CAPABILITIES:
            path = self.config(
                {"version": 1, "capabilities": {capability: True}, "targets": [], "workspaces": []}
            )
            self.assertEqual(self.cli(["config", "--config", str(path)])[0], 1)
            with self.assertRaises(Blocked):
                Policy().require(capability)

    def test_package_and_ci_controls_cannot_be_runtime_generated_or_downgraded(self):
        for path in (
            "src/forgestra/cli.py",
            "scripts/acquire_tools.py",
            "scripts/bootstrap.py",
            "scripts/ci.py",
            "scripts/record_pr02_evidence.py",
            "scripts/forgestra_cli.py",
        ):
            with self.assertRaises(Blocked):
                validate_manifest([{"path": path, "content": "untrusted"}])
            self.assertEqual(classify_diff([{"operation": "modify", "path": path}]), 2)

    def test_pure_node_plan_uses_node_manager_for_every_command(self):
        self.node(self.root)
        with patch("subprocess.run", side_effect=AssertionError("no target execution")):
            result = plan(self.root, load())
        workspace = result["workspaces"][0]
        self.assertEqual(workspace["setup"], ["npm", "ci"])
        self.assertEqual(workspace["commands"]["build"], ["npm", "run", "build"])
        self.assertEqual(result["execution"], "BLOCKED")

    def test_factory_python_requirements_do_not_override_node(self):
        self.node(self.root)
        (self.root / "requirements.txt").write_text("# Factory tooling, not Node dependencies")
        workspace = plan(self.root, load())["workspaces"][0]
        self.assertEqual(workspace["language"], "javascript")
        self.assertEqual(workspace["manager"], "npm")
        self.assertTrue(all(v[0] == "npm" for v in workspace["commands"].values()))

    def test_pure_python_proposal_does_not_guess_build_or_dependency_install(self):
        (self.root / "pyproject.toml").write_text('[project]\nname="fixture"')
        workspace = plan(self.root, load())["workspaces"][0]
        self.assertEqual(workspace["language"], "python")
        self.assertEqual(workspace["commands"], {})
        self.assertIsNone(workspace["setup"])

    def test_explicit_mixed_workspace_preserves_cwd_and_argv(self):
        self.node(self.root / "web")
        (self.root / "api").mkdir()
        (self.root / "api/pyproject.toml").write_text('[project]\nname="api"')
        config = {
            "version": 1,
            "capabilities": {},
            "targets": [],
            "workspaces": [
                {
                    "path": "web",
                    "language": "javascript",
                    "manager": "npm",
                    "commands": {"build": ["npm", "run", "custom-build"]},
                },
                {
                    "path": "api",
                    "language": "python",
                    "manager": "pip",
                    "commands": {"test": ["python", "-m", "unittest", "discover", "-s", "tests"]},
                },
            ],
        }
        result = plan(self.root, load(self.config(config)))
        self.assertEqual([w["path"] for w in result["workspaces"]], ["web", "api"])
        self.assertEqual(
            result["workspaces"][0]["commands"]["build"], ["npm", "run", "custom-build"]
        )

    def test_ambiguous_locks_invalid_manifests_and_workspace_escape_fail(self):
        self.node(self.root)
        (self.root / "yarn.lock").write_text("")
        with self.assertRaises(Blocked):
            plan(self.root, load())
        (self.root / "yarn.lock").unlink()
        (self.root / "package.json").write_text('{"scripts":[],"scripts":{}}')
        with self.assertRaises(ValueError):
            plan(self.root, load())
        config = {
            "version": 1,
            "capabilities": {},
            "targets": [],
            "workspaces": [
                {"path": "../outside", "language": "python", "manager": "pip", "commands": {}}
            ],
        }
        with self.assertRaises(Blocked):
            plan(self.root, load(self.config(config)))

    def test_shell_commands_and_pip_run_build_cannot_be_configured(self):
        for argv in ["npm run build", ["pip", "run", "build"], ["sh", "-c", "anything"]]:
            path = self.config(
                {
                    "version": 1,
                    "capabilities": {},
                    "targets": [],
                    "workspaces": [
                        {
                            "path": ".",
                            "language": "javascript",
                            "manager": "npm",
                            "commands": {"build": argv},
                        }
                    ],
                }
            )
            with self.assertRaises(Blocked):
                load(path)

    def test_bootstrap_refuses_existing_environment_and_filters_credentials(self):
        (self.root / ".venv").mkdir()
        with patch.object(bootstrap, "ROOT", self.root), patch(
            "subprocess.run", side_effect=AssertionError("must not install")
        ):
            with self.assertRaises(ValueError):
                bootstrap.bootstrap(self.root)
        with patch.dict("os.environ", {"FACTORY_ADMIN_TOKEN": "synthetic"}):
            self.assertNotIn("FACTORY_ADMIN_TOKEN", bootstrap.environment())
