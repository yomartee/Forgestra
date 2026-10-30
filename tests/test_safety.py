import ast
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import unittest
from unittest.mock import patch

from forgestra_safety import (
    Blocked,
    CAPABILITIES,
    Policy,
    classify_diff,
    private_output_workspace,
    redact,
    unique_pairs,
    write_new_tree,
)
from local_generation import (
    write_creator_output,
    write_frontend_output,
    write_frontend_pages,
    ENV_EXAMPLE,
)
from check_safety import run_suite
from check_workflows import validate
from inspect_local import inspect
from public_contract import containment

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ENV = {
    key: value
    for key, value in os.environ.items()
    if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}
}
CONTAINMENT = containment(ROOT)
BASH = (
    str(Path("C:/Program Files/Git/bin/bash.exe"))
    if Path("C:/Program Files/Git/bin/bash.exe").exists()
    else shutil.which("bash")
)


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ,
            {
                **RUNTIME_ENV,
                "FORGESTRA_KILL_SWITCH": "0",
                "ANTHROPIC_API_KEY": "canary-provider-do-not-use",
                "FACTORY_ADMIN_TOKEN": "canary-admin-do-not-use",
                "WORKIK_API_KEY": "canary-workik-do-not-use",
            },
            clear=True,
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.workspace = private_output_workspace()
        self.parent = self.workspace.__enter__()
        self.addCleanup(self.workspace.__exit__, None, None, None)
        self.output = self.parent / "new-output"

    def assertAtomicReject(self, paths):
        with self.assertRaises(Blocked):
            write_creator_output(
                self.output,
                [
                    {"path": "valid/nested.txt", "content": "ok"},
                    *[{"path": p, "content": "bad"} for p in paths],
                ],
            )
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_defaults_block_all_privilege_with_credentials(self):
        for capability in CAPABILITIES:
            with self.subTest(capability=capability), self.assertRaises(Blocked):
                Policy().require(capability)

    def test_invalid_configuration(self):
        for document in [
            [],
            {},
            {"version": True, "capabilities": {}, "targets": []},
            {"version": 1, "capabilities": {"bogus": True}, "targets": []},
            {"version": 1, "capabilities": {"publication": "true"}, "targets": []},
            {
                "version": 1,
                "capabilities": {},
                "targets": [{"owner": "*", "repository": "r", "path": str(self.parent)}],
            },
        ]:
            with self.subTest(document=document), self.assertRaises(Blocked):
                Policy(document)

    def test_policy_file_missing_malformed_duplicate(self):
        config = self.parent / "policy.json"
        with self.assertRaises(Blocked):
            Policy.load(config)
        for content in ["{", '{"version":1,"version":1,"capabilities":{},"targets":[]}']:
            config.write_text(content)
            with self.assertRaises(Blocked):
                Policy.load(config)

    def test_allowlist_is_not_approval(self):
        document = {
            "version": 1,
            "capabilities": {c: True for c in CAPABILITIES},
            "targets": [{"owner": "fixture", "repository": "repo", "path": str(self.parent)}],
        }
        policy = Policy(document)
        for target in [
            None,
            ("other", "repo", str(self.parent)),
            ("fixture", "repo", str(self.parent)),
        ]:
            with self.assertRaises(Blocked):
                policy.require("publication", target)
        for capability in CAPABILITIES:
            with self.subTest(capability=capability), self.assertRaises(Blocked):
                policy.require(capability, ("fixture", "repo", str(self.parent)))

    def test_kill_switch_checked_after_policy_creation(self):
        policy = Policy()
        os.environ["FORGESTRA_KILL_SWITCH"] = "1"
        with self.assertRaisesRegex(Blocked, "kill switch"):
            policy.require("publication")
        with self.assertRaises(Blocked):
            write_creator_output(self.output, [{"path": "ok.txt", "content": "ok"}])
        self.assertFalse(self.output.exists())

    def test_real_entry_points_block_before_imports_and_effects(self):
        for name in CONTAINMENT["python_entry_points"]:
            with self.subTest(name=name):
                spec = importlib.util.spec_from_file_location("legacy_fixture", ROOT / name)
                assert spec is not None and spec.loader is not None
                module = importlib.util.module_from_spec(spec)
                with (
                    patch("subprocess.run", side_effect=AssertionError("unexpected subprocess")),
                    patch(
                        "socket.socket.connect", side_effect=AssertionError("unexpected network")
                    ),
                    patch(
                        "socket.create_connection", side_effect=AssertionError("unexpected network")
                    ),
                    patch("os.system", side_effect=AssertionError("unexpected shell")),
                    patch("os.popen", side_effect=AssertionError("unexpected shell")),
                    patch(
                        "urllib.request.urlopen", side_effect=AssertionError("unexpected network")
                    ),
                ):
                    with self.assertRaises(Blocked):
                        spec.loader.exec_module(module)

    def test_blocked_cli_is_nonzero_without_success_or_canary(self):
        # Child inherits only explicit synthetic values and OS runtime variables.
        env = {k: v for k, v in os.environ.items() if k in {"SYSTEMROOT", "WINDIR", "PATH"}}
        env.update(
            {
                "ANTHROPIC_API_KEY": "canary-provider-do-not-use",
                "FACTORY_ADMIN_TOKEN": "canary-admin-do-not-use",
            }
        )
        for name in CONTAINMENT["python_entry_points"]:
            with self.subTest(name=name):
                result = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        str(ROOT / "tests/blocked_entry_probe.py"),
                        str(ROOT / name),
                        "--target",
                        "x';$(whoami)",
                    ],
                    cwd=self.parent,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("BLOCKED:", output)
                self.assertNotIn("canary-", output)
                self.assertNotIn("successful", output.lower())
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_customer_files_preserved_on_blocked_install_and_sync(self):
        names = [
            ".github/workflows/customer.yml",
            "scripts/custom.py",
            "config/custom.json",
            "requirements.txt",
            "CLAUDE.md",
            "src/custom.py",
        ]
        for name in names:
            file = self.parent / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b"customer\x00\xff\r\n")

        def snapshot():
            return {
                p.relative_to(self.parent).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.parent.rglob("*")
                if p.is_file()
            }

        before = snapshot()
        for name in ["scripts/install_remote.py", "scripts/agents/sync_manager.py"]:
            spec = importlib.util.spec_from_file_location("blocked_customer", ROOT / name)
            assert spec is not None and spec.loader is not None
            with self.assertRaises(Blocked):
                spec.loader.exec_module(importlib.util.module_from_spec(spec))
        with self.assertRaises(Blocked):
            write_new_tree(self.parent, [{"path": "CLAUDE.md", "content": "replace"}])
        self.assertEqual(before, snapshot())

    def test_path_attacks_atomic(self):
        for path in [
            "../escape",
            "/tmp/escape",
            "C:/escape",
            "C:escape",
            "\\\\server\\share\\escape",
            "a\\..\\escape",
            "a/../escape",
            "a//b",
            "a/.",
            "NUL.txt",
            "file.",
            "-option",
            "quote's.txt",
            "white space.txt",
            "line\nbreak",
            "$(whoami).txt",
            "a:stream",
        ]:
            with self.subTest(path=path):
                self.assertAtomicReject([path])

    def test_control_paths_atomic(self):
        for path in [
            ".git/config",
            ".github/workflows/test.yml",
            ".github/CODEOWNERS",
            "AGENTS.md",
            "nested/CLAUDE.md",
            ".codex/config.toml",
            ".agents/prompt.md",
            "config/policy.json",
            "prompts/test.md",
            "approval.json",
            "permissions.json",
        ]:
            with self.subTest(path=path):
                self.assertAtomicReject([path])

    def test_conflicting_destinations_atomic(self):
        for paths in [["A.txt", "a.txt"], ["a", "a/b"], ["a/b", "a"]]:
            self.assertAtomicReject(paths)

    def test_rename_delete_and_embedded_approval_rejected(self):
        for item in [
            {"path": "x", "content": "x", "approved": True},
            {"path": "x", "operation": "delete"},
            {"path": "x", "source": ".github/workflows/x.yml", "operation": "rename"},
        ]:
            with self.assertRaises(Blocked):
                write_new_tree(self.output, [{"path": "ok.txt", "content": "ok"}, item])
            self.assertFalse(self.output.exists())

    def test_nested_creator_output(self):
        result = write_creator_output(
            self.output, [{"path": "src/nested/file.py", "content": "value = 1\n"}]
        )
        self.assertEqual(result["status"], "LOCAL_OUTPUT_WRITTEN")
        self.assertEqual((self.output / "src/nested/file.py").read_bytes(), b"value = 1\n")
        self.assertEqual(result["integration"], "NOT_RUN")

    def test_frontend_manifest_and_placeholders(self):
        result = write_frontend_output(self.output, ["products", "order_items"])
        self.assertEqual(result["files"], 3)
        self.assertEqual((self.output / ".env.example").read_text(), ENV_EXAMPLE)
        for file in self.output.rglob("*"):
            if file.is_file():
                self.assertNotIn("canary-", file.read_text())
                self.assertNotIn("ADMIN_SECRET", file.read_text())

    def test_frontend_invalid_identifier_leaves_no_partial_output(self):
        for resources in [
            ["products", "../bad"],
            ["products", "products"],
            ["products", "Bad"],
            [],
        ]:
            with self.assertRaises(Blocked):
                write_frontend_output(self.output, resources)
            self.assertFalse(self.output.exists())

    def test_symlink_escape(self):
        link = self.parent / "link"
        outside = self.parent / "outside"
        outside.mkdir()
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest("OS symlink creation unavailable: " + type(error).__name__)
        with self.assertRaises(Blocked):
            write_creator_output(link / "output", [{"path": "x", "content": "bad"}])
        self.assertEqual(list(outside.iterdir()), [])

    def test_staging_failure_cleans_output(self):
        with patch.object(Path, "write_text", side_effect=OSError("canary-admin-do-not-use")):
            with self.assertRaises(Blocked) as error:
                write_creator_output(self.output, [{"path": "ok.txt", "content": "ok"}])
        self.assertNotIn("canary-", str(error.exception))
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_canary_manifest_and_redaction(self):
        for canary in [
            "canary-provider-do-not-use",
            "canary-admin-do-not-use",
            "canary-workik-do-not-use",
        ]:
            with self.assertRaises(Blocked) as error:
                write_creator_output(self.output, [{"path": "x.txt", "content": canary}])
            self.assertNotIn(canary, str(error.exception))
            self.assertNotIn(canary, redact("error: " + canary))
        self.assertNotIn(
            "unknown-password", redact("git clone https://unknown-password@github.com/a/b")
        )

    def test_canary_filename_and_runtime_env_blocked(self):
        for path, content in [
            ("canary-provider-do-not-use", "ok"),
            (".env.production", "ok"),
            (".env.example", "WORKIK_API_KEY=unknown-value"),
        ]:
            with self.assertRaises(Blocked):
                write_creator_output(self.output, [{"path": path, "content": content}])
            self.assertFalse(self.output.exists())

    def test_actual_generation_writers_delegate_to_shared_boundary(self):
        creator = ast.parse((ROOT / "scripts/autonomous_growth.py").read_text(encoding="utf-8"))
        method = next(
            n
            for n in ast.walk(creator)
            if isinstance(n, ast.FunctionDef) and n.name == "create_repository"
        )
        calls = [
            n.func.id
            for n in ast.walk(method)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        ]
        self.assertIn("write_creator_output", calls)
        frontend = ast.parse(
            (ROOT / "scripts/agents/frontend_engine.py").read_text(encoding="utf-8")
        )
        method = next(
            n
            for n in ast.walk(frontend)
            if isinstance(n, ast.FunctionDef) and n.name == "_generate_resource_pages"
        )
        calls = [
            n.func.id
            for n in ast.walk(method)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        ]
        self.assertIn("write_frontend_pages", calls)
        with self.assertRaises(Blocked):
            write_frontend_pages(
                self.output,
                {
                    "resources": [
                        {"name": "safe", "label": "Safe"},
                        {"name": "../bad", "label": "Bad"},
                    ]
                },
            )
        self.assertFalse(self.output.exists())

    def test_staging_publish_failure_preserves_destination(self):
        with patch.object(Path, "rename", side_effect=OSError("canary-provider-do-not-use")):
            with self.assertRaises(Blocked):
                write_creator_output(self.output, [{"path": "x.txt", "content": "ok"}])
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_kill_switch_during_staging_prevents_publication(self):
        real_write = Path.write_text

        def cancel(path, content, **kwargs):
            result = real_write(path, content, **kwargs)
            os.environ["FORGESTRA_KILL_SWITCH"] = "1"
            return result

        with patch.object(Path, "write_text", cancel):
            with self.assertRaises(Blocked):
                write_creator_output(
                    self.output,
                    [
                        {"path": "first.txt", "content": "ok"},
                        {"path": "second.txt", "content": "ok"},
                    ],
                )
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_executable_and_configuration_risk(self):
        for path in [
            "package.json",
            "Dockerfile",
            "backend/service.py",
            "mcp-server/repo-operations.py",
            "config/system_architect.txt",
            ".github/CODEOWNERS",
            "requirements.txt",
            "unknown.xyz",
            "tests/test_auth.py",
            "build/production-test.py",
            "auth-build.py",
            "tests/test_safe.py",
        ]:
            with self.subTest(path=path):
                self.assertGreaterEqual(classify_diff([{"operation": "modify", "path": path}]), 1)

    def test_full_diff_and_operation_precedence(self):
        for changes in [
            [
                {
                    "operation": "rename",
                    "source": ".github/workflows/test.yml",
                    "path": "docs/test.md",
                }
            ],
            [{"operation": "rename", "source": "docs/test.md", "path": "auth/build.md"}],
            [{"operation": "delete", "path": ".github/CODEOWNERS"}],
            [
                {"operation": "modify", "path": "docs/readme.md"},
                {"operation": "modify", "path": "package.json"},
            ],
        ]:
            self.assertEqual(classify_diff(changes), 2)
        self.assertEqual(classify_diff([{"operation": "modify", "path": "docs/readme.md"}]), 0)
        self.assertEqual(classify_diff([{"operation": "delete", "path": "docs/readme.md"}]), 1)

    def test_hostile_diff_names_are_data(self):
        for name in ["a'b.py", "a\nb", "-option", "$(touch PWNED)", "a; echo PWNED"]:
            self.assertEqual(classify_diff([{"operation": "modify", "path": name}]), 2)
        self.assertFalse((self.parent / "PWNED").exists())

    def test_zero_tests_fail(self):
        self.assertEqual(run_suite(unittest.TestSuite(), io.StringIO())["status"], "FAILED")

    def test_skipped_security_fixture_fails_gate(self):
        class UnavailableFixture(unittest.TestCase):
            @unittest.skip("fixture unavailable")
            def test_unavailable(self):
                pass

        result = run_suite(
            unittest.defaultTestLoader.loadTestsFromTestCase(UnavailableFixture), io.StringIO()
        )
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["skipped"], 1)

    def test_invalid_diff_objects_require_privileged_review(self):
        for changes in [None, list[object](), "bad"]:
            self.assertGreaterEqual(classify_diff(changes), 1)
        for change in [
            {"operation": [], "path": "docs/x.md"},
            {"operation": "rename", "path": "x"},
            {"operation": "modify", "path": None},
            {"operation": "modify", "path": "x", "approved": True},
        ]:
            self.assertEqual(classify_diff([change]), 2)

    def test_legacy_workflows_have_no_privilege_or_interpolation(self):
        for name in CONTAINMENT["workflows"]:
            source = (ROOT / name).read_text()
            document = validate(ROOT / name)
            self.assertEqual(document["permissions"], {})
            self.assertEqual(document["on"], {"workflow_dispatch": None})
            self.assertEqual(set(document["jobs"]), {"blocked"})
            self.assertIn("exit 1", document["jobs"]["blocked"]["steps"][0]["run"])
            for forbidden in [
                "${{",
                "secrets.",
                '"uses"',
                '"schedule"',
                '"workflow_run"',
                '"issue_comment"',
                "git push",
                "--auto",
            ]:
                self.assertNotIn(forbidden, source)

    def test_workflow_duplicate_keys_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"jobs":{},"jobs":{}}', object_pairs_hook=unique_pairs)
        workflow = validate(ROOT / ".github/workflows/safety-regressions.yml")
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        steps = workflow["jobs"]["public-product"]["steps"]
        self.assertFalse(steps[0]["with"]["persist-credentials"])
        self.assertNotIn("secrets.", json.dumps(workflow))

    def test_optional_service_manifests_do_not_bypass_policy(self):
        mcp = json.loads((ROOT / "mcp.json").read_text(), object_pairs_hook=unique_pairs)
        self.assertEqual(mcp, {"mcpServers": {}})
        dependabot = json.loads(
            (ROOT / ".github/dependabot.yml").read_text(), object_pairs_hook=unique_pairs
        )
        self.assertEqual(dependabot, {"version": 2, "updates": []})
        copilot = json.loads(
            (ROOT / ".github/copilot-setup-steps.yml").read_text(), object_pairs_hook=unique_pairs
        )
        self.assertEqual(copilot["setup"], [])
        self.assertIn("run_safety_isolated.py", copilot["test"][0]["run"])

    def test_inspection_uses_shared_classifier_without_remote_effects(self):
        (self.parent / "custom.txt").write_text("customer")
        with patch("subprocess.run", side_effect=AssertionError("subprocess forbidden")):
            result = inspect(self.parent, [{"operation": "modify", "path": "package.json"}])
        self.assertEqual(result["risk_tier"], 2)
        self.assertEqual(result["provider"], "NOT_RUN")
        self.assertFalse(result["auto_merge"])

    def test_shell_entry_points_stop_before_legacy_body(self):
        for name in [
            "scripts/install_transformation_kit.sh",
            "scripts/install_to_voxguard.sh",
            "scripts/init_factory.sh",
            "scripts/transform/setup_sync.sh",
            "scripts/validate-trinity.sh",
        ]:
            lines = (ROOT / name).read_text(encoding="utf-8").splitlines()
            self.assertEqual(lines[3], "exit 1")
            self.assertIn("BLOCKED:", lines[2])
            self.assertNotIn(b"\r", (ROOT / name).read_bytes())
            self.assertTrue(all(not line or line.startswith("#") for line in lines[4:]))

    def test_shell_entry_points_execute_blocked_in_customer_fixture(self):
        if not BASH:
            self.skipTest("bash unavailable")
        customer = self.parent / "requirements.txt"
        customer.write_bytes(b"customer requirements\r\n")
        before = customer.read_bytes()
        for name in [
            "scripts/install_transformation_kit.sh",
            "scripts/install_to_voxguard.sh",
            "scripts/init_factory.sh",
            "scripts/transform/setup_sync.sh",
            "scripts/validate-trinity.sh",
        ]:
            result = subprocess.run(
                [BASH, str(ROOT / name), str(self.parent), "';$(touch PWNED)"],
                cwd=self.parent,
                env={**os.environ, "PATH": str(self.parent / "no-external-commands")},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("BLOCKED:", result.stderr)
            self.assertNotIn("canary-", result.stdout + result.stderr)
            self.assertEqual(customer.read_bytes(), before)
        self.assertEqual([p.name for p in self.parent.iterdir()], ["requirements.txt"])


if __name__ == "__main__":
    unittest.main()
