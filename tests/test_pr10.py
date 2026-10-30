"""PR 10 contracts: optional SDK separation and fail-closed read-only integration."""

import copy
import hashlib
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

from forgestra import integrations as i
from forgestra.cli import main
from forgestra.verification import validate_optional
from forgestra_safety import Blocked, private_output_workspace
from pr10_mcp_validation import acquire, valid_mcp, acceptance

ROOT = Path(__file__).resolve().parents[1]


class OptionalIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.scope = private_output_workspace()
        self.parent = self.scope.__enter__()
        self.addCleanup(self.scope.__exit__, None, None, None)
        self.root = self.parent / "root"
        self.root.mkdir()
        (self.root / "target.py").write_text(
            "raise RuntimeError('Never execute target')\n", encoding="utf-8"
        )

    def source(self):
        target = self.parent / "source"
        for name in (
            "pyproject.toml",
            "src/forgestra_mcp/__init__.py",
            "src/forgestra_mcp/__main__.py",
            "src/forgestra_mcp/server.py",
        ):
            path = target / "integrations/mcp" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "integrations/mcp" / name, path)
        for name in ("config/pr10-mcp-tools.json", "requirements/mcp.lock"):
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
        return target

    def test_catalogue_is_honest_and_all_privileged_capabilities_disabled(self):
        status = i.catalogue()
        self.assertTrue(all(v == "DISABLED" for v in status["privileged_capabilities"].values()))
        for name in ("workik", "lovable", "mobile"):
            self.assertEqual(status["integrations"][name]["status"], "PLANNED")
        self.assertNotIn("mcp", sys.modules)

    def test_demo_never_claims_live_sales_or_outreach(self):
        demo = i.sales_demo()
        self.assertEqual(demo["status"], "DEMO")
        self.assertIs(demo["is_mock"], True)
        self.assertIsNone(demo["provider_result_id"])
        self.assertEqual(demo["outreach"], "DISABLED")
        self.assertTrue(demo["prospects"][0]["email"].endswith(".invalid"))

    def test_unavailable_workflow_is_structured_and_never_dispatched(self):
        with patch("forgestra.integrations.subprocess.run") as run:
            self.assertEqual(
                i.dispatch("derive_product", {}, self.root), i.error("WORKFLOW_UNAVAILABLE")
            )
            for name in ("trigger_sync", "outreach", "workik", "lovable", "mobile"):
                self.assertEqual(i.dispatch(name, {}, self.root), i.error("UNSUPPORTED_OPERATION"))
            run.assert_not_called()

    def test_tool_arguments_cannot_select_root_or_commands(self):
        arguments: tuple[object, ...] = (
            {"root": "../outside"},
            {"command": "gh push"},
            {"approved": True},
            [],
        )
        for args in arguments:
            with patch("forgestra.integrations.subprocess.run") as run:
                self.assertEqual(
                    i.dispatch("inspect_workspace", args, self.root), i.error("INVALID_ARGUMENTS")
                )
                run.assert_not_called()

    def test_unknown_tool_type_is_rejected_without_exception(self):
        self.assertEqual(i.dispatch([], {}, self.root), i.error("INVALID_ARGUMENTS"))

    def test_timeout_is_typed_without_log_or_path_leak(self):
        with patch(
            "forgestra.integrations.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["private-command"], 10),
        ):
            self.assertEqual(i.dispatch("inspect_workspace", {}, self.root), i.error("TIMEOUT"))

    def test_nonzero_exit_cannot_become_success(self):
        with patch(
            "forgestra.integrations.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1, "private-token", "private-error"),
        ):
            self.assertEqual(
                i.dispatch("inspect_workspace", {}, self.root), i.error("PROCESS_FAILED")
            )

    def test_process_unavailable_is_typed(self):
        with patch("forgestra.integrations.subprocess.run", side_effect=OSError("private-name")):
            self.assertEqual(
                i.dispatch("inspect_workspace", {}, self.root), i.error("PROCESS_UNAVAILABLE")
            )

    def test_invalid_and_boolean_results_fail_closed(self):
        for text in ("{}", '{"status":"INSPECTED_LOCAL","files":true}', "not-json"):
            with patch(
                "forgestra.integrations.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, text, ""),
            ):
                self.assertEqual(
                    i.dispatch("inspect_workspace", {}, self.root), i.error("INVALID_RESULT")
                )

    def test_inspection_command_and_environment_are_fixed(self):
        want = {
            "status": "INSPECTED_LOCAL",
            "files": 1,
            "risk_tier": 1,
            "auto_merge": False,
            "provider": "NOT_RUN",
            "remote": "NOT_RUN",
        }
        with patch.dict(
            os.environ,
            {"GITHUB_TOKEN": "synthetic-credential", "ANTHROPIC_API_KEY": "synthetic-credential"},
        ):
            with patch(
                "forgestra.integrations.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, json.dumps(want), ""),
            ) as run:
                self.assertEqual(i.dispatch("inspect_workspace", {}, self.root), want)
                self.assertEqual(
                    run.call_args.args[0],
                    [sys.executable, "-I", "-m", "forgestra", "inspect", str(self.root.resolve())],
                )
                self.assertNotIn("GITHUB_TOKEN", run.call_args.kwargs["env"])
                self.assertNotIn("ANTHROPIC_API_KEY", run.call_args.kwargs["env"])
                self.assertEqual(run.call_args.kwargs["timeout"], 10)

    def test_root_changes_invalidate_result(self):
        def changed(*args, **kwargs):
            (self.root / "new.txt").write_text("new", encoding="utf-8")
            return subprocess.CompletedProcess(
                [],
                0,
                json.dumps(
                    {
                        "status": "INSPECTED_LOCAL",
                        "files": 1,
                        "risk_tier": 1,
                        "auto_merge": False,
                        "provider": "NOT_RUN",
                        "remote": "NOT_RUN",
                    }
                ),
                "",
            )

        with patch("forgestra.integrations.subprocess.run", side_effect=changed):
            self.assertEqual(
                i.dispatch("inspect_workspace", {}, self.root), i.error("INVALID_RESULT")
            )

    def test_missing_or_linked_root_is_denied(self):
        self.assertEqual(
            i.dispatch("inspect_workspace", {}, self.parent / "missing"), i.error("INVALID_ROOT")
        )
        with patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaises(Blocked):
                i.root_inventory(self.root)

    def test_inventory_depth_is_bounded(self):
        path = self.root
        for n in range(18):
            path = path / str(n)
            path.mkdir()
        with self.assertRaises(Blocked):
            i.root_inventory(self.root)

    def test_kill_switch_stops_all_tool_effects(self):
        with patch.dict(os.environ, {"FORGESTRA_KILL_SWITCH": "1"}):
            with patch("forgestra.integrations.subprocess.run") as run:
                for name in i.TOOLS:
                    self.assertEqual(i.dispatch(name, {}, self.root), i.error("KILL_SWITCH"))
                run.assert_not_called()

    def test_client_configuration_is_only_a_read_only_plan(self):
        result = i.client_config(Path(sys.executable).absolute(), self.root)
        entry = result["mcpServers"]["forgestra-local-readonly"]
        self.assertEqual(entry["env"], {})
        self.assertEqual(
            entry["args"], ["-I", "-m", "forgestra_mcp", "--root", str(self.root.resolve())]
        )
        self.assertEqual(json.loads((ROOT / "mcp.json").read_text()), {"mcpServers": {}})
        with self.assertRaises(Blocked):
            i.client_config(Path("python"), self.root)

    def test_catalogue_and_client_cli_are_real(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["integrations"]), 0)
        self.assertEqual(json.loads(output.getvalue()), i.catalogue())
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(
                main(["integrations", "--client-python", sys.executable, "--root", str(self.root)]),
                0,
            )
        self.assertEqual(json.loads(output.getvalue())["activation"], "NOT_APPLIED")

    def test_optional_source_and_lock_are_independent_of_core(self):
        source = self.source()
        self.assertEqual(validate_optional(source)["sdk"], "mcp==2.3.0")

    def test_optional_build_hook_is_rejected(self):
        source = self.source()
        (source / "integrations/mcp/setup.py").write_text("raise RuntimeError()", encoding="utf-8")
        with self.assertRaises(Blocked):
            validate_optional(source)

    def test_optional_backend_or_sdk_drift_is_rejected(self):
        source = self.source()
        path = source / "integrations/mcp/pyproject.toml"
        original = path.read_text(encoding="utf-8")
        for text in (
            original.replace("setuptools.build_meta", "untrusted.backend"),
            original.replace("mcp==2.3.0", "mcp>=2"),
        ):
            path.write_text(text, encoding="utf-8")
            with self.assertRaises(Blocked):
                validate_optional(source)

    def test_optional_lock_drift_is_rejected(self):
        source = self.source()
        path = source / "requirements/mcp.lock"
        path.write_text(path.read_text() + "unreviewed==1\n", encoding="utf-8")
        with self.assertRaises(Blocked):
            validate_optional(source)

    def test_optional_wheel_paths_and_origins_are_rejected(self):
        source = self.source()
        path = source / "config/pr10-mcp-tools.json"
        original = json.loads(path.read_text())
        for key, value in (
            ("filename", "../outside.whl"),
            ("url", "https://untrusted.invalid/package.whl"),
        ):
            modified = copy.deepcopy(original)
            modified["platforms"]["windows"][0][key] = value
            path.write_text(json.dumps(modified), encoding="utf-8")
            with self.assertRaises(Blocked):
                validate_optional(source)

    def test_missing_sdk_tools_fail_without_download(self):
        real = Path.is_file

        def available(path):
            return False if path.parent == ROOT / ".tools/pr10-wheels" else real(path)

        with patch("pr10_mcp_validation.Path.is_file", available):
            with patch("pr10_mcp_validation.urllib.request.urlopen") as request:
                with self.assertRaises((Blocked, ValueError)):
                    acquire()
                request.assert_not_called()

    def test_false_optional_acceptance_summaries_fail(self):
        for value in (None, {}, {"status": "PASSED_LOCAL", "protocol": {"tests": 0}}):
            self.assertFalse(valid_mcp(value))

    def test_numeric_auto_merge_result_is_rejected(self):
        result = dict(
            status="INSPECTED_LOCAL",
            files=1,
            risk_tier=1,
            auto_merge=0,
            provider="NOT_RUN",
            remote="NOT_RUN",
        )
        with patch(
            "forgestra.integrations.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, json.dumps(result), ""),
        ):
            self.assertEqual(
                i.dispatch("inspect_workspace", {}, self.root), i.error("INVALID_RESULT")
            )

    def test_client_interpreter_linked_ancestor_is_denied(self):
        python = Path(sys.executable).absolute()
        original = Path.is_symlink

        def linked(path):
            return path == python.parent or original(path)

        with patch.object(Path, "is_symlink", linked):
            with self.assertRaises(Blocked):
                i.client_config(python, self.root)

    def test_mcp_record_rejects_numeric_flags_and_unbound_logs(self):
        # Execute the current authored SDK session; never substitute historical
        # archive bytes or a synthetic success receipt for actual protocol work.
        record = acceptance()
        python = str(
            Path("<fixture>/optional-env")
            / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        )
        record["commands"][8]["argv"] = [
            python,
            "-I",
            str(Path("<fixture>/protocol.py")),
            "--protocol",
            str(Path("<fixture>/fixture")),
        ]
        record["commands"][9]["argv"] = [python, "-I", "-m", "forgestra", "integrations"]
        record["dependency_wheels"] = {w["filename"]: w["sha256"] for w in acquire()}
        record["optional_payload_sha256"] = {
            n: hashlib.sha256(
                (ROOT / "integrations/mcp/src/forgestra_mcp" / n).read_bytes()
            ).hexdigest()
            for n in ("__init__.py", "__main__.py", "server.py")
        }
        self.assertTrue(valid_mcp(record))
        for index, change in enumerate(
            (
                lambda r: r["protocol"]["calls"]["inspect_timeout"].update(is_error=1),
                lambda r: r["protocol"]["inventory"][0]["annotations"].update(destructive_hint=0),
                lambda r: r["commands"][8].update(
                    log="", log_sha256=hashlib.sha256(b"").hexdigest()
                ),
                lambda r: r["commands"][8].update(argv=[]),
                lambda r: r["commands"][9].update(argv=["unrelated-command"]),
            )
        ):
            bad = copy.deepcopy(record)
            change(bad)
            if index < 2:
                # Keep log agreement so the typed JSON check itself must reject it.
                log = json.dumps(bad["protocol"], sort_keys=True) + "\n"
                bad["commands"][8].update(
                    log=log, log_sha256=hashlib.sha256(log.encode()).hexdigest()
                )
            self.assertFalse(valid_mcp(bad))
