"""PR 07 independent specification, quota, replay and authority regressions."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any
import unittest
from unittest.mock import patch

from forgestra import creation
from forgestra.cli import main
from forgestra_safety import Blocked, private_output_workspace, write_new_tree


class CreationTests(unittest.TestCase):
    def setUp(self):
        self.spec = copy.deepcopy(creation.FIXTURE_SPEC)

    def second(self):
        spec = copy.deepcopy(self.spec)
        spec["request_id"] = "07100000-0000-4000-8000-000000000002"
        spec["repository"] += "-second"
        spec["frontend"]["repository"] = spec["repository"]
        return spec

    def test_specification_requires_explicit_complete_contract(self):
        invalid: tuple[object, ...] = (None, {}, [], "research something", True)
        for value in invalid:
            with self.assertRaises((Blocked, ValueError)):
                creation.plan(value)
        for key in self.spec:
            changed = copy.deepcopy(self.spec)
            del changed[key]
            with self.assertRaises(Blocked):
                creation.plan(changed)

    def test_authority_flags_and_counts_cannot_be_smuggled_into_spec(self):
        for key in ("approved", "publish", "target_count", "commands", "output", "policy"):
            changed = {**self.spec, key: True}
            with self.assertRaises(Blocked):
                creation.plan(changed)

    def test_unknown_versions_and_noncanonical_ids_fail(self):
        invalid: tuple[object, ...] = (True, 0, 2, "1")
        for version in invalid:
            with self.assertRaises(Blocked):
                creation.plan({**self.spec, "schema_version": version})
        for request in ("", "--option", "../outside", "not-a-uuid"):
            with self.assertRaises((Blocked, ValueError)):
                creation.plan({**self.spec, "request_id": request})

    def test_single_repository_mapping_is_exact(self):
        for target in ("other/wrong", "https://github.com/yomartee/app", "../app", "a/app;cmd"):
            changed = copy.deepcopy(self.spec)
            changed["frontend"]["repository"] = target
            with self.assertRaises(Blocked):
                creation.plan(changed)
        changed = copy.deepcopy(self.spec)
        changed["frontend"]["path"] = "../other"
        with self.assertRaises(Blocked):
            creation.plan(changed)

    def test_unknown_missing_duplicate_illustrative_components_fail(self):
        for components in ([], ["OAuth 2.0 Authentication"], ["react", "react"]):
            with self.assertRaises(Blocked):
                creation.plan({**self.spec, "components": components})

    def test_invalid_domain_never_returns_product_plan(self):
        invalid: tuple[object, ...] = ({}, {"resources": []}, "type Query { placeholder: String }")
        for domain in invalid:
            with self.assertRaises(Blocked):
                creation.plan({**self.spec, "domain": domain})

    def test_plan_is_deterministic_read_only_and_has_no_guessed_metrics(self):
        with patch("subprocess.run", side_effect=AssertionError("no execution")):
            first = creation.plan(self.spec)
            self.assertEqual(first, creation.plan(self.spec))
        self.assertEqual(first["products"], 1)
        self.assertEqual(first["side_effects"], [])
        self.assertEqual(first["frontend_events"], [])
        self.assertEqual(first["publication"], "BLOCKED")
        self.assertNotIn("confidence", first)
        self.assertNotIn("health", first)

    def test_product_has_no_factory_policy_or_schedules(self):
        emitted = creation.files(self.spec)
        paths = {f["path"] for f in emitted}
        self.assertIn("forgestra-components.json", paths)
        self.assertTrue(all(".github" not in p and "workflows" not in p for p in paths))
        manifest = json.loads(
            next(f["content"] for f in emitted if f["path"] == "forgestra-components.json")
        )
        self.assertEqual(manifest["distribution_rights"], "NOT_CLEARED")
        for name, component in manifest["components"].items():
            self.assertIn(name, creation.COMPONENTS)
            self.assertEqual(component["license"], "MIT")
            self.assertIn("Copyright", component["notice"])
            self.assertEqual(component["upstream_test_suite"], "NOT_RUN")

    def test_output_requires_private_scope_and_never_overwrites(self):
        with self.assertRaises(Blocked):
            write_new_tree(Path("unapproved-product"), creation.files(self.spec))
        with private_output_workspace() as parent:
            output = parent / "product"
            write_new_tree(output, creation.files(self.spec))
            before = (output / "forgestra-components.json").read_bytes()
            with self.assertRaises(Blocked):
                write_new_tree(output, creation.files(self.spec))
            self.assertEqual(before, (output / "forgestra-components.json").read_bytes())

    def test_approval_cannot_be_self_issued_from_spec(self):
        with self.assertRaises(Blocked):
            creation.approve_fixture(self.spec)
        with private_output_workspace():
            with self.assertRaises(Blocked):
                creation.Ledger()

    def test_fixture_cannot_approve_arbitrary_product(self):
        with private_output_workspace(), creation.fixture_authority():
            changed = copy.deepcopy(self.spec)
            changed["domain"]["name"] = "otherapp"
            with self.assertRaises(Blocked):
                creation.approve_fixture(changed)

    def test_forged_approval_never_charges_budget(self):
        with private_output_workspace(), creation.fixture_authority():
            ledger = creation.Ledger()
            try:
                with self.assertRaises(Blocked):
                    ledger.reserve(self.spec, "approved-by-model")
                self.assertEqual(
                    ledger.db.execute("SELECT COUNT(*) FROM requests").fetchone()[0], 0
                )
            finally:
                ledger.close()

    def test_changed_spec_or_policy_invalidates_approval(self):
        with private_output_workspace(), creation.fixture_authority():
            approval = creation.approve_fixture(self.spec)
            changed = copy.deepcopy(self.spec)
            changed["request_id"] = self.second()["request_id"]
            with self.assertRaises(Blocked):
                creation.authorized(changed, approval)
            with patch.object(creation, "policy_hash", return_value="changed"):
                with self.assertRaises(Blocked):
                    creation.authorized(self.spec, approval)

    def test_expired_fixture_approval_is_denied(self):
        with private_output_workspace():
            with creation.fixture_authority():
                approval = creation.approve_fixture(self.spec)
            with self.assertRaises(Blocked):
                creation.authorized(self.spec, approval)

    def test_duplicate_reserved_request_requires_reconciliation(self):
        with private_output_workspace(), creation.fixture_authority():
            ledger = creation.Ledger()
            try:
                approval = creation.approve_fixture(self.spec)
                self.assertEqual(ledger.reserve(self.spec, approval)["status"], "RESERVED")
                self.assertEqual(
                    ledger.reserve(self.spec, approval)["status"], "NEEDS_RECONCILIATION"
                )
                self.assertEqual(
                    ledger.db.execute("SELECT COUNT(*) FROM requests").fetchone()[0], 1
                )
            finally:
                ledger.close()

    def test_daily_budget_survives_closed_connection_and_process_restart(self):
        with private_output_workspace(), creation.fixture_authority():
            ledger = creation.Ledger()
            approval = creation.approve_fixture(self.spec)
            ledger.reserve(self.spec, approval)
            path = ledger.path
            ledger.close()
            # A separate interpreter observes committed state, without fixture authority.
            from bootstrap import environment

            script = (
                "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); "
                "print(c.execute('SELECT COUNT(*) FROM requests').fetchone()[0]); c.close()"
            )
            child = subprocess.run(
                [sys.executable, "-I", "-c", script, str(path)],
                env=environment(),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual((child.returncode, child.stdout.strip()), (0, "1"))
            restarted = creation.Ledger()
            try:
                second = self.second()
                with self.assertRaises(Blocked):
                    restarted.reserve(second, creation.approve_fixture(second))
            finally:
                restarted.close()

    def test_failed_validation_remains_charged_and_cannot_retry(self):
        with private_output_workspace(), creation.fixture_authority():
            ledger = creation.Ledger()
            try:
                approval = creation.approve_fixture(self.spec)
                ledger.reserve(self.spec, approval)
                ledger.finish(self.spec, approval, "FAILED_VALIDATION")
                self.assertEqual(
                    ledger.reserve(self.spec, approval)["previous_status"], "FAILED_VALIDATION"
                )
                with self.assertRaises(Blocked):
                    ledger.finish(self.spec, approval, "READY_FOR_LOCAL_REVIEW", {})
            finally:
                ledger.close()

    def test_cancelled_attempt_stays_terminal_and_charged(self):
        with private_output_workspace(), creation.fixture_authority():
            ledger = creation.Ledger()
            try:
                approval = creation.approve_fixture(self.spec)
                ledger.reserve(self.spec, approval)
                ledger.finish(self.spec, approval, "CANCELLED")
                with self.assertRaises(Blocked):
                    ledger.finish(self.spec, approval, "FAILED_VALIDATION")
            finally:
                ledger.close()

    def test_parallel_connections_cannot_double_reserve(self):
        with private_output_workspace(), creation.fixture_authority():
            first, second = creation.Ledger(), creation.Ledger()
            try:
                first.db.execute("BEGIN IMMEDIATE")
                with self.assertRaises(Blocked):
                    second.reserve(self.spec, creation.approve_fixture(self.spec))
                first.db.execute("ROLLBACK")
                self.assertEqual(
                    second.reserve(self.spec, creation.approve_fixture(self.spec))["status"],
                    "RESERVED",
                )
            finally:
                first.close()
                second.close()

    def test_kill_switch_stops_reservation_and_completion(self):
        with private_output_workspace(), creation.fixture_authority():
            ledger = creation.Ledger()
            try:
                approval = creation.approve_fixture(self.spec)
                with patch.dict(os.environ, {"FORGESTRA_KILL_SWITCH": "1"}):
                    with self.assertRaises(Blocked):
                        ledger.reserve(self.spec, approval)
                    with self.assertRaises(Blocked):
                        ledger.finish(self.spec, approval, "FAILED_VALIDATION")
            finally:
                ledger.close()

    def test_missing_component_source_fails_closed(self):
        from pr07_creation_validation import verify_components

        with private_output_workspace() as parent:
            write_new_tree(parent / "candidate", creation.files(self.spec))
            with self.assertRaises((FileNotFoundError, Blocked)):
                verify_components(parent / "candidate")

    def test_failed_web_gate_cannot_commit_or_report_ready(self):
        from pr07_creation_validation import finalize

        with private_output_workspace() as parent, creation.fixture_authority():
            ledger = creation.Ledger()
            try:
                approval = creation.approve_fixture(self.spec)
                ledger.reserve(self.spec, approval)
                with patch(
                    "pr07_creation_validation.commit_candidate",
                    side_effect=AssertionError("must not commit"),
                ):
                    ledger.claim(self.spec, approval)
                    with self.assertRaises(Blocked):
                        finalize(parent / "candidate", [], {"status": "FAILED"}, ledger, approval)
                self.assertEqual(
                    ledger.reserve(self.spec, approval)["previous_status"], "FAILED_VALIDATION"
                )
            finally:
                ledger.close()

    def test_execution_claim_is_single_use_across_connections(self):
        with private_output_workspace(), creation.fixture_authority():
            first, second = creation.Ledger(), creation.Ledger()
            try:
                approval = creation.approve_fixture(self.spec)
                first.reserve(self.spec, approval)
                first.claim(self.spec, approval)
                with self.assertRaises(Blocked):
                    second.claim(self.spec, approval)
                self.assertEqual(
                    second.reserve(self.spec, approval)["previous_status"], "EXECUTING"
                )
            finally:
                first.close()
                second.close()

    def test_unverified_publication_cannot_dispatch_event(self):
        for receipt in (
            None,
            {"status": "PUBLISHED", "repository": self.spec["repository"], "sha": "a" * 40},
        ):
            result = creation.dispatch_frontend(receipt)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["frontend_events"], [])
        self.assertEqual(creation.runtime_create()["status"], "BLOCKED")

    def test_cli_plans_only_and_runtime_creation_is_blocked(self):
        with private_output_workspace() as parent:
            path = parent / "spec.json"
            path.write_text(json.dumps(self.spec), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["create", "--spec", str(path)]), 0)
            self.assertEqual(json.loads(output.getvalue()), creation.plan(self.spec))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["create"]), 1)
            self.assertEqual(json.loads(output.getvalue())["side_effects"], [])
            self.assertEqual(list(parent.iterdir()), [path])

    def test_missing_creation_evidence_cannot_pass(self):
        from pr07_creation_validation import valid_creation

        for record in (None, {}, {"status": "READY_FOR_LOCAL_REVIEW"}):
            self.assertFalse(valid_creation(record, {}))

    def test_execution_requires_active_charged_reservation(self):
        with private_output_workspace(), creation.fixture_authority():
            ledger = creation.Ledger()
            try:
                approval = creation.approve_fixture(self.spec)
                with self.assertRaises(Blocked):
                    ledger.require_reserved(self.spec, approval)
                ledger.reserve(self.spec, approval)
                ledger.require_reserved(self.spec, approval)
                ledger.finish(self.spec, approval, "CANCELLED")
                with self.assertRaises(Blocked):
                    ledger.require_reserved(self.spec, approval)
            finally:
                ledger.close()

    def test_event_version_mapping_commit_and_deduplication_are_bound(self):
        sha = "a" * 40
        event = {
            "schema_version": 1,
            "event_type": "forgestra.product.published.v1",
            "request_id": self.spec["request_id"],
            "repository": self.spec["repository"],
            "frontend": self.spec["frontend"],
            "tested_sha": sha,
            "idempotency_key": creation.digest(
                creation.canonical([self.spec["request_id"], self.spec["repository"], sha]).encode()
            ),
        }
        first = creation.validate_frontend_event(event, self.spec, sha)
        self.assertEqual(first, creation.validate_frontend_event(event, self.spec, sha))
        self.assertEqual(first["status"], "VALID_DATA_ONLY")
        self.assertEqual(creation.dispatch_frontend(event)["frontend_events"], [])
        for key in event:
            changed = {**event, key: "changed"}
            with self.assertRaises(Blocked):
                creation.validate_frontend_event(changed, self.spec, sha)

    def test_component_source_version_license_and_lock_tampering_are_denied(self):
        from pr07_creation_validation import verify_components

        with private_output_workspace() as parent:
            root = parent / "node_modules/react"
            root.mkdir(parents=True)
            expected = creation.registry()["react"]
            package = {
                "version": expected["version"],
                "license": expected["license"],
                "repository": expected["upstream"],
            }
            payloads = {"package.json": creation.canonical(package), "LICENSE": expected["notice"]}
            for name, content in payloads.items():
                (root / name).write_text(content, encoding="utf-8", newline="\n")
            hashes = {n: creation.digest(c.encode()) for n, c in payloads.items()}
            expected.update(
                source_tree_sha256=creation.digest(creation.canonical(hashes).encode()),
                source_files=2,
                package_sha256=hashes["package.json"],
            )
            lock = {
                "packages": {
                    "node_modules/react": {
                        k: expected[k] for k in ("version", "resolved", "integrity")
                    }
                }
            }
            (parent / "package-lock.json").write_text(creation.canonical(lock), encoding="utf-8")
            with patch.object(creation, "registry", return_value={"react": expected}):
                self.assertEqual(
                    verify_components(parent)["react"]["status"], "SOURCE_VERIFIED_LOCAL"
                )
                for name in payloads:
                    (root / name).write_text("tampered", encoding="utf-8")
                    with self.assertRaises(Blocked):
                        verify_components(parent)
                    (root / name).write_text(payloads[name], encoding="utf-8", newline="\n")
                lock["packages"]["node_modules/react"]["version"] = "0.0.0"
                (parent / "package-lock.json").write_text(
                    creation.canonical(lock), encoding="utf-8"
                )
                with self.assertRaises(Blocked):
                    verify_components(parent)

    def product_record(self):
        from pr07_creation_validation import git_tree

        contents = {f["path"]: f["content"] for f in creation.files(self.spec)}
        hashes = {n: creation.digest(s.encode()) for n, s in contents.items()}
        sha = "a" * 40
        argv = [
            ["init", "--template=", "--initial-branch=fixture-product"],
            ["add", "--", *sorted(hashes)],
            ["commit", "--no-verify", "-m", "Verified authored PR 07 product fixture"],
            ["rev-parse", "HEAD"],
            ["ls-tree", "-r", "--full-tree", "HEAD"],
        ]
        commands: list[dict[str, Any]] = [{"argv": a, "exit_code": 0, "stdout": ""} for a in argv]
        commands[3]["stdout"] = sha + "\n"
        commands[4]["stdout"] = "\n".join(git_tree(contents, sha)) + "\n"
        product: dict[str, Any] = {
            "commit": sha,
            "files": hashes,
            "git_commands": commands,
            "remote": "NOT_CONFIGURED",
            "compiler_declarations": contents["next-env.d.ts"],
        }
        web_files = {
            f["path"]: creation.digest(f["content"].encode())
            for f in creation.web.render(self.spec["domain"])
        }
        return product, {"generated_files": web_files}

    def test_git_evidence_requires_complete_successful_commands_and_exact_tree(self):
        from pr07_creation_validation import valid_product

        product, web = self.product_record()
        self.assertTrue(valid_product(product, web))
        for key in product:
            changed = copy.deepcopy(product)
            del changed[key]
            self.assertFalse(valid_product(changed, web))
        for field, invalid in (
            ("exit_code", True),
            ("exit_code", 1),
            ("argv", []),
            ("stdout", None),
        ):
            changed = copy.deepcopy(product)
            changed["git_commands"][3][field] = invalid
            self.assertFalse(valid_product(changed, web))
        changed = copy.deepcopy(product)
        changed["git_commands"][4]["stdout"] = "100644 blob " + "b" * 40 + "\tREADME.md\n"
        self.assertFalse(valid_product(changed, web))

    def test_compiler_declarations_must_match_actual_tested_snapshot(self):
        from pr07_creation_validation import valid_product, git_tree

        product, web = self.product_record()
        changed = copy.deepcopy(product)
        changed["compiler_declarations"] = "// changed after tests\n"
        changed["files"]["next-env.d.ts"] = creation.digest(
            changed["compiler_declarations"].encode()
        )
        contents = {f["path"]: f["content"] for f in creation.files(self.spec)}
        contents["next-env.d.ts"] = changed["compiler_declarations"]
        changed["git_commands"][4]["stdout"] = (
            "\n".join(git_tree(contents, changed["commit"])) + "\n"
        )
        self.assertFalse(valid_product(changed, web))

    def test_approval_and_journal_are_bound_to_issued_workspace(self):
        with private_output_workspace(), creation.fixture_authority():
            approval = creation.approve_fixture(self.spec)
            ledger = creation.Ledger()
            try:
                with private_output_workspace():
                    with self.assertRaises(Blocked):
                        creation.authorized(self.spec, approval)
                    with self.assertRaises(Blocked):
                        creation.Ledger()
                    with self.assertRaises(Blocked):
                        ledger.reserve(self.spec, approval)
                self.assertEqual(ledger.reserve(self.spec, approval)["status"], "RESERVED")
            finally:
                ledger.close()

    def test_corrupted_ready_receipt_never_replays_as_success(self):
        with private_output_workspace(), creation.fixture_authority():
            approval = creation.approve_fixture(self.spec)
            ledger = creation.Ledger()
            try:
                ledger.reserve(self.spec, approval)
                for state, receipt in (
                    ("READY_FOR_LOCAL_REVIEW", None),
                    ("READY_FOR_LOCAL_REVIEW", "{}"),
                    ("READY_FOR_LOCAL_REVIEW", "invalid-json"),
                    ("READY_FOR_LOCAL_REVIEW", '{"proof":"forged"}'),
                    ("UNRECOGNIZED", None),
                    ("EXECUTING", '{"proof":"forged"}'),
                ):
                    ledger.db.execute("UPDATE requests SET status=?,receipt=?", (state, receipt))
                    with self.assertRaises(Blocked):
                        ledger.reserve(self.spec, approval)
                    self.assertFalse(ledger.db.in_transaction)
                self.assertEqual(
                    ledger.db.execute("SELECT COUNT(*) FROM requests").fetchone()[0], 1
                )
            finally:
                ledger.close()

    def test_failed_child_ci_keeps_bound_diagnostic_logs(self):
        from record_pr07_evidence import diagnostic_report
        from record_pr02_evidence import REQUIRED_CHECKS

        with private_output_workspace() as parent:
            checks = []
            for name in sorted(REQUIRED_CHECKS):
                content = "FAILED fixture check\n"
                (parent / (name + ".log")).write_text(content, encoding="utf-8", newline="\n")
                checks.append(
                    {
                        "name": name,
                        "status": "FAILED",
                        "exit_code": 1,
                        "argv": ["fixture"],
                        "log_sha256": creation.digest(content.encode()),
                    }
                )
            report = {
                "run_id": "fixture-run",
                "status": "FAILED",
                "privileged_automation": "DISABLED",
                "checks": checks,
            }
            self.assertTrue(diagnostic_report(report, parent, "fixture-run"))
            self.assertFalse(diagnostic_report(report, parent, "different-run"))
            (parent / (checks[0]["name"] + ".log")).write_text("altered", encoding="utf-8")
            self.assertFalse(diagnostic_report(report, parent, "fixture-run"))

    def test_malformed_creation_evidence_is_a_denial_not_an_exception(self):
        from pr07_creation_validation import valid_creation, valid_product

        invalid: tuple[object, ...] = (None, [], "invalid", 1)
        for value in invalid:
            self.assertFalse(valid_creation({}, value))
            self.assertFalse(valid_product(value, {}))
