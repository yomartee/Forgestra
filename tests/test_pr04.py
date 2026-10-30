"""PR 04 authored-fixture acceptance. No target code or remote request executes."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

from forgestra.cli import main
from forgestra.repair import (
    Approval,
    FIX,
    SEED,
    FixtureControl,
    LocalPublisher,
    files,
    git,
    local_repair_fixture,
    environment,
)
from forgestra_safety import Blocked


class PR04Tests(unittest.TestCase):
    def test_approved_repair_real_commit_and_exact_proposal(self):
        with local_repair_fixture() as control:
            before = files(control.source)
            plan = control.plan()
            result = control.execute(plan, control.approve(plan))
            self.assertEqual(result["status"], "VALIDATED_LOCAL")
            self.assertEqual(result["tests"]["tests"], 3)
            self.assertEqual(result["proposal"]["head_sha"], result["tested_commit"])
            self.assertNotEqual(result["tested_commit"], result["input_commit"])
            self.assertEqual(
                git(control.parent / result["candidate"], "rev-parse", "HEAD").strip(),
                result["tested_commit"],
            )
            self.assertEqual(files(control.source), before)
            self.assertEqual(result["publication"], "BLOCKED")
            self.assertEqual(result["risk_tier"], 1)

    def test_unapproved_and_model_approval_never_write(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            before = files(control.source)
            for approval in (None, {"approved": True}, Approval("{}", "forged")):
                self.assertEqual(control.execute(plan, approval)["status"], "BLOCKED")
            self.assertEqual(files(control.source), before)
            self.assertFalse(list(control.parent.glob("candidate-*")))
            self.assertEqual(
                control.journal.execute("SELECT attempts FROM budget").fetchone()[0], 0
            )

    def test_approval_binding_cannot_change(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            grant = control.approve(plan)
            for field in (
                "target_id",
                "input_commit",
                "policy_sha256",
                "checks_sha256",
                "scope_id",
            ):
                changed = copy.deepcopy(plan)
                changed[field] = "different"
                self.assertEqual(control.execute(changed, grant)["status"], "BLOCKED")
            changed = copy.deepcopy(plan)
            changed["changes"][0]["content"] += "\n"
            self.assertEqual(control.execute(changed, grant)["status"], "BLOCKED")

    def test_expired_approval_denied(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            grant = control.approve(plan)
            with patch("forgestra.repair.time.time", return_value=10**12):
                self.assertEqual(control.execute(plan, grant)["status"], "BLOCKED")

    def test_duplicate_survives_journal_reopen_without_new_commit(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            grant = control.approve(plan)
            first = control.execute(plan, grant)
            control.journal.close()
            control.journal = sqlite3.connect(control.parent / "runs.sqlite", isolation_level=None)
            second = control.execute(plan, grant)
            self.assertEqual(first, second)
            self.assertEqual(control.journal.execute("SELECT count(*) FROM runs").fetchone()[0], 1)
            self.assertEqual(
                control.journal.execute("SELECT attempts FROM budget").fetchone()[0], 1
            )

    def test_budget_survives_terminal_failure(self):
        with local_repair_fixture() as control:
            bad = control.plan("def add(a,b):\n    return a - b + 0\n")
            self.assertEqual(
                control.execute(bad, control.approve(bad))["status"], "VALIDATION_FAILED"
            )
            plan = control.plan()
            result = control.execute(plan, control.approve(plan))
            self.assertEqual(result["reason_code"], "BUDGET_EXHAUSTED")

    def test_target_lock_is_not_stolen(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            lock = control.parent / "target.lock"
            lock.write_text("unreconciled operation")
            result = control.execute(plan, control.approve(plan))
            self.assertEqual(result["reason_code"], "TARGET_LOCKED")
            self.assertTrue(lock.exists())

    def test_noop_has_no_test_or_publication_claim(self):
        with local_repair_fixture() as control:
            plan = control.plan(SEED["src/arithmetic.py"])
            result = control.execute(plan, control.approve(plan))
            self.assertEqual(result["status"], "NO_OP")
            self.assertEqual(result["tests"], "NOT_RUN")
            self.assertNotIn("proposal", result)
            self.assertFalse(list(control.parent.glob("candidate-*")))

    def test_timeout_is_terminal_without_publication(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            with patch.object(
                control, "check", side_effect=subprocess.TimeoutExpired("authored check", 5)
            ):
                result = control.execute(plan, control.approve(plan))
            self.assertEqual(result["status"], "TIMED_OUT")
            self.assertNotIn("proposal", result)

    def test_crash_requires_reconciliation_not_retry(self):
        class SimulatedCrash(BaseException):
            pass

        with local_repair_fixture() as control:
            plan = control.plan()
            grant = control.approve(plan)
            with patch.object(control, "check", side_effect=SimulatedCrash):
                with self.assertRaises(SimulatedCrash):
                    control.execute(plan, grant)
            self.assertEqual(control.execute(plan, grant)["status"], "NEEDS_RECONCILIATION")
            self.assertEqual(
                control.journal.execute("SELECT attempts FROM budget").fetchone()[0], 1
            )

    def test_hostile_source_is_parsed_never_executed(self):
        for kind in ("top-level", "return-annotation", "type-parameter"):
            with local_repair_fixture() as control:
                marker = control.parent / "forbidden-marker"
                action = f"open({str(marker)!r}, 'w').write('unsafe')"
                payload = (
                    action + "\n"
                    if kind == "top-level"
                    else (
                        f"def add(a,b) -> {action}:\n    return a + b\n"
                        if kind == "return-annotation"
                        else "def add[T](a,b):\n    return a + b\n"
                    )
                )
                plan = control.plan(payload)
                result = control.execute(plan, control.approve(plan))
                self.assertEqual(result["status"], "VALIDATION_FAILED")
                self.assertFalse(marker.exists())
                self.assertNotIn("proposal", result)

    def test_protected_rename_delete_and_paths_block(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            grant = control.approve(plan)
            for name in ("../escape.py", ".github/workflows/ci.yml", "AGENTS.md", "C:/escape.py"):
                changed = copy.deepcopy(plan)
                changed["changes"][0]["path"] = name
                self.assertEqual(control.execute(changed, grant)["status"], "BLOCKED")
            for operation in ("rename", "delete", "add"):
                changed = copy.deepcopy(plan)
                changed["changes"][0]["operation"] = operation
                self.assertEqual(control.execute(changed, grant)["status"], "BLOCKED")

    def test_changed_input_invalidates_approval(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            grant = control.approve(plan)
            (control.source / "README.md").write_text("changed by user")
            self.assertEqual(control.execute(plan, grant)["status"], "BLOCKED")
            self.assertEqual((control.source / "README.md").read_text(), "changed by user")

    def test_publisher_rejects_unverified_receipts_and_later_changes(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            result = control.execute(plan, control.approve(plan))
            candidate = control.parent / result["candidate"]
            forged = copy.deepcopy(result)
            forged["tested_commit"] = "0" * 40
            with self.assertRaises(Blocked):
                LocalPublisher.prepare(candidate, forged)
            (candidate / "src/arithmetic.py").write_text("changed after tests")
            with self.assertRaises(Blocked):
                LocalPublisher.prepare(candidate, result)
            self.assertEqual(
                control.execute(plan, control.approve(plan))["status"], "NEEDS_RECONCILIATION"
            )

    def test_git_configuration_is_not_target_authority(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            grant = control.approve(plan)
            with (control.source / ".git/config").open("a") as stream:
                stream.write("\n[alias]\nunsafe = !echo forbidden\n")
            self.assertEqual(control.execute(plan, grant)["status"], "BLOCKED")

    def test_git_wrapper_cannot_push_or_accept_customer_root(self):
        with local_repair_fixture() as control:
            with self.assertRaises(Blocked):
                git(control.source, "push", "origin", "HEAD")
            with self.assertRaises(Blocked):
                git(Path.cwd(), "rev-parse", "HEAD")

    def test_credentials_filtered_and_runtime_entry_blocked(self):
        with patch.dict(
            os.environ,
            {
                "GITHUB_TOKEN": "canary-provider-do-not-use",
                "ANTHROPIC_API_KEY": "canary-admin-do-not-use",
            },
        ):
            self.assertNotIn("GITHUB_TOKEN", environment(Path(".")))
            self.assertEqual(environment(Path("."))["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertNotIn("ANTHROPIC_API_KEY", environment(Path(".")))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["repair"]), 1)
            self.assertEqual(
                json.loads(output.getvalue())["reason_code"], "RUNTIME_REPAIR_DISABLED"
            )
            with self.assertRaises(Blocked):
                LocalPublisher.publish({"approved": True})

    def test_kill_switch_and_expired_scope_block(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            grant = control.approve(plan)
            with patch.dict(os.environ, {"FORGESTRA_KILL_SWITCH": "1"}):
                self.assertEqual(control.execute(plan, grant)["status"], "BLOCKED")
        self.assertEqual(control.execute(plan, grant)["status"], "BLOCKED")

    def test_control_cannot_be_constructed_for_a_customer_root(self):
        with self.assertRaises(Blocked):
            FixtureControl(Path.cwd(), object())

    def test_zero_checks_cannot_validate_repair(self):
        with local_repair_fixture() as control:
            response = subprocess.CompletedProcess([], 0, '{"status":"PASSED","tests":0}', "")
            with patch("forgestra.repair.subprocess.run", return_value=response):
                checked = control.check(control.parent / "candidate-synthetic")
            self.assertFalse(checked["passed"])

    def test_candidate_changed_during_check_cannot_be_committed(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            check = control.check

            def changed(candidate):
                result = check(candidate)
                (candidate / "README.md").write_text("unapproved change")
                return result

            with patch.object(control, "check", changed):
                result = control.execute(plan, control.approve(plan))
            self.assertEqual(result["status"], "NEEDS_RECONCILIATION")
            self.assertNotIn("proposal", result)

    def test_git_attribute_controls_cannot_run_filters(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            grant = control.approve(plan)
            attributes = control.source / ".git/info/attributes"
            attributes.parent.mkdir(exist_ok=True)
            attributes.write_text("* filter=unsafe")
            self.assertEqual(control.execute(plan, grant)["status"], "BLOCKED")

    def test_inconsistent_journal_never_replays_success(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            grant = control.approve(plan)
            result = control.execute(plan, grant)
            result["idempotency_key"] = "different"
            control.journal.execute("UPDATE runs SET result=?", (json.dumps(result),))
            self.assertEqual(control.execute(plan, grant)["status"], "NEEDS_RECONCILIATION")

    def test_kill_switch_after_checks_cancels_before_commit(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            grant = control.approve(plan)
            check = control.check

            def cancelled(candidate):
                result = check(candidate)
                os.environ["FORGESTRA_KILL_SWITCH"] = "1"
                return result

            with patch.dict(os.environ, {"FORGESTRA_KILL_SWITCH": "0"}):
                with patch.object(control, "check", cancelled):
                    result = control.execute(plan, grant)
            self.assertEqual(result["status"], "CANCELLED")
            self.assertNotIn("proposal", result)

    def test_unavailable_journal_requires_reconciliation(self):
        with local_repair_fixture() as control:
            plan = control.plan()
            grant = control.approve(plan)
            control.journal.close()
            self.assertEqual(control.execute(plan, grant)["status"], "NEEDS_RECONCILIATION")

    def test_plan_byte_budget_rejects_invalid_input_before_staging(self):
        with local_repair_fixture() as control:
            for value in ("x" * 32001, "é" * 16001, "\ud800", None):
                with self.assertRaises(Blocked):
                    control.plan(value)
            self.assertFalse(list(control.parent.glob("candidate-*")))
            self.assertEqual(
                control.journal.execute("SELECT attempts FROM budget").fetchone()[0], 0
            )

    def test_failed_checker_preserves_counts(self):
        with local_repair_fixture() as control:
            plan = control.plan("import os\n")
            result = control.execute(plan, control.approve(plan))
            self.assertEqual(result["tests"]["collected"], 3)
            self.assertEqual(result["tests"]["failures"], 1)
            self.assertEqual(result["check_exit_code"], 1)

    def test_recorder_rejects_false_success_evidence(self):
        from record_pr04_evidence import valid_repair

        result = acceptance()
        self.assertTrue(valid_repair(result))
        for field, top_value in (
            ("original_preserved", False),
            ("duplicate_same_run", False),
            ("remote_pr", "created"),
            ("privileged_automation", "ENABLED"),
        ):
            changed = copy.deepcopy(result)
            changed[field] = top_value
            self.assertFalse(valid_repair(changed))
        for section, field, value in (
            ("approved_repair", "tests", {"status": "PASSED", "tests": 0}),
            ("approved_repair", "tested_commit", "0" * 40),
            ("approved_repair", "auto_merge", True),
            ("approved_repair", "candidate_files", {}),
            ("approved_repair", "policy_sha256", "0" * 64),
            ("failed_checks", "status", "VALIDATED_LOCAL"),
            ("unapproved", "status", "VALIDATED_LOCAL"),
            ("budget", "reason_code", "UNKNOWN"),
        ):
            changed = copy.deepcopy(result)
            changed[section][field] = value
            self.assertFalse(valid_repair(changed))
        for malformed in (None, {}, {"status": "PASSED_LOCAL"}):
            self.assertFalse(valid_repair(malformed))


def acceptance():
    """Durable evidence for the real local happy path and negative boundaries."""
    with local_repair_fixture() as control:
        plan = control.plan()
        before = files(control.source)
        denied = control.execute(plan)
        grant = control.approve(plan)
        repaired = control.execute(plan, grant)
        duplicate = control.execute(plan, grant)
        another = control.plan(FIX + "\n")
        budget = control.execute(another, control.approve(another))
        preserved = files(control.source) == before
    with local_repair_fixture() as control:
        plan = control.plan("import os\n")
        failed = control.execute(plan, control.approve(plan))
    passed = (
        denied["status"] == "BLOCKED"
        and repaired["status"] == "VALIDATED_LOCAL"
        and duplicate == repaired
        and budget.get("reason_code") == "BUDGET_EXHAUSTED"
        and failed["status"] == "VALIDATION_FAILED"
        and preserved
        and repaired["proposal"]["head_sha"] == repaired["tested_commit"]
    )
    return {
        "status": "PASSED_LOCAL" if passed else "FAILED",
        "mode": "AUTHORED_FIXTURE_ONLY",
        "approved_repair": repaired,
        "unapproved": denied,
        "duplicate_same_run": duplicate == repaired,
        "budget": budget,
        "failed_checks": failed,
        "original_preserved": preserved,
        "remote_pr": "NOT_RUN",
        "privileged_automation": "DISABLED",
    }
