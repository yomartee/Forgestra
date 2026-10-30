"""Maintenance regressions; private authored fixtures only, no provider or target code."""

import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import uuid

from forgestra import maintenance as m, repair
from forgestra.cli import main
from forgestra_safety import Blocked, private_output_workspace, strict_json_loads
from pr09_maintenance_validation import scenario, valid_maintenance


def declared_event():
    log = (
        json.dumps(
            {
                "status": "FAILED",
                "collected": 3,
                "tests": 3,
                "failures": 2,
                "errors": 0,
                "skipped": 0,
                "expected_failures": 0,
                "unexpected_successes": 0,
            },
            sort_keys=True,
        )
        + "\n"
    )
    return {
        "schema_version": 1,
        "kind": "repair",
        "repository": m.REPOSITORY,
        "actor": m.ACTOR,
        "workflow": "authored-addition-check",
        "run_id": str(uuid.uuid4()),
        "head_sha": "a" * 40,
        "check_sha256": m.CHECK_SHA,
        "conclusion": "failure",
        "log": log,
        "log_sha256": repair.digest(log.encode()),
        "changes": copy.deepcopy(m.DIFF),
    }


class MaintenanceReviewTests(unittest.TestCase):
    def test_declaration_is_read_only_and_unverified(self):
        value = m.review(declared_event())
        self.assertEqual(value["status"], "REVIEW_REQUIRED")
        self.assertEqual(value["origin_verification"], "UNVERIFIED_DECLARATION")
        self.assertEqual(value["side_effects"], [])
        self.assertEqual(value["execution"], "DISABLED")

    def test_missing_log_origin_sha_or_check_fails_closed(self):
        for field in ("actor", "repository", "head_sha", "check_sha256", "run_id"):
            event = declared_event()
            del event[field]
            with self.assertRaises(Blocked):
                m.review(event)

    def test_other_actor_repository_workflow_or_check_is_denied(self):
        for field in ("actor", "repository", "workflow", "check_sha256", "head_sha"):
            event = declared_event()
            event[field] = "untrusted"
            with self.assertRaises(Blocked):
                m.review(event)

    def test_log_tamper_and_sensitive_output_are_denied(self):
        event = declared_event()
        event["log"] += "extra"
        with self.assertRaises(Blocked):
            m.review(event)
        event = declared_event()
        event["log"] = "Authorization: Bearer synthetic-maintenance-secret"
        event["log_sha256"] = repair.digest(event["log"].encode())
        with self.assertRaises((Blocked, ValueError)):
            m.review(event)

    def test_zero_skipped_or_boolean_test_counts_never_pass(self):
        for field, value in (("tests", 0), ("skipped", 1), ("failures", True)):
            event = declared_event()
            result = json.loads(event["log"])
            result[field] = value
            event["log"] = json.dumps(result)
            event["log_sha256"] = repair.digest(event["log"].encode())
            with self.assertRaises(Blocked):
                m.review(event)

    def test_complete_diff_auth_production_policy_and_rename_require_review(self):
        for name in (
            "src/auth.py",
            "deploy/production.yml",
            ".github/CODEOWNERS",
            "config/system_architect.txt",
            "requirements.txt",
        ):
            event = declared_event()
            event["changes"].append({"operation": "modify", "path": name})
            self.assertEqual(m.review(event)["risk_tier"], 2)
        event["changes"] = [
            {"operation": "rename", "source": ".github/CODEOWNERS", "path": "docs/moved.md"}
        ]
        self.assertEqual(m.review(event)["risk_tier"], 2)

    def test_new_delivery_uuid_does_not_reset_fingerprint(self):
        event = declared_event()
        key = m.fingerprint(event)
        event["run_id"] = str(uuid.uuid4())
        self.assertEqual(m.fingerprint(event), key)

    def test_runtime_cli_stays_blocked(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["maintain"]), 1)
        self.assertEqual(json.loads(output.getvalue()), m.runtime_maintenance())

    def test_cli_evidence_can_only_request_review(self):
        with private_output_workspace() as parent:
            path = parent / "event.json"
            path.write_text(json.dumps(declared_event()), encoding="utf-8")
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["maintain", "--evidence", str(path)]), 1)
            self.assertEqual(json.loads(output.getvalue())["execution"], "DISABLED")

    def test_kill_switch_blocks_even_read_only_maintenance(self):
        with patch.dict(os.environ, {"FORGESTRA_KILL_SWITCH": "1"}):
            with self.assertRaises(Blocked):
                m.review(declared_event())
            with self.assertRaises(Blocked):
                m.runtime_maintenance()

    def test_absent_evidence_cannot_pass_acceptance(self):
        for document in (None, {}, {"status": "PASSED_LOCAL", "cases": {}}):
            self.assertFalse(valid_maintenance(document))

    def test_legacy_paths_have_no_health_scores_or_marker_refactors(self):
        for name in ("self_heal.py", "autonomous_janitor.py"):
            source = (Path(__file__).resolve().parents[1] / "scripts" / name).read_text()
            self.assertIn('require("', source)
            for text in ("REFACTOR_APPLIED", "calculate_quality_score", "os.system", "Anthropic"):
                self.assertNotIn(text, source)


class MaintenanceFixtureTests(unittest.TestCase):
    def test_real_failure_is_repaired_and_new_commit_checked_once(self):
        case = scenario()
        result = case["result"]
        self.assertEqual(result["status"], "READY_FOR_LOCAL_REVIEW")
        self.assertTrue(m.counts(json.loads(case["event"]["log"]), True))
        self.assertNotEqual(case["event"]["head_sha"], result["post_commit_check"]["head_sha"])
        self.assertNotEqual(case["event"]["run_id"], result["post_commit_check"]["run_id"])
        self.assertEqual(case["replay"]["receipt"], result)
        self.assertEqual(case["repair_attempts"], 1)
        self.assertTrue(case["original_preserved"])

    def test_refactor_changes_actual_code_and_preserves_three_cases(self):
        case = scenario("refactor")
        self.assertEqual(case["result"]["status"], "READY_FOR_LOCAL_REVIEW")
        self.assertTrue(m.counts(json.loads(case["event"]["log"])))
        self.assertTrue(m.counts(case["result"]["post_commit_check"]["result"]))
        self.assertEqual(case["result"]["repair"]["diff"], m.DIFF)
        self.assertNotEqual(repair.FIX, repair.REFACTOR)

    def test_no_fix_is_terminal_escalation_without_retry(self):
        case = scenario(content=repair.SEED["src/arithmetic.py"])
        self.assertEqual(case["result"]["reason_code"], "NO_FIX")
        self.assertEqual(case["result"]["status"], "ESCALATED")
        self.assertEqual(case["replay"]["receipt"], case["result"])
        self.assertEqual(case["repair_attempts"], 1)

    def test_bad_fix_is_terminal_escalation_without_proposal(self):
        case = scenario(content="def add(a, b):\n    return a * b\n")
        self.assertEqual(case["result"]["reason_code"], "FAILED_VALIDATION")
        self.assertNotIn("proposal", case["result"]["repair"])
        self.assertEqual(case["replay"]["receipt"], case["result"])

    def test_json_observation_and_unapproved_plan_cannot_execute(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                observation = e.observe()
                for supplied in (declared_event(), observation):
                    with self.assertRaises(Blocked):
                        e.run(supplied, c.plan())
                self.assertEqual(e.db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0], 0)
            finally:
                e.close()

    def test_tampered_observation_and_changed_plan_are_denied(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                observation = e.observe()
                plan = c.plan()
                grant = e.approve(observation, plan)
                with self.assertRaises(Blocked):
                    e.run(observation, c.plan(repair.FIX + "\n"), grant)
                body = strict_json_loads(observation.payload)
                body["event"]["actor"] = "untrusted"
                with self.assertRaises(Blocked):
                    e.observed(m.Observation(repair.canonical(body), observation.signature))
            finally:
                e.close()

    def test_unknown_or_active_state_never_restarts_work(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                o = e.observe()
                event = strict_json_loads(o.payload)["event"]
                plan = c.plan()
                grant = e.approve(o, plan)
                for state in ("EXECUTING", "UNKNOWN"):
                    e.db.execute("DELETE FROM attempts")
                    e.db.execute(
                        "INSERT INTO attempts VALUES(?,?,NULL,NULL)", (m.fingerprint(event), state)
                    )
                    with self.assertRaises(Blocked):
                        e.run(o, plan, grant)
                self.assertEqual(c.journal.execute("SELECT attempts FROM budget").fetchone()[0], 0)
            finally:
                e.close()

    def test_diagnostic_command_never_imports_hostile_target(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                root = c.parent / "candidate-hostile"
                from forgestra_safety import write_new_tree

                write_new_tree(root, [{"path": n, "content": v} for n, v in repair.SEED.items()])
                marker = c.parent / "executed.txt"
                (root / "src/arithmetic.py").write_text(
                    "from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n",
                    encoding="utf-8",
                )
                with self.assertRaises(Blocked):
                    e.check(root)
                self.assertFalse(marker.exists())
            finally:
                e.close()

    def test_expired_workspace_cannot_reuse_maintenance_authority(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                o = e.observe()
                with private_output_workspace():
                    with self.assertRaises(Blocked):
                        e.approve(o, c.plan())
            finally:
                e.close()

    def test_missing_log_has_explicit_terminal_escalation(self):
        for value in (None, ""):
            event = declared_event()
            event["log"] = value
            result = m.review(event)
            self.assertEqual(result["status"], "ESCALATED")
            self.assertEqual(result["reason_code"], "MISSING_FAILURE_LOG")
            self.assertEqual(result["side_effects"], [])

    def test_exhausted_executor_budget_escalates_once(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                o = e.observe()
                plan = c.plan()
                grant = e.approve(o, plan)
                c.journal.execute("UPDATE budget SET attempts=1")
                result = e.run(o, plan, grant)
                self.assertEqual(result["status"], "ESCALATED")
                self.assertEqual(result["reason_code"], "ATTEMPT_EXHAUSTED")
                self.assertEqual(e.run(o, plan, grant)["receipt"], result)
            finally:
                e.close()

    def test_other_active_fingerprint_serializes_target(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                o = e.observe()
                plan = c.plan()
                grant = e.approve(o, plan)
                e.db.execute("INSERT INTO attempts VALUES(?,'EXECUTING',NULL,NULL)", ("b" * 64,))
                with self.assertRaises(Blocked):
                    e.run(o, plan, grant)
                self.assertEqual(c.journal.execute("SELECT attempts FROM budget").fetchone()[0], 0)
            finally:
                e.close()

    def test_corrupt_success_cache_never_reexecutes(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                o = e.observe()
                plan = c.plan()
                grant = e.approve(o, plan)
                self.assertEqual(e.run(o, plan, grant)["status"], "READY_FOR_LOCAL_REVIEW")
                e.db.execute("UPDATE attempts SET receipt='{}',proof='forged'")
                with self.assertRaises(Blocked):
                    e.run(o, plan, grant)
                self.assertEqual(c.journal.execute("SELECT attempts FROM budget").fetchone()[0], 1)
            finally:
                e.close()

    def test_changed_policy_and_source_revoke_maintenance_grant(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                o = e.observe()
                plan = c.plan()
                grant = e.approve(o, plan)
                with patch("forgestra.maintenance.policy_hash", return_value="changed"):
                    with self.assertRaises(Blocked):
                        e.run(o, plan, grant)
                (c.source / "README.md").write_text("changed", encoding="utf-8")
                with self.assertRaises(Blocked):
                    e.run(o, plan, grant)
                self.assertEqual(e.db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0], 0)
            finally:
                e.close()

    def test_zero_checker_contract_fails_before_any_success(self):
        import subprocess

        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                e.observe()
                fake = subprocess.CompletedProcess([], 0, '{"status":"PASSED","tests":0}', "")
                with patch("forgestra.maintenance.subprocess.run", return_value=fake):
                    with self.assertRaises(Blocked):
                        e.check(c.parent / "candidate-observation")
            finally:
                e.close()

    def test_observation_rejects_seed_bytes_not_at_the_source_commit(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                c.seed["src/arithmetic.py"] += "\n"
                with self.assertRaises(Blocked):
                    e.observe()
            finally:
                e.close()

    def test_observation_rejects_changed_diagnostic_snapshot(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                check = e.check

                def changed(root):
                    (root / "README.md").write_text("changed diagnostic", encoding="utf-8")
                    return check(root)

                with patch.object(e, "check", side_effect=changed):
                    with self.assertRaises(Blocked):
                        e.observe()
            finally:
                e.close()

    def test_ready_replay_rechecks_candidate_bytes(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                o = e.observe()
                plan = c.plan()
                grant = e.approve(o, plan)
                result = e.run(o, plan, grant)
                (c.parent / result["repair"]["candidate"] / "src/arithmetic.py").write_text(
                    "unreviewed", encoding="utf-8"
                )
                with self.assertRaises(Blocked):
                    e.run(o, plan, grant)
                self.assertEqual(c.journal.execute("SELECT attempts FROM budget").fetchone()[0], 1)
            finally:
                e.close()

    def test_fresh_maintenance_success_requires_executor_signature(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                o = e.observe()
                plan = c.plan()
                grant = e.approve(o, plan)
                forged = c.execute(plan, grant.repair_approval)
                forged["verification_signature"] = "forged"
                with patch.object(c, "execute", return_value=forged):
                    result = e.run(o, plan, grant)
                self.assertEqual(result["status"], "ESCALATED")
                self.assertNotIn("post_commit_check", result)
            finally:
                e.close()

    def test_fresh_maintenance_success_requires_exact_verified_proposal(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                o = e.observe()
                plan = c.plan()
                grant = e.approve(o, plan)
                forged = c.execute(plan, grant.repair_approval)
                forged["proposal"]["head_sha"] = "0" * 40
                with patch.object(c, "execute", return_value=forged):
                    result = e.run(o, plan, grant)
                self.assertEqual(result["status"], "ESCALATED")
                self.assertNotIn("post_commit_check", result)
            finally:
                e.close()

    def test_escalation_evidence_requires_consistent_child_denials_and_counts(self):
        from pr09_maintenance_validation import acceptance

        original = acceptance()
        self.assertTrue(valid_maintenance(original))
        for name in ("no_fix", "failed_fix"):
            for field, value in (
                ("publication", "PUBLISHED"),
                ("remote_pr", "CREATED"),
                ("auto_merge", True),
                ("input_commit", "0" * 40),
                ("verification_signature", "forged"),
                ("checks_sha256", "forged"),
                ("plan_sha256", "forged"),
                ("candidate", "../outside"),
            ):
                document = copy.deepcopy(original)
                # Keep replay consistent to test the inner contract independently.
                document["cases"][name]["result"]["repair"][field] = value
                document["cases"][name]["replay"]["receipt"] = copy.deepcopy(
                    document["cases"][name]["result"]
                )
                self.assertFalse(valid_maintenance(document), (name, field))
        document = copy.deepcopy(original)
        document["cases"]["failed_fix"]["result"]["repair"]["tests"]["skipped"] = 1
        document["cases"]["failed_fix"]["replay"]["receipt"] = copy.deepcopy(
            document["cases"]["failed_fix"]["result"]
        )
        self.assertFalse(valid_maintenance(document))
        document = copy.deepcopy(original)
        document["cases"]["no_fix"]["result"]["repair"]["tests"] = {"status": "PASSED"}
        document["cases"]["no_fix"]["replay"]["receipt"] = copy.deepcopy(
            document["cases"]["no_fix"]["result"]
        )
        self.assertFalse(valid_maintenance(document))

    def test_checker_rejects_snapshot_changes_during_child(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                e.observe()
                root = c.parent / "candidate-observation"
                run = m.subprocess.run

                def changed(*args, **kwargs):
                    result = run(*args, **kwargs)
                    (root / "README.md").write_text("changed during child", encoding="utf-8")
                    return result

                with patch("forgestra.maintenance.subprocess.run", side_effect=changed):
                    with self.assertRaises(Blocked):
                        e.check(root)
            finally:
                e.close()

    def test_policy_revoked_after_post_commit_check_cannot_finish_ready(self):
        with repair.local_repair_fixture() as c:
            e = m.FixtureMaintenance(c)
            try:
                o = e.observe()
                plan = c.plan()
                grant = e.approve(o, plan)
                check, policy = e.check, m.policy_hash
                revoked = [False]

                def checked(root):
                    result = check(root)
                    revoked[0] = True
                    return result

                with patch.object(e, "check", side_effect=checked):
                    with patch(
                        "forgestra.maintenance.policy_hash",
                        side_effect=lambda: ("changed" if revoked[0] else policy()),
                    ):
                        result = e.run(o, plan, grant)
                self.assertEqual(result["status"], "ESCALATED")
                self.assertNotIn("post_commit_check", result)
                self.assertNotIn("proposal", result["repair"])
            finally:
                e.close()
