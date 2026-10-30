"""Three-way synchronization and isolated journal regressions; no target code runs."""

from contextlib import ExitStack, redirect_stdout
import copy
import io
import json
import os
import unittest
from unittest.mock import patch

from forgestra import synchronization as sync, sync_control as control
from forgestra.cli import main
from forgestra_safety import Blocked, private_output_workspace
from pr08_sync_validation import BASE, HEAD, CUSTOM, CONFIG, RUN_ID, write_fixture, valid_sync


class SynchronizationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.parent = self.stack.enter_context(private_output_workspace())
        self.addCleanup(self.stack.close)
        self.source, self.target = self.parent / "sync-source", self.parent / "sync-target"
        write_fixture(self.source, BASE)
        write_fixture(
            self.target,
            {**CUSTOM, **{n.replace("template/", "app/", 1): d for n, d in BASE.items()}},
        )
        self.config = copy.deepcopy(CONFIG)
        self.baseline = sync.baseline(self.source, self.config)

    def preview(self):
        return sync.plan(self.source, self.target, self.config, self.baseline)

    def head(self):
        for name in BASE:
            (self.source / name).unlink()
        for name, data in HEAD.items():
            (self.source / name).write_bytes(data)

    def journal(self):
        self.stack.enter_context(control.fixture_control())
        result = control.Journal()
        self.addCleanup(result.close)
        return result

    def test_identical_owned_files_are_noops(self):
        proposal = self.preview()
        self.assertEqual(proposal["changes"], [])
        self.assertEqual(proposal["conflicts"], [])
        self.assertEqual(len(proposal["unchanged"]), 2)

    def test_upstream_add_update_delete_are_distinct_from_target_only(self):
        self.head()
        proposal = self.preview()
        self.assertEqual(
            sorted(c["operation"] for c in proposal["changes"]), ["add", "delete", "update"]
        )
        self.assertIn(
            {"path": "app/custom.txt", "reason": "UNOWNED_TARGET_FILE"}, proposal["preserved"]
        )

    def test_downstream_edits_and_deletions_are_preserved(self):
        (self.target / "app/guide.txt").write_bytes(b"Customer edit\n")
        (self.target / "app/removed.txt").unlink()
        proposal = self.preview()
        self.assertEqual(proposal["changes"], [])
        self.assertEqual(proposal["conflicts"], [])
        self.assertEqual(
            sum(p["reason"] == "DOWNSTREAM_ONLY_CHANGE" for p in proposal["preserved"]), 2
        )

    def test_divergent_edits_conflict(self):
        self.head()
        (self.target / "app/guide.txt").write_bytes(b"Different downstream change\n")
        proposal = self.preview()
        self.assertEqual(proposal["status"], "CONFLICT")
        self.assertIn(
            {"path": "app/guide.txt", "reason": "DIVERGENT_THREE_WAY_CHANGE"}, proposal["conflicts"]
        )

    def test_delete_edit_and_edit_delete_conflict(self):
        self.head()
        (self.target / "app/removed.txt").write_bytes(b"Customer retained edit\n")
        (self.target / "app/guide.txt").unlink()
        self.assertEqual(len(self.preview()["conflicts"]), 2)

    def test_equal_concurrent_edits_need_no_change(self):
        self.head()
        (self.target / "app/guide.txt").write_bytes(HEAD["template/guide.txt"])
        self.assertIn("app/guide.txt", self.preview()["unchanged"])

    def test_unowned_same_name_is_not_implicitly_adopted(self):
        self.head()
        (self.target / "app/new.txt").write_bytes(HEAD["template/new.txt"])
        self.assertIn(
            {"path": "app/new.txt", "reason": "UNOWNED_DESTINATION"}, self.preview()["conflicts"]
        )

    def test_file_directory_and_case_collisions_are_blocking(self):
        self.head()
        (self.target / "app/new.txt").mkdir()
        self.assertTrue(self.preview()["conflicts"])
        (self.target / "app/new.txt").rmdir()
        (self.target / "app").rename(self.target / "APP-temp")
        (self.target / "APP-temp").rename(self.target / "APP")
        self.assertTrue(self.preview()["conflicts"])

    def test_missing_or_tampered_baseline_is_not_two_way_fallback(self):
        invalid: tuple[object, ...] = (None, {}, [], "invalid")
        for value in invalid:
            with self.assertRaises(Blocked):
                sync.plan(self.source, self.target, self.config, value)
        changed = copy.deepcopy(self.baseline)
        changed["files"]["template/guide.txt"] = "0" * 64
        with self.assertRaises(Blocked):
            sync.plan(self.source, self.target, self.config, changed)

    def test_baseline_cannot_claim_unmapped_ownership_or_fake_commit(self):
        for field, value in (
            ("ownership", {"app/custom.txt": "template/guide.txt"}),
            ("source_commit", "a" * 40),
        ):
            changed = copy.deepcopy(self.baseline)
            changed[field] = value
            changed["baseline_sha256"] = sync.digest(
                sync.encoded({k: v for k, v in changed.items() if k != "baseline_sha256"})
            )
            with self.assertRaises(Blocked):
                sync.plan(self.source, self.target, self.config, changed)

    def test_mapping_rejects_traversal_protected_overlap_and_authority(self):
        for path in (
            "../escape",
            "C:/escape",
            ".github",
            "config",
            "--option",
            "template/../outside",
        ):
            changed = copy.deepcopy(self.config)
            changed["paths"][0]["target"] = path
            with self.assertRaises(Blocked):
                sync.mapping(changed)
        changed = copy.deepcopy(self.config)
        changed["paths"].append({"source": "other", "target": "app/nested"})
        with self.assertRaises(Blocked):
            sync.mapping(changed)
        with self.assertRaises(Blocked):
            sync.mapping({**self.config, "approved": True})

    def test_roots_must_be_distinct_and_disjoint(self):
        for target in (self.source, self.source / "template", self.parent):
            with self.assertRaises(Blocked):
                sync.plan(self.source, target, self.config, self.baseline)

    def test_protected_mapped_file_is_not_written(self):
        (self.source / "template/CLAUDE.md").write_text("model approval", encoding="utf-8")
        with self.assertRaises(Blocked):
            self.preview()

    def test_inspection_is_deterministic_and_has_no_subprocess_or_writes(self):
        before = sync.read_tree(self.target)
        with patch("subprocess.run", side_effect=AssertionError("no target execution")):
            self.assertEqual(self.preview(), self.preview())
        self.assertEqual(before, sync.read_tree(self.target))

    def test_opt_in_selection_is_read_only_and_deduplicated(self):
        off = copy.deepcopy(self.config)
        off["opted_in"] = False
        result = sync.enumerate_targets({"schema_version": 1, "targets": [off]})
        self.assertEqual(result["targets"], [])
        self.assertEqual(result["execution"], "DISABLED")
        with self.assertRaises(Blocked):
            sync.enumerate_targets({"schema_version": 1, "targets": [self.config, self.config]})

    def test_configuration_or_json_cannot_approve_runtime_sync(self):
        self.assertEqual(sync.runtime_sync()["status"], "BLOCKED")
        with self.assertRaises(Blocked):
            control.approval(self.preview())

    def test_unapproved_conflicting_or_opted_out_plans_cannot_reserve(self):
        journal = self.journal()
        proposal = self.preview()
        with self.assertRaises(Blocked):
            journal.reserve(RUN_ID, proposal, "model approval")
        changed = {**proposal, "status": "CONFLICT"}
        with self.assertRaises(Blocked):
            control.approval(changed)
        changed = copy.deepcopy(proposal)
        changed["mapping"]["opted_in"] = False
        with self.assertRaises(Blocked):
            control.approval(changed)
        self.assertEqual(journal.db.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 0)

    def test_changed_input_or_policy_invalidates_approval(self):
        journal = self.journal()
        proposal = self.preview()
        proof = control.approval(proposal)
        self.head()
        with self.assertRaises(Blocked):
            journal.reserve(RUN_ID, self.preview(), proof)
        with patch.object(control, "policy_hash", return_value="changed"):
            with self.assertRaises(Blocked):
                control.authorized(proposal, proof)

    def test_active_target_lock_serializes_distinct_plans(self):
        journal = self.journal()
        first = self.preview()
        proof = control.approval(first)
        journal.reserve(RUN_ID, first, proof)
        self.head()
        second = self.preview()
        with self.assertRaises(Blocked):
            journal.reserve(
                "08100000-0000-4000-8000-000000000009", second, control.approval(second)
            )

    def test_run_id_and_input_deduplication_survive_reopen(self):
        journal = self.journal()
        proposal = self.preview()
        proof = control.approval(proposal)
        journal.reserve(RUN_ID, proposal, proof)
        journal.close()
        other = control.Journal()
        try:
            duplicate = other.reserve("08100000-0000-4000-8000-000000000009", proposal, proof)
            self.assertEqual(duplicate["status"], "NEEDS_RECONCILIATION")
            self.assertEqual(other.db.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 1)
        finally:
            other.close()

    def test_single_execution_claim_across_connections(self):
        journal = self.journal()
        proposal = self.preview()
        proof = control.approval(proposal)
        journal.reserve(RUN_ID, proposal, proof)
        journal.claim(RUN_ID, proposal, proof)
        other = control.Journal()
        try:
            with self.assertRaises(Blocked):
                other.claim(RUN_ID, proposal, proof)
        finally:
            other.close()

    def test_failed_cancelled_and_unknown_states_never_report_success(self):
        journal = self.journal()
        proposal = self.preview()
        proof = control.approval(proposal)
        journal.reserve(RUN_ID, proposal, proof)
        journal.claim(RUN_ID, proposal, proof)
        journal.finish(RUN_ID, proposal, proof, "CANCELLED")
        result = journal.reserve(RUN_ID, proposal, proof)
        self.assertEqual(result["previous_status"], "CANCELLED")
        self.assertEqual(result["status"], "NEEDS_RECONCILIATION")
        journal.db.execute("UPDATE runs SET status='UNKNOWN'")
        with self.assertRaises(Blocked):
            journal.reserve(RUN_ID, proposal, proof)

    def test_unsigned_ready_and_corrupt_cached_receipt_are_denied(self):
        journal = self.journal()
        proposal = self.preview()
        proof = control.approval(proposal)
        journal.reserve(RUN_ID, proposal, proof)
        journal.claim(RUN_ID, proposal, proof)
        receipt = {
            "status": "READY_FOR_LOCAL_REVIEW",
            "plan_sha256": control.fingerprint(proposal),
            "publication": "BLOCKED",
        }
        with self.assertRaises(Blocked):
            journal.finish(RUN_ID, proposal, proof, "READY_FOR_LOCAL_REVIEW", receipt)
        journal.db.execute(
            "UPDATE runs SET status='READY_FOR_LOCAL_REVIEW',receipt='{}',proof='forged'"
        )
        with self.assertRaises(Blocked):
            journal.reserve(RUN_ID, proposal, proof)

    def test_workspace_expiry_and_nested_scope_deny_approval(self):
        self.journal()
        proposal = self.preview()
        proof = control.approval(proposal)
        with private_output_workspace():
            with self.assertRaises(Blocked):
                control.authorized(proposal, proof)
            with self.assertRaises(Blocked):
                control.Journal()

    def test_kill_switch_stops_plans_and_journal_effects(self):
        journal = self.journal()
        proposal = self.preview()
        proof = control.approval(proposal)
        with patch.dict(os.environ, {"FORGESTRA_KILL_SWITCH": "1"}):
            with self.assertRaises(Blocked):
                self.preview()
            with self.assertRaises(Blocked):
                journal.reserve(RUN_ID, proposal, proof)

    def test_cli_plan_and_baseline_and_blocked_runtime_are_real(self):
        config, baseline = self.parent / "mapping.json", self.parent / "baseline.json"
        config.write_bytes(sync.encoded(self.config))
        baseline.write_bytes(sync.encoded(self.baseline))
        for args, status, code in (
            (["sync-baseline", "--source", str(self.source), "--mapping", str(config)], None, 0),
            (
                [
                    "sync",
                    "--source",
                    str(self.source),
                    "--target",
                    str(self.target),
                    "--mapping",
                    str(config),
                    "--baseline",
                    str(baseline),
                ],
                "PLANNED_LOCAL",
                0,
            ),
            (["sync"], "BLOCKED", 1),
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(args), code)
            result = json.loads(output.getvalue())
            if status:
                self.assertEqual(result["status"], status)
            else:
                self.assertEqual(result, self.baseline)

    def test_missing_sync_evidence_cannot_pass(self):
        for value in (None, {}, {"status": "PASSED_LOCAL"}):
            self.assertFalse(valid_sync(value))

    def test_corrupt_previous_target_state_blocks_a_new_plan(self):
        journal = self.journal()
        proposal = self.preview()
        journal.reserve(RUN_ID, proposal, control.approval(proposal))
        journal.db.execute("UPDATE runs SET status='UNKNOWN'")
        self.head()
        changed = self.preview()
        with self.assertRaises(Blocked):
            journal.reserve(
                "08100000-0000-4000-8000-000000000009", changed, control.approval(changed)
            )

    def test_transient_private_cleanup_lock_is_retried(self):
        real_cleanup = sync.safety.tempfile.TemporaryDirectory.cleanup
        attempts = []

        def flaky(instance):
            attempts.append(instance.name)
            if len(attempts) == 1:
                raise PermissionError("synthetic transient lock")
            return real_cleanup(instance)

        with patch.object(sync.safety.tempfile.TemporaryDirectory, "cleanup", flaky):
            with patch.object(sync.safety.time, "sleep"):
                with private_output_workspace() as parent:
                    (parent / "fixture.txt").write_text("owned", encoding="utf-8")
        self.assertEqual(len(attempts), 2)
        if os.name == "nt":
            self.assertTrue(attempts[1].startswith("\\\\?\\"))
        self.assertFalse(parent.exists())

    def test_exhausted_private_cleanup_stays_blocked_and_sanitized(self):
        real_factory = sync.safety.tempfile.TemporaryDirectory
        issued = []

        def factory(*args, **kwargs):
            instance = real_factory(*args, **kwargs)
            issued.append(instance)
            return instance

        with patch.object(sync.safety.tempfile, "TemporaryDirectory", side_effect=factory):
            with patch.object(
                real_factory, "cleanup", side_effect=OSError("synthetic-private-secret")
            ) as cleanup:
                with patch.object(sync.safety.time, "sleep"):
                    with self.assertRaises(Blocked) as error:
                        with private_output_workspace():
                            pass
                self.assertEqual(cleanup.call_count, 5)
                self.assertNotIn("synthetic-private-secret", str(error.exception))
        issued[0].cleanup()

    def test_signed_success_receipt_cannot_name_another_run(self):
        journal = self.journal()
        proposal = self.preview()
        proof = control.approval(proposal)
        journal.reserve(RUN_ID, proposal, proof)
        journal.claim(RUN_ID, proposal, proof)
        receipt = {
            "run_id": "08100000-0000-4000-8000-000000000009",
            "status": "NOOP",
            "plan_sha256": control.fingerprint(proposal),
            "publication": "BLOCKED",
        }
        receipt["verification_proof"] = control.signature(receipt)
        with self.assertRaises(Blocked):
            journal.finish(RUN_ID, proposal, proof, "NOOP", receipt)

    def test_changed_plan_cannot_finish_as_noop(self):
        journal = self.journal()
        self.head()
        proposal = self.preview()
        proof = control.approval(proposal)
        journal.reserve(RUN_ID, proposal, proof)
        journal.claim(RUN_ID, proposal, proof)
        receipt = {
            "run_id": RUN_ID,
            "status": "NOOP",
            "plan_sha256": control.fingerprint(proposal),
            "publication": "BLOCKED",
        }
        receipt["verification_proof"] = control.signature(receipt)
        with self.assertRaises(Blocked):
            journal.finish(RUN_ID, proposal, proof, "NOOP", receipt)

    def test_terminal_update_does_not_overwrite_intervening_cancellation(self):
        journal = self.journal()
        proposal = self.preview()
        proof = control.approval(proposal)
        journal.reserve(RUN_ID, proposal, proof)
        journal.claim(RUN_ID, proposal, proof)
        original = journal.require_executing

        def cancelled(*args):
            original(*args)
            journal.db.execute("UPDATE runs SET status='CANCELLED'")

        with patch.object(journal, "require_executing", side_effect=cancelled):
            with self.assertRaises(Blocked):
                journal.finish(RUN_ID, proposal, proof, "FAILED")
        self.assertEqual(journal.db.execute("SELECT status FROM runs").fetchone()[0], "CANCELLED")

    def test_git_helper_rejects_nonliteral_files_before_subprocess(self):
        from pr08_sync_validation import git_snapshot

        root = self.parent / "sync-candidate"
        root.mkdir()
        (root / "unreviewed.txt").write_bytes(b"Not authored fixture bytes")
        with patch("pr08_sync_validation.subprocess.run") as run:
            with self.assertRaises(Blocked):
                git_snapshot(root, {"unreviewed.txt": b"Not authored fixture bytes"})
            run.assert_not_called()

    def test_valid_noop_replays_original_run_but_rejects_relabelled_cache(self):
        journal = self.journal()
        proposal = self.preview()
        proof = control.approval(proposal)
        journal.reserve(RUN_ID, proposal, proof)
        journal.claim(RUN_ID, proposal, proof)
        receipt = {
            "run_id": RUN_ID,
            "status": "NOOP",
            "plan_sha256": control.fingerprint(proposal),
            "publication": "BLOCKED",
        }
        receipt["verification_proof"] = control.signature(receipt)
        journal.finish(RUN_ID, proposal, proof, "NOOP", receipt)
        another = "08100000-0000-4000-8000-000000000009"
        replay = journal.reserve(another, proposal, proof)
        self.assertEqual(replay["status"], "DUPLICATE")
        self.assertEqual(replay["receipt"]["run_id"], RUN_ID)
        journal.db.execute("UPDATE runs SET run_id=?", (another,))
        with self.assertRaises(Blocked):
            journal.reserve(another, proposal, proof)

    def test_git_helper_checks_actual_bytes_before_subprocess(self):
        from pr08_sync_validation import git_snapshot

        expected = {**CUSTOM, **{n.replace("template/", "app/", 1): d for n, d in HEAD.items()}}
        root = self.parent / "sync-candidate"
        write_fixture(root, expected)
        (root / "app/guide.txt").write_bytes(b"Unreviewed modification")
        with patch("pr08_sync_validation.subprocess.run") as run:
            with self.assertRaises(Blocked):
                git_snapshot(root, expected)
            run.assert_not_called()
