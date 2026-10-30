"""PR 05 preservation, conflict and denied-authority acceptance."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from forgestra.adoption import (
    FIXTURE_CONFIGURATION,
    RECEIPT,
    SEED,
    VERSIONS,
    FixtureInstaller,
    assets,
    default_branch,
    local_install_fixture,
    plan,
    read_tree,
)
from forgestra.cli import main
from forgestra_safety import Blocked


class PR05Tests(unittest.TestCase):
    def test_install_repeat_upgrade_uninstall_preserve_all_user_bytes(self):
        with local_install_fixture() as control:
            original = control.current
            installed = control.transition()
            self.assertEqual(installed["status"], "APPLIED_FIXTURE_ONLY")
            self.assertEqual(read_tree(original)["files"], SEED)
            self.assertEqual(control.transition()["status"], "NO_OP")
            upgraded = control.transition("upgrade", VERSIONS[1])
            self.assertEqual(upgraded["status"], "APPLIED_FIXTURE_ONLY")
            for name, data in SEED.items():
                self.assertEqual((control.current / name).read_bytes(), data)
            self.assertEqual(
                control.preview("upgrade", VERSIONS[1])["installed_factory_version"], VERSIONS[1]
            )
            self.assertEqual(control.transition("uninstall")["status"], "APPLIED_FIXTURE_ONLY")
            self.assertEqual(read_tree(control.current)["files"], SEED)

    def test_planner_does_not_write_or_execute(self):
        with local_install_fixture() as control:
            before = read_tree(control.current)
            with patch("subprocess.run", side_effect=AssertionError("no process")):
                proposal = control.preview()
            self.assertEqual(proposal["status"], "PLANNED_LOCAL")
            self.assertEqual(before, read_tree(control.current))
            self.assertEqual(proposal["side_effects"], [])
            self.assertEqual(proposal["target_tests"], "NOT_RUN")
            self.assertTrue(all(c["path"].startswith(".forgestra/") for c in proposal["changes"]))

    def test_unowned_same_bytes_still_conflict(self):
        with local_install_fixture() as control:
            name, data = next(iter(assets(VERSIONS[0]).items()))
            path = control.current / name
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
            before = read_tree(control.current)
            self.assertEqual(control.transition()["status"], "REVIEW_REQUIRED")
            self.assertEqual(before, read_tree(control.current))

    def test_file_directory_collision_blocks_whole_transition(self):
        with local_install_fixture() as control:
            (control.current / ".forgestra").write_bytes(b"customer")
            self.assertEqual(control.transition()["status"], "REVIEW_REQUIRED")
            self.assertFalse(list(control.parent.glob("adoption-*")))

    def test_empty_directory_at_asset_file_is_collision(self):
        with local_install_fixture() as control:
            (control.current / RECEIPT).mkdir(parents=True)
            self.assertEqual(control.transition()["status"], "REVIEW_REQUIRED")

    def test_modified_owned_file_never_overwritten_or_deleted(self):
        for action in ("install", "upgrade", "uninstall"):
            with local_install_fixture() as control:
                control.transition()
                name = next(iter(assets(VERSIONS[0])))
                (control.current / name).write_bytes(b"customer modification")
                before = read_tree(control.current)
                self.assertEqual(
                    control.transition(action, VERSIONS[1])["status"], "REVIEW_REQUIRED"
                )
                self.assertEqual(before, read_tree(control.current))

    def test_unknown_namespace_user_file_survives_uninstall(self):
        with local_install_fixture() as control:
            control.transition()
            path = control.current / ".forgestra/user-notes.txt"
            path.write_bytes(b"mine")
            self.assertEqual(control.transition("uninstall")["status"], "APPLIED_FIXTURE_ONLY")
            self.assertEqual(
                (control.current / path.relative_to(path.parents[1])).read_bytes(), b"mine"
            )

    def test_forged_manifest_cannot_delete_customer_file(self):
        with local_install_fixture() as control:
            control.transition()
            path = control.current / RECEIPT
            document = json.loads(path.read_bytes())
            document["ownership"]["CLAUDE.md"] = "0" * 64
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(control.transition("uninstall")["status"], "REVIEW_REQUIRED")
            self.assertEqual((control.current / "CLAUDE.md").read_bytes(), SEED["CLAUDE.md"])

    def test_unknown_versions_and_operations_block(self):
        with local_install_fixture() as control:
            for action, version in (("delete", VERSIONS[0]), ("install", "latest")):
                with self.assertRaises(Blocked):
                    control.transition(action, version)

    def test_upgrade_requires_manifest_and_explicit_operation(self):
        with local_install_fixture() as control:
            self.assertEqual(control.transition("upgrade")["status"], "REVIEW_REQUIRED")
            control.transition()
            self.assertEqual(
                control.transition("install", VERSIONS[1])["status"], "REVIEW_REQUIRED"
            )
            control.transition("upgrade", VERSIONS[1])
            self.assertEqual(
                control.transition("upgrade", VERSIONS[0])["status"], "REVIEW_REQUIRED"
            )

    def test_default_branch_uses_cached_ref_without_master_fallback(self):
        with local_install_fixture() as control:
            self.assertEqual(default_branch(control.current)["name"], "team/trunk")
            self.assertFalse(default_branch(control.current)["live_verified"])
            (control.current / ".git/refs/remotes/origin/HEAD").unlink()
            proposal = control.preview()
            self.assertIsNone(proposal["default_branch"]["name"])
            self.assertIn("DEFAULT_BRANCH_UNAVAILABLE_NO_FALLBACK", proposal["prerequisites"])
            self.assertEqual(control.transition()["status"], "REVIEW_REQUIRED")

    def test_malformed_branch_metadata_is_blocked(self):
        with local_install_fixture() as control:
            head = control.current / ".git/refs/remotes/origin/HEAD"
            for content in (
                b"master",
                b"ref: refs/remotes/origin/../../bad",
                b"ref: refs/remotes/origin/a.lock",
            ):
                head.write_bytes(content)
                with self.assertRaises(Blocked):
                    control.preview()

    def test_permission_failure_never_falls_back(self):
        with local_install_fixture() as control:
            with patch("forgestra.adoption.bounded_file", side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    default_branch(control.current)

    def test_mixed_target_requires_explicit_workspace(self):
        with local_install_fixture() as control:
            proposal = plan(control.current)
            self.assertEqual(proposal["status"], "REVIEW_REQUIRED")
            self.assertIn("TARGET_TOOLCHAIN_CONFIGURATION_REQUIRED", proposal["prerequisites"])
            self.assertEqual(control.preview()["workspaces"]["workspaces"][0]["manager"], "npm")

    def test_missing_lockfile_blocks_incomplete_setup(self):
        with local_install_fixture() as control:
            (control.current / "package-lock.json").unlink()
            self.assertEqual(control.transition()["status"], "REVIEW_REQUIRED")

    def test_case_alias_collision_requires_review(self):
        with local_install_fixture() as control:
            (control.current / ".FORGESTRA").mkdir()
            self.assertEqual(control.transition()["status"], "REVIEW_REQUIRED")
        with local_install_fixture() as control:
            (control.current / ".forgestra/ASSETS").mkdir(parents=True)
            self.assertEqual(control.transition()["status"], "REVIEW_REQUIRED")

    def test_link_entry_is_denied_without_following_it(self):
        with local_install_fixture() as control:
            with patch.object(Path, "is_symlink", return_value=True):
                with self.assertRaises(Blocked):
                    control.preview()

    def test_byte_budget_blocks_oversized_customer_file(self):
        with local_install_fixture() as control:
            (control.current / "large.bin").write_bytes(b"x" * 262145)
            with self.assertRaises(Blocked):
                control.preview()

    def test_kill_switch_prevents_candidate_creation(self):
        with local_install_fixture() as control:
            with patch.dict(os.environ, {"FORGESTRA_KILL_SWITCH": "1"}):
                with self.assertRaises(Blocked):
                    control.transition()
            self.assertFalse(list(control.parent.glob("adoption-*")))

    def test_scope_and_constructor_cannot_accept_customer_root(self):
        with self.assertRaises(Blocked):
            FixtureInstaller(Path.cwd(), object())
        with local_install_fixture() as control:
            pass
        with self.assertRaises(Blocked):
            control.transition()

    def test_runtime_install_stays_disabled(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["install"]), 1)
        self.assertEqual(json.loads(output.getvalue())["reason_code"], "RUNTIME_INSTALL_DISABLED")

    def test_source_change_during_staging_keeps_new_user_bytes(self):
        with local_install_fixture() as control:
            original = control.current
            preview = control.preview

            def changed(*args):
                result = preview(*args)
                (original / "README.md").write_bytes(b"new customer edit")
                return result

            with patch.object(control, "preview", changed):
                with self.assertRaises(Blocked):
                    control.transition()
            self.assertEqual(control.current, original)
            self.assertEqual((original / "README.md").read_bytes(), b"new customer edit")

    def test_kill_switch_during_staging_never_selects_partial_candidate(self):
        with local_install_fixture() as control:
            original = control.current
            write = Path.write_bytes

            def cancelled(path, data):
                count = write(path, data)
                os.environ["FORGESTRA_KILL_SWITCH"] = "1"
                return count

            with patch.dict(os.environ, {"FORGESTRA_KILL_SWITCH": "0"}):
                with patch.object(Path, "write_bytes", cancelled):
                    with self.assertRaises(Blocked):
                        control.transition()
            self.assertEqual(control.current, original)
            self.assertEqual(read_tree(original)["files"], SEED)

    def test_recorder_rejects_false_success_and_inconsistent_plans(self):
        import hashlib
        import shutil
        from forgestra.adoption import runtime_install
        from record_pr05_evidence import valid_adoption

        node = shutil.which("node")
        assert node is not None, "authored fixture requires the installed Node toolchain"
        record = acceptance()
        record["installed_plan"] = copy.deepcopy(record["install"]["plan"])
        record["installed_denial"] = runtime_install()
        record["original_unchanged_after_installed_cli"] = True
        with local_install_fixture() as control:
            config = copy.deepcopy(FIXTURE_CONFIGURATION)
            del config["workspaces"][0]["commands"]["test"]
            missing_test = plan(control.current, configuration=config)
            (control.current / ".git/refs/remotes/origin/HEAD").unlink()
            missing_branch = control.preview()
        record["installed_negative_plans"] = [
            {"name": name, "exit_code": 1, "status": "PASSED", "result": document}
            for name, document in (
                ("missing-test", missing_test),
                ("missing-default-branch", missing_branch),
                (
                    "invalid-command",
                    {"status": "BLOCKED", "reason_code": "INVALID_INPUT_OR_CONFIGURATION"},
                ),
                (
                    "redacted-plan",
                    {"status": "BLOCKED", "reason_code": "INVALID_INPUT_OR_CONFIGURATION"},
                ),
            )
        ]
        outputs = {
            "build.js": "authored fixture build\n",
            "test.js": "TAP version 13\n# Subtest: test.js\nok 1 - test.js\n  ---\n"
            "  duration_ms: 1.25\n  type: 'test'\n  ...\n1..1\n# tests 1\n# suites 0\n"
            "# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 2.5\n",
        }
        record["fixture_commands"] = [
            {
                "stage": stage,
                "argv": argv,
                "exit_code": 0,
                "status": "PASSED",
                "stdout": outputs[argv[-1]],
                "stdout_sha256": hashlib.sha256(outputs[argv[-1]].encode()).hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            }
            for stage in ("clean", "installed", "upgraded", "uninstalled")
            for argv in (
                [node, "build.js"],
                [node, "--test", "--test-reporter=tap", "test.js"],
            )
        ]
        self.assertTrue(valid_adoption(record))
        for key in (
            "original_preserved",
            "uninstall_preserved",
            "original_unchanged_after_installed_cli",
        ):
            changed = copy.deepcopy(record)
            changed[key] = False
            self.assertFalse(valid_adoption(changed))
        changed = copy.deepcopy(record)
        changed["upgrade"]["plan"]["changes"][0]["path"] = "CLAUDE.md"
        self.assertFalse(valid_adoption(changed))
        changed = copy.deepcopy(record)
        changed["fixture_commands"][0]["exit_code"] = True
        self.assertFalse(valid_adoption(changed))
        changed = copy.deepcopy(record)
        changed["fixture_commands"][1]["stdout"] = "# tests 0\n# fail 0\n"
        changed["fixture_commands"][1]["stdout_sha256"] = hashlib.sha256(
            changed["fixture_commands"][1]["stdout"].encode()
        ).hexdigest()
        self.assertFalse(valid_adoption(changed))
        for value in (None, {}, {"status": "PASSED_LOCAL"}):
            self.assertFalse(valid_adoption(value))
        malformed_plans: tuple[object, ...] = (None, [], "PASSED_LOCAL")
        for malformed_plan in malformed_plans:
            changed = copy.deepcopy(record)
            changed["upgrade"]["plan"] = malformed_plan
            self.assertFalse(valid_adoption(changed))
        from forgestra.adoption import digest, encoded

        for field, invalid_value in (
            ("status", "BLOCKED"),
            ("schema_version", True),
            ("remote", "CREATED"),
            ("ownership_authority", "APPROVED"),
        ):
            changed = copy.deepcopy(record)
            proposal = changed["upgrade"]["plan"]
            proposal[field] = invalid_value
            material = {k: v for k, v in proposal.items() if k != "plan_sha256"}
            proposal["plan_sha256"] = digest(encoded(material))
            self.assertFalse(valid_adoption(changed))
        changed = copy.deepcopy(record)
        changed["installed_negative_plans"][0]["exit_code"] = 0
        self.assertFalse(valid_adoption(changed))

    def test_explicit_config_cannot_select_publisher_or_shell(self):
        with local_install_fixture() as control:
            config = copy.deepcopy(FIXTURE_CONFIGURATION)
            config["workspaces"][0]["commands"]["test"] = ["npm", "run", "missing"]
            self.assertEqual(
                plan(control.current, configuration=config)["status"], "REVIEW_REQUIRED"
            )


def acceptance():
    """Actual filesystem transitions; execution of target commands is separate."""
    with local_install_fixture() as control:
        original = control.current
        install = control.transition()
        repeat = control.transition()
        upgrade = control.transition("upgrade", VERSIONS[1])
        uninstall = control.transition("uninstall")
        return {
            "status": (
                "PASSED_LOCAL"
                if (
                    install["status"]
                    == upgrade["status"]
                    == uninstall["status"]
                    == "APPLIED_FIXTURE_ONLY"
                    and repeat["status"] == "NO_OP"
                    and read_tree(original)["files"] == read_tree(control.current)["files"] == SEED
                )
                else "FAILED"
            ),
            "install": install,
            "repeat": repeat,
            "upgrade": upgrade,
            "uninstall": uninstall,
            "original_preserved": read_tree(original)["files"] == SEED,
            "uninstall_preserved": read_tree(control.current)["files"] == SEED,
            "privileged_automation": "DISABLED",
            "publication": "BLOCKED",
            "remote": "NOT_RUN",
        }
