"""PR 06 schema, route, ownership, secret and private-output contracts."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from forgestra import web
from forgestra.cli import main
from forgestra_safety import Blocked, private_output_workspace, relative_path


class PR06Tests(unittest.TestCase):
    def setUp(self):
        self.document = copy.deepcopy(web.FIXTURE_SCHEMA)

    def test_domain_is_explicit_owned_and_nonempty(self):
        self.assertEqual(web.schema(self.document), self.document)
        self.assertEqual(self.document["authentication"]["owner_field"], "owner_id")

    def test_empty_comments_and_wrong_root_types_rejected(self):
        cases: tuple[object, ...] = (
            None,
            [],
            {},
            "# Only comments",
            {**self.document, "resources": []},
        )
        for document in cases:
            with self.assertRaises(Blocked):
                web.schema(document)

    def test_schema_version_and_unknown_keys_fail_closed(self):
        for version in (True, 0, "1"):
            with self.assertRaises(Blocked):
                web.schema({**self.document, "schema_version": version})
        with self.assertRaises(Blocked):
            web.schema({**self.document, "approved": True})

    def test_identifier_injection_and_protected_resources_rejected(self):
        for name in (
            "../outside",
            "query_root",
            "users",
            "api",
            "secrets",
            "admin_tasks",
            "x;drop",
            "Tasks",
            "__proto__",
            "nul",
        ):
            document = copy.deepcopy(self.document)
            document["resources"][0]["name"] = name
            with self.assertRaises(Blocked):
                web.schema(document)

    def test_duplicate_resources_and_fields_rejected(self):
        self.document["resources"].append(copy.deepcopy(self.document["resources"][0]))
        with self.assertRaises(Blocked):
            web.schema(self.document)
        self.document = copy.deepcopy(web.FIXTURE_SCHEMA)
        self.document["resources"][0]["fields"].append(
            copy.deepcopy(self.document["resources"][0]["fields"][0])
        )
        with self.assertRaises(Blocked):
            web.schema(self.document)

    def test_generated_hasura_root_collisions_rejected(self):
        another = copy.deepcopy(self.document["resources"][0])
        another["name"] = "tasks_aggregate"
        self.document["resources"].append(another)
        with self.assertRaises(Blocked):
            web.schema(self.document)

    def test_relations_enums_and_unknown_fields_are_not_silently_skipped(self):
        types: tuple[object, ...] = ("relation", "enum", "array", {})
        for field_type in types:
            document = copy.deepcopy(self.document)
            document["resources"][0]["fields"][0]["type"] = field_type
            with self.assertRaises(Blocked):
                web.schema(document)

    def test_limits_and_nullable_types_are_strict(self):
        for invalid in (None, 0, "true"):
            document = copy.deepcopy(self.document)
            document["resources"][0]["fields"][0]["nullable"] = invalid
            with self.assertRaises(Blocked):
                web.schema(document)
        self.document["resources"] *= 9
        with self.assertRaises(Blocked):
            web.schema(self.document)

    def test_authentication_cannot_select_admin_or_client_owner(self):
        for field, value in (
            ("role", "admin"),
            ("mode", "anonymous"),
            ("owner_field", "client_owner"),
        ):
            document = copy.deepcopy(self.document)
            document["authentication"][field] = value
            with self.assertRaises(Blocked):
                web.schema(document)

    def test_secret_canary_labels_rejected_without_output(self):
        canary = "synthetic-review-credential-06"
        self.document["resources"][0]["label"] = canary
        with patch.dict(os.environ, {"FORGESTRA_TEST_SECRET": canary}):
            with self.assertRaises(Blocked):
                web.render(self.document)

    def test_complete_render_is_deterministic(self):
        first = web.render(self.document)
        self.assertEqual(first, web.render(copy.deepcopy(self.document)))
        paths = {f["path"] for f in first}
        for expected in (
            "package-lock.json",
            "src/app/layout.tsx",
            "src/app/page.tsx",
            "src/app/tasks/page.tsx",
            "src/app/tasks/create/page.tsx",
            "src/app/tasks/[id]/edit/page.tsx",
            "src/app/api/graphql/route.ts",
        ):
            self.assertIn(expected, paths)

    def test_sql_and_metadata_enforce_backend_ownership(self):
        self.document["resources"][0]["name"] = "order"
        sql, raw = web.backend_files(web.schema(self.document))
        self.assertIn('CREATE TABLE public."order"', sql)
        metadata = json.loads(raw)
        table = metadata["sources"][0]["tables"][0]
        self.assertEqual(
            table["select_permissions"][0]["permission"]["filter"],
            {"owner_id": {"_eq": "X-Hasura-User-Id"}},
        )
        self.assertNotIn("owner_id", table["insert_permissions"][0]["permission"]["columns"])
        self.assertEqual(
            table["insert_permissions"][0]["permission"]["set"], {"owner_id": "x-hasura-user-id"}
        )

    def test_concrete_operations_and_types_are_emitted(self):
        files = {f["path"]: f["content"] for f in web.render(self.document)}
        self.assertIn("tasks_update", files["src/generated/models.ts"])
        self.assertIn("uuid!", files["src/generated/domain.ts"])
        self.assertIn("Promise<{ id: string }>", files["src/app/tasks/[id]/edit/page.tsx"])

    def test_read_only_inspection_does_not_spawn_or_write(self):
        with patch("subprocess.run", side_effect=AssertionError("no subprocess")):
            result = web.inspect(self.document)
        self.assertEqual(result["status"], "PLANNED_LOCAL")
        self.assertEqual(result["side_effects"], [])
        self.assertEqual(result["backend_connectivity"], "NOT_RUN")

    def test_arbitrary_output_directory_denied(self):
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "customer"
            with self.assertRaises(Blocked):
                web.write_project(output, self.document)
            self.assertFalse(output.exists())

    def test_new_project_written_only_in_issued_scope(self):
        with private_output_workspace() as parent:
            output = parent / "web-candidate"
            web.write_project(output, self.document)
            self.assertTrue((output / "src/app/tasks/[id]/edit/page.tsx").is_file())
            (output / "src/custom/extension.ts").write_text("// user extension", encoding="utf-8")
            before = (output / "src/custom/extension.ts").read_bytes()
            with self.assertRaises(Blocked):
                web.write_project(output, self.document)
            self.assertEqual((output / "src/custom/extension.ts").read_bytes(), before)

    def test_expired_scope_denies_generation(self):
        with private_output_workspace() as parent:
            output = parent / "web-candidate"
        with self.assertRaises(Blocked):
            web.write_project(output, self.document)

    def test_kill_switch_denies_before_staging(self):
        with private_output_workspace() as parent:
            with patch.dict(os.environ, {"FORGESTRA_KILL_SWITCH": "1"}):
                with self.assertRaises(Blocked):
                    web.write_project(parent / "candidate", self.document)
            self.assertEqual(list(parent.iterdir()), [])

    def test_asset_tampering_rejected_before_output(self):
        with private_output_workspace() as parent:
            assets = parent / "assets"
            shutil.copytree(web.ROOT, assets)
            (assets / "home.txt").write_text("tampered", encoding="utf-8")
            with patch.object(web, "ROOT", assets):
                with self.assertRaises(Blocked):
                    web.write_project(parent / "candidate", self.document)
            self.assertFalse((parent / "candidate").exists())

    def test_extra_template_files_denied(self):
        with private_output_workspace() as parent:
            assets = parent / "assets"
            shutil.copytree(web.ROOT, assets)
            (assets / "extra.txt").write_text("not reviewed", encoding="utf-8")
            with patch.object(web, "ROOT", assets):
                with self.assertRaises(Blocked):
                    web.render(self.document)

    def test_only_the_reviewed_dynamic_route_syntax_is_allowed(self):
        relative_path("src/app/tasks/[id]/edit/page.tsx")
        for path in (
            "src/app/tasks/[...id]/page.tsx",
            "src/app/tasks/[id]/other.tsx",
            "arbitrary/[id]/file",
            "src/app/../tasks/[id]/edit/page.tsx",
        ):
            with self.assertRaises(Blocked):
                relative_path(path)

    def test_source_cli_is_read_only_and_empty_schema_is_nonzero(self):
        with private_output_workspace() as parent:
            source = parent / "domain.json"
            for document, expected in ((self.document, 0), ({}, 1)):
                source.write_text(json.dumps(document), encoding="utf-8")
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main(["web", "--schema", str(source)]), expected)
                result = json.loads(output.getvalue())
                self.assertEqual(result["status"], "PLANNED_LOCAL" if expected == 0 else "BLOCKED")
            self.assertEqual([p.name for p in parent.iterdir()], ["domain.json"])

    def test_dependency_lock_rejects_hooks_ranges_and_foreign_hosts(self):
        from pr06_web_validation import dependency_contract

        package = json.loads((web.ROOT / "package.json").read_text(encoding="utf-8"))
        lock = json.loads((web.ROOT / "package-lock.json").read_text(encoding="utf-8"))
        self.assertGreater(dependency_contract(package, lock)["locked"], 0)
        changed = copy.deepcopy(package)
        changed["scripts"]["postinstall"] = "echo unreviewed"
        with self.assertRaises(Blocked):
            dependency_contract(changed, lock)
        changed = copy.deepcopy(lock)
        first = next(name for name in changed["packages"] if name)
        changed["packages"][first]["resolved"] = "https://other.invalid/pkg.tgz"
        with self.assertRaises(Blocked):
            dependency_contract(package, changed)
        changed = copy.deepcopy(package)
        changed["dependencies"]["next"] = "latest"
        with self.assertRaises(Blocked):
            dependency_contract(changed, lock)

    def test_zero_skipped_duplicate_or_inconsistent_web_tests_fail(self):
        from pr06_web_validation import test_counts

        tap = "\n".join(f"ok {i} - fixture {i}" for i in range(1, 22)) + "\n1..21\n"
        tap += "# tests 21\n# suites 0\n# pass 21\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n"
        self.assertEqual(test_counts(tap)["tests"], 21)
        for invalid in (
            "",
            tap + "# tests 0\n",
            tap.replace("# skipped 0", "# skipped 1"),
            tap.replace("ok 2 -", "ok 1 -"),
        ):
            with self.assertRaises(Blocked):
                test_counts(invalid)

    def test_missing_web_evidence_cannot_pass(self):
        from pr06_web_validation import valid_web

        cases: tuple[object, ...] = (
            None,
            {},
            {"status": "PASSED_LOCAL"},
            {"browser": None, "canary_scan": {}},
        )
        for document in cases:
            self.assertFalse(valid_web(document))

    def test_malformed_lock_containers_and_resolution_fail_closed(self):
        from pr06_web_validation import dependency_contract

        package = json.loads((web.ROOT / "package.json").read_text(encoding="utf-8"))
        lock = json.loads((web.ROOT / "package-lock.json").read_text(encoding="utf-8"))
        invalid_values: tuple[object, ...] = (None, [], "invalid", 1)
        for value in invalid_values:
            changed = copy.deepcopy(lock)
            changed["packages"][""] = value
            with self.assertRaises(Blocked):
                dependency_contract(package, changed)
            changed = copy.deepcopy(lock)
            first = next(name for name in changed["packages"] if name)
            changed["packages"][first]["resolved"] = value
            with self.assertRaises(Blocked):
                dependency_contract(package, changed)
