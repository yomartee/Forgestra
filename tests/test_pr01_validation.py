"""Local tool validation stays fail-closed without requiring tools for unit tests."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any
import unittest
from unittest.mock import patch

import pr01_validation
import record_pr01_evidence

ROOT = Path(__file__).resolve().parents[1]


class LocalValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="forgestra-validation-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / "docs/engineering/evidence/pr-01"
        self.evidence.mkdir(parents=True)
        self.provenance: dict[str, Any] = {"native": {}, "python": {}}
        self.root_patch = patch.object(pr01_validation, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def write_provenance(self):
        (self.evidence / "local-tools.json").write_text(json.dumps(self.provenance))

    def test_changed_native_validator_is_rejected_before_execution(self):
        executable = self.root / ".tools/actionlint/actionlint.exe"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"inert tool fixture")
        self.provenance["native"]["actionlint"] = {
            "executable": executable.relative_to(self.root).as_posix(),
            "executable_sha256": "0" * 64,
        }
        self.write_provenance()
        with patch("subprocess.run", side_effect=AssertionError("must not execute")):
            with self.assertRaises(ValueError):
                pr01_validation.verified_native("actionlint")

    def test_changed_python_tool_manifest_is_rejected(self):
        manifest = self.root / ".tools/installed-files.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("{}")
        self.provenance["python"] = {
            "installed_manifest": manifest.relative_to(self.root).as_posix(),
            "installed_manifest_sha256": "0" * 64,
        }
        self.write_provenance()
        with self.assertRaises(ValueError):
            pr01_validation.verified_python_tools()

    def test_formatter_configuration_cannot_exclude_the_safety_scope(self):
        config = self.root / "config/pr01-black.toml"
        config.parent.mkdir()
        config.write_text('[tool.black]\nforce-exclude = ".*"\n')
        with self.assertRaises(ValueError):
            pr01_validation.command("black")

    def test_unknown_validator_and_path_escape_are_rejected(self):
        with self.assertRaises(ValueError):
            pr01_validation.command("unapproved")
        for path in ["../outside", ".tools/../../outside", "C:/outside", "-option"]:
            with self.assertRaises(ValueError):
                pr01_validation.checked_path(path)

    def test_untracked_tool_bytecode_is_rejected(self):
        directory = self.root / ".tools/python"
        directory.mkdir(parents=True)
        manifest = self.root / ".tools/installed-files.json"
        manifest.write_text("{}")
        self.provenance["python"] = {
            "installed_manifest": manifest.relative_to(self.root).as_posix(),
            "installed_manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        }
        (directory / "untracked.pyc").write_bytes(b"untrusted bytecode")
        self.write_provenance()
        with self.assertRaises(ValueError):
            pr01_validation.verified_python_tools()

    def test_failed_lint_cannot_report_passed_evidence(self):
        for name in ["actionlint", "shellcheck", "black", "flake8", "mypy"]:
            self.assertEqual(record_pr01_evidence.assess_check(name, 1, "")["status"], "FAILED")
            self.assertEqual(record_pr01_evidence.assess_check(name, 0, "")["status"], "PASSED")

    def test_publisher_references_match_explicit_owner_decision(self):
        owners = [
            line
            for line in (ROOT / ".github/CODEOWNERS").read_text().splitlines()
            if line and not line.startswith("#")
        ]
        self.assertTrue(owners)
        self.assertTrue(all(line.split()[1:] == ["@yomartee"] for line in owners))
        previous_owner = "abiola" + "ogu"
        for relative in record_pr01_evidence.source_hashes():
            content = (ROOT / relative).read_bytes()
            self.assertNotIn(previous_owner.encode("ascii"), content.lower(), relative)

    def test_tool_subprocess_receives_no_publisher_credentials(self):
        # Inspect the actual subprocess boundary, not the checksum/policy logic.
        captured: dict[str, str] = {}
        executable = self.root / ".tools/shellcheck/shellcheck.exe"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"inert static validator fixture")
        self.provenance["native"]["shellcheck"] = {
            "executable": executable.relative_to(self.root).as_posix(),
            "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        }
        self.write_provenance()

        def completed(argv, **kwargs):
            captured.update(kwargs["env"])
            return type("Completed", (), {"returncode": 0})()

        with (
            patch.dict(os.environ, {"FACTORY_ADMIN_TOKEN": "canary-admin-do-not-use"}),
            patch.object(pr01_validation.subprocess, "run", completed),
            patch("sys.argv", ["pr01_validation.py", "shellcheck"]),
        ):
            self.assertEqual(pr01_validation.main(), 0)
        self.assertNotIn("FACTORY_ADMIN_TOKEN", captured)
