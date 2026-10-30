"""Public checks and private preservation are different, fail-closed contracts."""

import copy
import hashlib
import json
import base64
import csv
import io
import tarfile
import zipfile
from pathlib import Path
import unittest
from typing import Any
from unittest.mock import patch

from forgestra_safety import Blocked, private_output_workspace
import public_contract as p
from private_evidence import PROFILE, REQUIRED, replay
from forgestra.release import readiness, sbom
from check_safety import run_suite

ROOT = Path(__file__).resolve().parents[1]


class PublicCandidateTests(unittest.TestCase):
    def test_projection_rejects_malformed_case_and_manifest_directives(self):
        with private_output_workspace() as root:
            path = root / "config/public-source.json"
            path.parent.mkdir()
            cases: tuple[list[Any], ...] = (
                [{}],
                [None],
                ["docs/AUDIT/a.md"],
                ["owner_decisions.md"],
                ["*.py"],
                ["a\ninclude secret"],
                ["src/private.egg-info/a"],
            )
            for names in cases:
                path.write_text(json.dumps({"profile": p.PUBLIC, "paths": names}))
                with self.assertRaises(Blocked):
                    p.source_paths(root)

    def test_unlisted_nested_egg_info_is_not_an_ignored_source_directory(self):
        with private_output_workspace() as root:
            (root / "config").mkdir()
            path = root / "config/public-source.json"
            path.write_text(
                json.dumps({"profile": p.PUBLIC, "paths": ["config/public-source.json"]})
            )
            directory = root / "private.egg-info"
            directory.mkdir()
            (directory / "unlisted.txt").write_text("synthetic private bytes")
            with self.assertRaises(Blocked):
                p.inventory(root)

    def archives(
        self, root, *, omit=None, altered=None, extra=None, bad_record=False, duplicate=False
    ):
        files = {
            "LICENSE": b"authored license fixture; no rights grant",
            "src/forgestra/__init__.py": b"# authored inert fixture\n",
            "scripts/forgestra_safety.py": b"# authored inert fixture\n",
            "scripts/inspect_local.py": b"# authored inert fixture\n",
        }
        for name, data in files.items():
            dest = root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        prefix = "forgestra-0.2.0.dev0.dist-info/"
        wheel_files = {
            "forgestra/__init__.py": files["src/forgestra/__init__.py"],
            "forgestra_safety.py": files["scripts/forgestra_safety.py"],
            "inspect_local.py": files["scripts/inspect_local.py"],
            prefix + "licenses/LICENSE": files["LICENSE"],
            prefix
            + "METADATA": (
                b"Name: forgestra\nVersion: 0.2.0.dev0\nRequires-Python: <3.15,>=3.14\n"
                b'Requires-Dist: black==26.10.1; extra == "dev"\n'
                b'Requires-Dist: flake8==7.4.1; extra == "dev"\n'
                b'Requires-Dist: mypy==2.4.0; extra == "dev"\n\n'
            ),
            prefix + "WHEEL": b"Wheel-Version: 1.0\n",
            prefix + "entry_points.txt": b"authored inert fixture",
            prefix + "top_level.txt": b"forgestra\n",
        }
        if altered == "wheel":
            wheel_files["forgestra/__init__.py"] = b"# altered payload\n"
        stream = io.StringIO()
        writer = csv.writer(stream)
        for name, data in wheel_files.items():
            writer.writerow(
                (
                    name,
                    "sha256="
                    + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("="),
                    str(len(data)),
                )
            )
        writer.writerow((prefix + "RECORD", "", ""))
        wheel_files[prefix + "RECORD"] = (
            b"bad,record\n" if bad_record else stream.getvalue().encode()
        )
        wheel = root / "authored.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, data in wheel_files.items():
                archive.writestr(name, data)
        sdist = root / "authored.tar.gz"
        generated = {
            "PKG-INFO": b"authored metadata",
            "setup.cfg": b"[egg_info]\ntag_build = \ntag_date = 0\n\n",
        }
        generated.update(
            {
                "scripts/forgestra.egg-info/" + n: b"authored metadata"
                for n in (
                    "PKG-INFO",
                    "SOURCES.txt",
                    "dependency_links.txt",
                    "entry_points.txt",
                    "requires.txt",
                    "top_level.txt",
                )
            }
        )
        contents = files | generated
        if omit:
            del contents[omit]
        if altered == "sdist":
            contents["src/forgestra/__init__.py"] = b"# altered source\n"
        if extra:
            contents[extra] = b"unlisted inert fixture"
        with tarfile.open(sdist, "w:gz") as archive:
            for name, data in list(contents.items()) + (
                [("LICENSE", files["LICENSE"])] if duplicate else []
            ):
                info = tarfile.TarInfo("forgestra-0.2.0.dev0/" + name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return sorted(files), wheel, sdist

    def inspect_fixture(self, root, **kwargs):
        names, wheel, sdist = self.archives(root, **kwargs)
        with patch.object(p, "source_paths", return_value=names):
            return p.inspect_distributions(root, wheel, sdist)

    def test_distribution_requires_complete_exact_authored_payload(self):
        with private_output_workspace() as root:
            result = self.inspect_fixture(root)
            self.assertEqual(len(result["wheel_members"]), 9)
            with self.assertRaises(Blocked):
                self.inspect_fixture(root, omit="src/forgestra/__init__.py")

    def test_distribution_rejects_source_tampering_and_extra_metadata_code(self):
        with private_output_workspace() as root:
            for kwargs in (
                {"altered": "sdist"},
                {"extra": "scripts/forgestra.egg-info/evil.py"},
                {"extra": "../escape"},
                {"duplicate": True},
            ):
                with self.assertRaises(Blocked):
                    self.inspect_fixture(root, **kwargs)

    def test_distribution_rejects_rehashed_wheel_changes_and_bad_record(self):
        with private_output_workspace() as root:
            for kwargs in ({"altered": "wheel"}, {"bad_record": True}):
                with self.assertRaises(Blocked):
                    self.inspect_fixture(root, **kwargs)

    def test_empty_inner_log_exports_finite_failed_receipt(self):
        import public_checks

        with private_output_workspace() as root:
            directory = root / ".tools/pr02-results"
            directory.mkdir(parents=True)
            (directory / "report.json").write_text("{}")
            (directory / "regressions.log").write_text("")
            with patch.object(public_checks, "ROOT", root), patch.object(
                p, "absent_private"
            ), patch.object(p, "containment"), patch.object(p, "inventory", return_value={}), patch(
                "forgestra.verification.validate_source"
            ), patch(
                "subprocess.run"
            ):
                self.assertEqual(public_checks.main(), 1)
            summary = json.loads((root / ".tools/public-results/upload/summary.json").read_text())
            self.assertEqual(summary["status"], "FAILED")
            self.assertEqual(summary["tests"], 0)
            self.assertEqual(
                set(p.validate_upload(root / ".tools/public-results/upload")), set(p.UPLOAD)
            )

    def test_unlisted_candidate_bytes_cannot_hide_outside_manifest(self):
        with private_output_workspace() as root:
            (root / "config").mkdir()
            (root / "README.md").write_text("authored public fixture")
            (root / "config/public-source.json").write_text(
                json.dumps(
                    {"profile": p.PUBLIC, "paths": ["README.md", "config/public-source.json"]}
                )
            )
            self.assertEqual(len(p.inventory(root)), 2)
            (root / "unlisted-private.txt").write_text("synthetic-private-sentinel")
            with self.assertRaises(Blocked):
                p.inventory(root)

    def test_public_fixture_has_explicit_authored_origin(self):
        value = p.containment(ROOT)
        self.assertEqual(len(value["python_entry_points"]), 18)
        self.assertEqual(len(value["workflows"]), 14)

    def test_missing_and_altered_public_fixture_deny(self):
        with private_output_workspace() as root:
            with self.assertRaises((OSError, Blocked)):
                p.containment(root)
            path = root / "tests/fixtures/public/containment.json"
            path.parent.mkdir(parents=True)
            data = (ROOT / "tests/fixtures/public/containment.json").read_bytes()
            path.write_bytes(data)
            self.assertEqual(p.containment(root), p.containment(ROOT))
            path.write_bytes(data + b" ")
            with self.assertRaises(Blocked):
                p.containment(root)

    def test_public_profile_requires_archive_physically_absent(self):
        with private_output_workspace() as root:
            p.absent_private(root)
            (root / "docs/audit").mkdir(parents=True)
            with self.assertRaises(Blocked):
                p.absent_private(root)

    def test_private_missing_or_tampered_archives_deny(self):
        with private_output_workspace() as root:
            manifest: dict[str, Any] = {"profile": PROFILE, "files": {}}
            with self.assertRaises(Blocked):
                replay(root, manifest)
            for name in sorted(REQUIRED):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                # Synthetic byte-preservation fixture, not a successful audit/run.
                path.write_bytes(b"authored-private-preservation-test\n")
                manifest["files"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
            receipt = replay(root, manifest)
            self.assertEqual(receipt["status"], "VERIFIED_BYTES")
            self.assertFalse(p.valid_summary(receipt))
            next(iter(root.rglob("verification.json"))).write_bytes(b"altered")
            with self.assertRaises(Blocked):
                replay(root, manifest)

    def summary(self, status="PASSED_LOCAL"):
        return {
            "profile": p.PUBLIC,
            "status": status,
            "source_sha256": "0" * 64,
            "tests": 1,
            "checks": [{"name": n, "status": "PASSED"} for n in p.CHECKS],
            "publication": "BLOCKED",
            "private_replay": "NOT_RUN",
            "live": "NOT_RUN",
            "reason": "NONE",
        }

    def test_profiles_and_receipts_cannot_substitute(self):
        value = self.summary()
        self.assertTrue(p.valid_summary(value))
        value["profile"] = PROFILE
        self.assertFalse(p.valid_summary(value))
        with private_output_workspace() as root:
            with self.assertRaises(Blocked):
                replay(root, self.summary())

    def test_zero_tests_and_approval_forgery_cannot_pass(self):
        value = self.summary()
        for field, replacement in (
            ("tests", 0),
            ("tests", True),
            ("publication", "APPROVED"),
            ("private_replay", "VERIFIED_BYTES"),
            ("checks", []),
        ):
            bad = copy.deepcopy(value)
            bad[field] = replacement
            self.assertFalse(p.valid_summary(bad))
        self.assertEqual(run_suite(unittest.TestSuite())["status"], "FAILED")
        self.assertEqual(readiness("A")["publication"], "BLOCKED")

    def test_projection_rejects_private_inputs_and_case_aliases(self):
        with private_output_workspace() as root:
            path = root / "config/public-source.json"
            path.parent.mkdir()
            for names in (
                ["docs/audit/a.md"],
                ["A.md", "a.md"],
                ["../secret"],
                ["OWNER_DECISIONS.md"],
            ):
                path.write_text(json.dumps({"profile": p.PUBLIC, "paths": names}), encoding="utf-8")
                with self.assertRaises(Blocked):
                    p.source_paths(root)

    def test_links_check_projection_case_and_anchors(self):
        with private_output_workspace() as root:
            (root / "README.md").write_text("[ok](Guide.md#supported)\n", encoding="utf-8")
            (root / "Guide.md").write_text("# Supported\n", encoding="utf-8")
            self.assertEqual(p.links(root, ["README.md", "Guide.md"])["status"], "PASSED")
            self.assertEqual(p.links(root, ["README.md"])["status"], "FAILED")
            (root / "README.md").write_text(
                "[bad](guide.md#supported) [bad](Guide.md#absent)", encoding="utf-8"
            )
            self.assertEqual(len(p.links(root, ["README.md", "Guide.md"])["errors"]), 2)

    def test_complete_upload_allowlist_for_success_and_failure(self):
        with private_output_workspace() as root:
            for index, status in enumerate(("PASSED_LOCAL", "FAILED")):
                summary = self.summary(status)
                if status == "FAILED":
                    summary.update(tests=0, checks=[], reason="PUBLIC_CHECK_FAILED")
                target = root / str(index)
                files = (
                    {}
                    if status == "FAILED"
                    else {
                        n: {"sha256": "0" * 64, "bytes": 1} for n in ("core.whl", "source.tar.gz")
                    }
                )
                p.export(
                    target,
                    summary,
                    {"profile": p.PUBLIC, "files": files, "license_approval": "PENDING"},
                    sbom(ROOT),
                )
                self.assertEqual(set(p.validate_upload(target)), set(p.UPLOAD))
                artifact = target / "artifacts.json"
                original = artifact.read_bytes()
                artifact.write_text('{"private_path":"synthetic-private-path"}')
                with self.assertRaises(Blocked):
                    p.validate_upload(target)
                artifact.write_bytes(original)
                (target / "raw.log").write_text("private-path-or-token-must-not-upload")
                with self.assertRaises(Blocked):
                    p.validate_upload(target)

    def test_failure_output_never_copies_arbitrary_child_details(self):
        with private_output_workspace() as root:
            summary = self.summary("FAILED")
            summary["reason"] = "synthetic-private-path-or-token"
            with self.assertRaises(Blocked):
                p.export(
                    root / "upload",
                    summary,
                    {"profile": p.PUBLIC, "files": {}, "license_approval": "PENDING"},
                    sbom(ROOT),
                )
