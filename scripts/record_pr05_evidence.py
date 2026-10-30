"""PR 05 offline adoption gate; accepted PR 01/02/03/04 artifacts remain immutable."""

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import uuid
import zipfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))


def valid_fixture_output(argv, code, stdout):
    import re

    if (
        type(code) is not int
        or code != 0
        or not isinstance(stdout, str)
        or len(stdout) > 65536
        or not isinstance(argv, list)
        or not argv
        or any(not isinstance(a, str) or not a for a in argv)
        or Path(argv[0]).name.casefold() not in {"node", "node.exe"}
    ):
        return False
    text = stdout.replace("\r\n", "\n")
    if argv[1:] == ["build.js"]:
        return text == "authored fixture build\n"
    if argv[1:] != ["--test", "--test-reporter=tap", "test.js"]:
        return False
    number = r"[0-9]+(?:\.[0-9]+)?"
    # Exact grammar for the pinned reporter and this single literal test file.
    return (
        re.fullmatch(
            r"TAP version 13\n# Subtest: test\.js\nok 1 - test\.js\n  ---\n"
            + r"  duration_ms: "
            + number
            + r"\n  type: 'test'\n  \.\.\.\n"
            + r"1\.\.1\n# tests 1\n# suites 0\n# pass 1\n# fail 0\n"
            + r"# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms "
            + number
            + r"\n",
            text,
        )
        is not None
    )


def valid_adoption(record):
    """A summary cannot substitute for filesystem and installed-command evidence."""
    import re
    import shutil

    from forgestra.adoption import (
        RECEIPT,
        VERSIONS,
        FIXTURE_CONFIGURATION,
        assets,
        receipt,
        digest,
        encoded,
    )
    from forgestra_safety import Blocked

    try:
        if not isinstance(record, dict):
            return False
        expected_workspaces = {
            "status": "PLANNED_LOCAL",
            "execution": "BLOCKED",
            "remote": "NOT_RUN",
            "workspaces": [
                {
                    "setup": ["npm", "ci"],
                    "lockfile": "package-lock.json",
                    **FIXTURE_CONFIGURATION["workspaces"][0],
                    "source": "explicit",
                }
            ],
        }
        for stage, action, version, installed in (
            ("install", "install", VERSIONS[0], None),
            ("repeat", "install", VERSIONS[0], VERSIONS[0]),
            ("upgrade", "upgrade", VERSIONS[1], VERSIONS[0]),
            ("uninstall", "uninstall", VERSIONS[0], VERSIONS[1]),
        ):
            proposal = record[stage]["plan"]
            if not isinstance(proposal, dict):
                return False
            material = {k: v for k, v in proposal.items() if k != "plan_sha256"}
            old_version = proposal["installed_factory_version"]
            old = (
                {}
                if old_version is None
                else {**assets(old_version), RECEIPT: receipt(old_version)}
            )
            new = {} if action == "uninstall" else {**assets(version), RECEIPT: receipt(version)}
            changes = []
            for name in sorted(set(old) | set(new)):
                if old.get(name) != new.get(name):
                    changes.append(
                        {
                            "path": name,
                            "operation": (
                                "delete"
                                if name not in new
                                else "add" if name not in old else "modify"
                            ),
                            "before_sha256": digest(old[name]) if name in old else None,
                            "after_sha256": digest(new[name]) if name in new else None,
                        }
                    )
            if (
                type(proposal["schema_version"]) is not int
                or proposal["schema_version"] != 1
                or proposal["status"] != ("NO_OP" if stage == "repeat" else "PLANNED_LOCAL")
                or proposal["installed_factory_version"] != installed
                or proposal["plan_sha256"] != digest(encoded(material))
                or not re.fullmatch(r"[0-9a-f]{64}", proposal["input_sha256"])
                or stage != "repeat"
                and not re.fullmatch(r"[0-9a-f]{64}", record[stage]["output_sha256"])
                or proposal["action"] != action
                or proposal["proposed_factory_version"] != version
                or proposal["changes"] != changes
                or proposal["prerequisites"] != []
                or proposal["conflicts"] != []
                or proposal["publication"] != "BLOCKED"
                or proposal["execution"] != "BLOCKED"
                or proposal["remote"] != "NOT_RUN"
                or proposal["asset_catalog"] != "UNRELEASED_AUTHORED_FIXTURE"
                or proposal["ownership_authority"] != "UNTRUSTED_DECLARATION_REQUIRES_REVIEW"
                or proposal["workspaces"] != expected_workspaces
                or proposal["privileged_automation"] != "DISABLED"
                or proposal["side_effects"] != []
                or proposal["target_tests"] != "NOT_RUN"
                or proposal["default_branch"]
                != {
                    "name": "team/trunk",
                    "source": "LOCAL_CACHED_ORIGIN_HEAD",
                    "live_verified": False,
                }
            ):
                return False
        if (
            record["repeat"]["plan"]["input_sha256"] != record["install"]["output_sha256"]
            or record["upgrade"]["plan"]["input_sha256"] != record["install"]["output_sha256"]
            or record["uninstall"]["plan"]["input_sha256"] != record["upgrade"]["output_sha256"]
        ):
            return False
        node = shutil.which("node")
        for stage in ("clean", "installed", "upgraded", "uninstalled"):
            commands = [c for c in record["fixture_commands"] if c["stage"] == stage]
            if [c["argv"] for c in commands] != [
                [node, "build.js"],
                [node, "--test", "--test-reporter=tap", "test.js"],
            ]:
                return False
            if any(
                type(c["exit_code"]) is not int
                or not all(
                    re.fullmatch(r"[0-9a-f]{64}", c[k]) for k in ("stdout_sha256", "stderr_sha256")
                )
                or not isinstance(c["stdout"], str)
                or digest(c["stdout"].encode()) != c["stdout_sha256"]
                or not valid_fixture_output(c["argv"], c["exit_code"], c["stdout"])
                for c in commands
            ):
                return False
        negatives = record["installed_negative_plans"]
        if not isinstance(negatives, list) or len(negatives) != 4:
            return False
        expected_negative = {
            "missing-test": ("REVIEW_REQUIRED", "TARGET_TEST_COMMAND_REQUIRED"),
            "missing-default-branch": ("REVIEW_REQUIRED", "DEFAULT_BRANCH_UNAVAILABLE_NO_FALLBACK"),
            "invalid-command": ("BLOCKED", None),
            "redacted-plan": ("BLOCKED", None),
        }
        if {n["name"] for n in negatives} != set(expected_negative):
            return False
        for negative in negatives:
            status, reason = expected_negative[negative["name"]]
            document = negative["result"]
            if (
                type(negative["exit_code"]) is not int
                or negative["exit_code"] != 1
                or negative["status"] != "PASSED"
                or document["status"] != status
            ):
                return False
            if reason is not None:
                if (
                    reason not in document["prerequisites"]
                    or document["execution"] != "BLOCKED"
                    or document["side_effects"] != []
                    or document["publication"] != "BLOCKED"
                ):
                    return False
                if (
                    negative["name"] == "missing-default-branch"
                    and document["default_branch"]["name"] is not None
                ):
                    return False
            elif document.get("reason_code") != "INVALID_INPUT_OR_CONFIGURATION":
                return False
        return (
            record["status"] == "PASSED_LOCAL"
            and record["original_preserved"] is True
            and record["uninstall_preserved"] is True
            and record["privileged_automation"] == "DISABLED"
            and record["publication"] == "BLOCKED"
            and record["remote"] == "NOT_RUN"
            and all(
                record[name]["status"] == "APPLIED_FIXTURE_ONLY"
                and record[name]["plan"]["conflicts"] == []
                and record[name]["plan"]["execution"] == "BLOCKED"
                for name in ("install", "upgrade", "uninstall")
            )
            and record["repeat"]["status"] == "NO_OP"
            and record["repeat"]["plan"]["changes"] == []
            and record["installed_plan"] == record["install"]["plan"]
            and record["installed_plan"]["side_effects"] == []
            and record["installed_plan"]["publication"] == "BLOCKED"
            and record["installed_denial"]
            == {
                "status": "BLOCKED",
                "reason_code": "RUNTIME_INSTALL_DISABLED",
                "privileged_automation": "DISABLED",
                "publication": "BLOCKED",
                "target_execution": "DISABLED",
            }
            and len(record["fixture_commands"]) == 8
            and all(
                c["exit_code"] == 0 and c["status"] == "PASSED" for c in record["fixture_commands"]
            )
            and {c["stage"] for c in record["fixture_commands"]}
            == {"clean", "installed", "upgraded", "uninstalled"}
            and record["original_unchanged_after_installed_cli"] is True
        )
    except (KeyError, TypeError, ValueError, Blocked):
        return False


def adoption_acceptance():
    import copy
    import hashlib
    import shutil

    from bootstrap import environment
    from forgestra.adoption import (
        FIXTURE_CONFIGURATION,
        SEED,
        VERSIONS,
        local_install_fixture,
        read_tree,
    )
    from forgestra_safety import strict_json_loads, Blocked

    sys.path.insert(0, str(ROOT / "tests"))
    from test_pr05 import acceptance

    record = acceptance()
    python = ROOT / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    node = shutil.which("node")
    if not node:
        raise Blocked("BLOCKED: fixture Node runtime missing")
    with local_install_fixture() as control:
        env = environment()
        env.update(
            HOME=str(control.parent), USERPROFILE=str(control.parent), NODE_OPTIONS="", NODE_PATH=""
        )

        def run(argv, cwd):
            return subprocess.run(
                argv,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                check=False,
            )

        version = run([node, "--version"], control.parent)
        if version.returncode or version.stdout.strip() != "v24.14.0":
            raise Blocked("BLOCKED: incompatible authored fixture toolchain")
        configuration = control.parent / "fixture-configuration.json"
        configuration.write_text(
            json.dumps(
                {
                    "version": 1,
                    "capabilities": {},
                    "targets": [],
                    **FIXTURE_CONFIGURATION,
                }
            ),
            encoding="utf-8",
        )
        original = read_tree(control.current)
        command = run(
            [
                str(python),
                "-I",
                "-m",
                "forgestra",
                "adopt",
                str(control.current),
                "--config",
                str(configuration),
            ],
            control.parent,
        )
        if command.returncode != 0:
            raise Blocked("BLOCKED: installed adoption plan failed")
        record["installed_plan"] = strict_json_loads(command.stdout)
        denied = run([str(python), "-I", "-m", "forgestra", "install"], control.parent)
        if denied.returncode != 1:
            raise Blocked("BLOCKED: installed runtime denial failed")
        record["installed_denial"] = strict_json_loads(denied.stdout)
        negatives = []
        head = control.current / ".git/refs/remotes/origin/HEAD"
        cached_head = head.read_bytes()
        original_config = configuration.read_bytes()
        for name in ("missing-test", "missing-default-branch", "invalid-command", "redacted-plan"):
            negative_config = copy.deepcopy(FIXTURE_CONFIGURATION)
            canary = "review-redacted-branch-05"
            if name == "missing-test":
                del negative_config["workspaces"][0]["commands"]["test"]
            elif name == "missing-default-branch":
                head.unlink()
            elif name == "invalid-command":
                negative_config["workspaces"][0]["commands"]["test"] = ["sh", "-c", "unused"]
            else:
                head.write_bytes(("ref: refs/remotes/origin/" + canary + "\n").encode())
                env["FORGESTRA_REVIEW_TOKEN"] = canary
            configuration.write_text(json.dumps(negative_config), encoding="utf-8")
            child = run(
                [
                    str(python),
                    "-I",
                    "-m",
                    "forgestra",
                    "adopt",
                    str(control.current),
                    "--config",
                    str(configuration),
                ],
                control.parent,
            )
            document = strict_json_loads(child.stdout)
            expected = "REVIEW_REQUIRED" if name.startswith("missing-") else "BLOCKED"
            passed = (
                child.returncode == 1
                and document.get("status") == expected
                and canary not in child.stdout
            )
            negatives.append(
                {
                    "name": name,
                    "exit_code": child.returncode,
                    "status": "PASSED" if passed else "FAILED",
                    "result": document,
                }
            )
            head.write_bytes(cached_head)
            configuration.write_bytes(original_config)
            env.pop("FORGESTRA_REVIEW_TOKEN", None)
        record["installed_negative_plans"] = negatives
        record["original_unchanged_after_installed_cli"] = original == read_tree(control.current)
        commands = []
        for stage in ("clean", "installed", "upgraded", "uninstalled"):
            if stage != "clean":
                action = {
                    "installed": "install",
                    "upgraded": "upgrade",
                    "uninstalled": "uninstall",
                }[stage]
                outcome = control.transition(
                    action, VERSIONS[1] if stage == "upgraded" else VERSIONS[0]
                )
                if outcome["status"] != "APPLIED_FIXTURE_ONLY":
                    raise Blocked("BLOCKED: authored transition failed")
            # Execute only these two reviewed literal files, after byte verification.
            if any((control.current / name).read_bytes() != data for name, data in SEED.items()):
                raise Blocked("BLOCKED: authored fixture changed")
            for argv in ([node, "build.js"], [node, "--test", "--test-reporter=tap", "test.js"]):
                child = run(argv, control.current)
                valid = valid_fixture_output(argv, child.returncode, child.stdout)
                commands.append(
                    {
                        "stage": stage,
                        "argv": argv,
                        "exit_code": child.returncode,
                        "status": "PASSED" if valid else "FAILED",
                        "stdout": child.stdout,
                        "stdout_sha256": hashlib.sha256(child.stdout.encode()).hexdigest(),
                        "stderr_sha256": hashlib.sha256(child.stderr.encode()).hexdigest(),
                    }
                )
        record["fixture_commands"] = commands
    if not valid_adoption(record):
        record["status"] = "FAILED"
    return record


def accepted_matches(baseline, files):
    prefixes = tuple("docs/engineering/evidence/pr-0" + str(i) + "/" for i in (1, 2, 3, 4))
    required = {
        prefix + name for prefix in prefixes for name in ("verification.json", "tested-files.json")
    }
    actual = {name: value for name, value in files.items() if name.startswith(prefixes)}
    return (
        isinstance(baseline, dict)
        and isinstance(baseline.get("accepted_evidence"), dict)
        and required <= set(actual)
        and actual == baseline["accepted_evidence"]
    )


def main():
    from bootstrap import environment
    from forgestra_safety import strict_json_loads, Blocked
    from record_pr02_evidence import (
        REQUIRED_CHECKS,
        clean_install,
        digest,
        source_hashes,
        valid_report,
        write_artifact,
    )
    from record_pr03_evidence import baseline_matches, installed_cli
    from record_pr04_evidence import repair_acceptance, valid_repair

    evidence = ROOT / "docs/engineering/evidence/pr-05"
    baseline = strict_json_loads((evidence / "baseline.json").read_text(encoding="utf-8"))

    def snapshot():
        files = source_hashes("pr-05")
        files["docs/engineering/evidence/pr-05/baseline.json"] = digest(evidence / "baseline.json")
        files["docs/engineering/evidence/pr-05/implementation-diagnostics.json"] = digest(
            evidence / "implementation-diagnostics.json"
        )
        for name in ("review-baseline.json", "review-reproduction.json"):
            files["docs/engineering/evidence/pr-05/" + name] = digest(evidence / name)
        return files

    before = snapshot()
    run_id = str(uuid.uuid4())
    write_artifact(
        evidence, "verification.json", json.dumps({"status": "RUNNING", "run_id": run_id}).encode()
    )
    report: dict[str, Any] = {"checks": [], "run_id": run_id}
    clean: dict[str, Any] = {"status": "NOT_RUN"}
    cli: dict[str, Any] = {"status": "NOT_RUN", "checks": []}
    repair: dict[str, Any] = {"status": "NOT_RUN"}
    adoption: dict[str, Any] = {"status": "NOT_RUN"}
    complete = False
    try:
        if not accepted_matches(baseline, before) or not baseline_matches(
            baseline, before, "audit_documents"
        ):
            raise Blocked("BLOCKED: accepted evidence changed")
        child = subprocess.run(
            [sys.executable, "-I", "scripts/ci.py", "--run-id", run_id],
            cwd=ROOT,
            env=environment(),
            timeout=600,
            check=False,
        )
        output = ROOT / ".tools/pr02-results"
        candidate = strict_json_loads((output / "report.json").read_text(encoding="utf-8"))
        complete = child.returncode == 0 and valid_report(candidate, output, run_id)
        if complete:
            report = candidate
            clean = clean_install()
            cli = installed_cli()
            repair = repair_acceptance()
            adoption = adoption_acceptance()
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        StopIteration,
        SyntaxError,
        Blocked,
        subprocess.SubprocessError,
        zipfile.BadZipFile,
    ):
        complete = False
    after = snapshot()
    preserved = accepted_matches(baseline, after)
    audits = baseline_matches(baseline, after, "audit_documents")
    passed = (
        complete
        and clean["status"] == "PASSED"
        and cli["status"] == "PASSED_LOCAL"
        and valid_repair(repair)
        and repair.get("installed_runtime_denial", {}).get("status") == "PASSED"
        and valid_adoption(adoption)
        and before == after
        and preserved
        and audits
    )
    write_artifact(
        evidence, "tested-files.json", (json.dumps(after, sort_keys=True, indent=2) + "\n").encode()
    )
    manifest_hash = digest(evidence / "tested-files.json")
    for name, artifact in (
        ("installed-cli.json", cli),
        ("repair-fixture.json", repair),
        ("adoption-fixture.json", adoption),
    ):
        artifact.update(run_id=run_id, tested_manifest_sha256=manifest_hash)
        write_artifact(evidence, name, (json.dumps(artifact, indent=2) + "\n").encode())
    for check in report["checks"]:
        if check["name"] in REQUIRED_CHECKS:
            name = check["name"] + ".log"
            write_artifact(evidence, name, (ROOT / ".tools/pr02-results" / name).read_bytes())
    report.update(
        status="PASSED_LOCAL" if passed else "FAILED",
        recorded_at_utc=datetime.now(timezone.utc).isoformat(),
        source_unchanged_during_checks=before == after,
        tested_manifest_sha256=manifest_hash,
        baseline_sha256=digest(evidence / "baseline.json"),
        accepted_evidence_unchanged=preserved,
        audit_documents_unchanged=audits,
        clean_install=clean,
        installed_cli={
            "status": cli["status"],
            "checks": len(cli["checks"]),
            "artifact_sha256": digest(evidence / "installed-cli.json"),
        },
        repair_fixture={
            "status": repair["status"],
            "artifact_sha256": digest(evidence / "repair-fixture.json"),
        },
        adoption_fixture={
            "status": adoption["status"],
            "artifact_sha256": digest(evidence / "adoption-fixture.json"),
        },
        git_commit=None,
        privileged_automation="DISABLED",
        live_provider="NOT_RUN",
        hosted_workflows="NOT_RUN",
        remote_pr="NOT_RUN",
        target_execution="DISABLED",
    )
    write_artifact(evidence, "verification.json", (json.dumps(report, indent=2) + "\n").encode())
    print(
        json.dumps(
            {
                "status": report["status"],
                "source_stable": before == after,
                "accepted_evidence_unchanged": preserved,
                "repair_fixture": repair["status"],
                "adoption_fixture": adoption["status"],
            }
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
