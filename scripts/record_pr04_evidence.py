"""PR 04 offline fixture gate; accepted PR 01/02/03 artifacts remain immutable."""

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


def accepted_matches(baseline, files):
    prefixes = tuple("docs/engineering/evidence/pr-0" + str(i) + "/" for i in (1, 2, 3))
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


def valid_repair(document):
    """Validate supporting fixture facts independently of the child's summary."""
    from forgestra.repair import CHECK, CHECKS_HASH, FIX, SEED, digest, policy_hash

    try:
        if not isinstance(document, dict):
            return False
        record = document["approved_repair"]
        tests = record["tests"]
        counts = {
            "status": "PASSED",
            "collected": 3,
            "tests": 3,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "expected_failures": 0,
            "unexpected_successes": 0,
        }
        proposal = record["proposal"]
        return (
            document["status"] == "PASSED_LOCAL"
            and document["mode"] == "AUTHORED_FIXTURE_ONLY"
            and document["original_preserved"] is True
            and document["duplicate_same_run"] is True
            and document["remote_pr"] == "NOT_RUN"
            and document["privileged_automation"] == "DISABLED"
            and record["status"] == "VALIDATED_LOCAL"
            and record["publication"] == "BLOCKED"
            and record["remote_pr"] == "NOT_RUN"
            and record["auto_merge"] is False
            and tests == counts
            and all(type(tests[k]) is int for k in counts if k != "status")
            and type(record["check_exit_code"]) is int
            and record["check_exit_code"] == 0
            and record["check_argv"] == [sys.executable, "-I", "-c", CHECK]
            and record["checks_sha256"] == CHECKS_HASH
            and record["policy_sha256"] == policy_hash()
            and record["candidate_files"]
            == {
                name: digest((FIX if name == "src/arithmetic.py" else text).encode())
                for name, text in SEED.items()
            }
            and record["plan_sha256"] == record["idempotency_key"]
            and record["tested_commit"] != record["input_commit"]
            and proposal
            == {
                "kind": "OFFLINE_PR_PROPOSAL",
                "head_sha": record["tested_commit"],
                "base_sha": record["input_commit"],
                "remote": "NOT_RUN",
                "publication": "BLOCKED",
            }
            and record["diff"] == [{"operation": "modify", "path": "src/arithmetic.py"}]
            and document["unapproved"]
            == {
                "status": "BLOCKED",
                "publication": "BLOCKED",
                "side_effects": [],
            }
            and document["budget"]["status"] == "BLOCKED"
            and document["budget"]["reason_code"] == "BUDGET_EXHAUSTED"
            and document["failed_checks"]["status"] == "VALIDATION_FAILED"
            and document["failed_checks"]["publication"] == "BLOCKED"
            and document["failed_checks"]["check_exit_code"] == 1
            and document["failed_checks"]["tests"]["status"] == "FAILED"
            and document["failed_checks"]["tests"]["failures"] == 1
            and "proposal" not in document["failed_checks"]
        )
    except (KeyError, TypeError, ValueError):
        return False


def repair_acceptance():
    from bootstrap import environment
    from forgestra_safety import strict_json_loads

    sys.path.insert(0, str(ROOT / "tests"))
    from test_pr04 import acceptance

    result = acceptance()
    python = ROOT / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    command = subprocess.run(
        [str(python), "-I", "-m", "forgestra", "repair"],
        cwd=ROOT,
        env=environment(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )
    document = strict_json_loads(command.stdout)
    blocked = (
        command.returncode == 1
        and isinstance(document, dict)
        and document.get("status") == "BLOCKED"
        and document.get("reason_code") == "RUNTIME_REPAIR_DISABLED"
        and document.get("privileged_automation") == "DISABLED"
        and document.get("publication") == "BLOCKED"
        and document.get("target_execution") == "DISABLED"
    )
    result["installed_runtime_denial"] = {
        "status": "PASSED" if blocked else "FAILED",
        "exit_code": command.returncode,
        "result": document,
    }
    if not blocked or not valid_repair(result):
        result["status"] = "FAILED"
    return result


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

    evidence = ROOT / "docs/engineering/evidence/pr-04"
    baseline = strict_json_loads((evidence / "baseline.json").read_text(encoding="utf-8"))

    def snapshot():
        files = source_hashes("pr-04")
        files["docs/engineering/evidence/pr-04/baseline.json"] = digest(evidence / "baseline.json")
        files["docs/engineering/evidence/pr-04/implementation-diagnostics.json"] = digest(
            evidence / "implementation-diagnostics.json"
        )
        files["docs/engineering/evidence/pr-04/review-baseline.json"] = digest(
            evidence / "review-baseline.json"
        )
        files["docs/engineering/evidence/pr-04/review-reproduction.json"] = digest(
            evidence / "review-reproduction.json"
        )
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
        and before == after
        and preserved
        and audits
    )
    write_artifact(
        evidence, "tested-files.json", (json.dumps(after, sort_keys=True, indent=2) + "\n").encode()
    )
    manifest_hash = digest(evidence / "tested-files.json")
    for name, artifact in (("installed-cli.json", cli), ("repair-fixture.json", repair)):
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
            }
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
