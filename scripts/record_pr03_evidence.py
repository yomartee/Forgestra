"""Local PR 03 gate. Preserve accepted PR 01/02 evidence; never call a provider."""

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import uuid
import zipfile
import tempfile
import hashlib
import re
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))


def baseline_matches(baseline, files, section):
    """Require complete accepted trees, never a vacuous or path-supplied digest loop."""
    prefixes: tuple[str, ...]
    if section == "accepted_evidence":
        prefixes = ("docs/engineering/evidence/pr-01/", "docs/engineering/evidence/pr-02/")
        required = {
            prefix + name
            for prefix in prefixes
            for name in ("verification.json", "tested-files.json")
        }
    elif section == "audit_documents":
        prefixes = ("docs/audit/",)
        required = {
            "docs/audit/Factory_Production_Open_Source_Audit.md",
            "docs/audit/Factory_Remediation_Roadmap.md",
        }
    else:
        return False
    expected = {name: value for name, value in files.items() if name.startswith(prefixes)}
    return (
        isinstance(baseline, dict)
        and isinstance(baseline.get(section), dict)
        and required <= set(expected)
        and expected == baseline[section]
    )


def valid_installed_result(document, expected_status, expected_assessment, improvement=False):
    """Validate real installed CLI output, including negative outcomes and nested evidence."""
    from forgestra.assessment import validate_assessment
    from forgestra_safety import Blocked

    try:
        if (
            not isinstance(document, dict)
            or type(document.get("schema_version")) is not int
            or document["schema_version"] != 1
            or document.get("status") != expected_status
            or document.get("provider")
            != ("NOT_RUN" if expected_status == "BLOCKED" else "OFFLINE_REPLAY")
            or document.get("live_provider") != "NOT_RUN"
            or document.get("privileged_automation") != "DISABLED"
            or document.get("completion_percentage", False) is not None
            or document.get("target_tests") != "UNTESTED"
            or document.get("side_effects") != []
            or document.get("assessment", False) != expected_assessment
        ):
            return False
        coverage = document["coverage"]
        identity = coverage["identity"]
        if (
            identity.get("git_commit", False) is not None
            or identity.get("kind") != "SAMPLED_SNAPSHOT"
            or not isinstance(identity.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", identity["sha256"])
        ):
            return False
        if expected_assessment is not None:
            validate_assessment(document["assessment"], coverage)
        if improvement:
            items = document["work_items"]
            if (
                document.get("operation") != "IMPROVEMENT_PLAN"
                or document.get("applied_changes") != []
                or document.get("publication") != "BLOCKED"
                or not isinstance(items, list)
                or len(items) != 1
                or items[0].get("finding_id") != "fixture-finding"
                or items[0].get("status") != "PROPOSED"
                or not re.fullmatch(r"[0-9a-f]{64}", items[0].get("key", ""))
            ):
                return False
        return True
    except (ValueError, TypeError, KeyError, AttributeError, Blocked):
        return False


def installed_cli():
    """Required installed-package smoke on authored fixtures; never run target code."""
    from bootstrap import environment
    from forgestra.providers import sanitized
    from forgestra_safety import strict_json_loads

    python = ROOT / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    checks = []
    with tempfile.TemporaryDirectory(prefix="forgestra-pr03-installed-") as temporary:
        base = Path(temporary)
        (base / "README.md").write_text("Synthetic evidence\n", encoding="utf-8")
        (base / "tests").mkdir()
        ref = {
            "path": "README.md",
            "sha256": hashlib.sha256((base / "README.md").read_bytes()).hexdigest(),
            "start": 1,
            "end": 1,
        }
        assessment = {
            "schema_version": 1,
            "findings": [
                {
                    "id": "fixture-finding",
                    "title": "Advisory fixture",
                    "severity": "LOW",
                    "evidence": [ref],
                    "details": {
                        "summary": "Synthetic only",
                        "scope_gaps": [{"description": "Untested fixture", "evidence": [ref]}],
                    },
                }
            ],
            "limitations": ["Offline fixture"],
        }
        replay = base / "replay.json"
        replay.write_text(
            json.dumps(
                {
                    "kind": "OFFLINE_REPLAY",
                    "response": {
                        "type": "message",
                        "stop_reason": "end_turn",
                        "content": [{"type": "text", "text": json.dumps(assessment)}],
                    },
                }
            ),
            encoding="utf-8",
        )
        outage = base / "outage.json"
        outage.write_text(
            json.dumps({"kind": "OFFLINE_REPLAY", "response": {"type": "error"}}), encoding="utf-8"
        )
        cases = (
            ("default-assessment", ["assess", str(base)], 1, "BLOCKED", None, False),
            (
                "nested-assessment",
                ["assess", str(base), "--replay", str(replay)],
                0,
                "SUCCESS_WITH_FINDINGS",
                assessment,
                False,
            ),
            (
                "improvement-plan",
                ["improve", str(base), "--replay", str(replay)],
                0,
                "SUCCESS_WITH_FINDINGS",
                assessment,
                True,
            ),
            (
                "audit-outage",
                ["audit", str(base), "--replay", str(outage)],
                1,
                "ERROR",
                None,
                False,
            ),
        )
        for name, args, code, status, expected, improvement in cases:
            argv = [str(python), "-I", "-m", "forgestra", *args]
            command = subprocess.run(
                argv,
                cwd=base,
                env=environment(),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                check=False,
            )
            document = strict_json_loads(command.stdout)
            passed = command.returncode == code and valid_installed_result(
                document, status, expected, improvement
            )
            checks.append(
                {
                    "name": name,
                    "argv": [a.replace(str(base), "<fixture>") for a in argv],
                    "exit_code": command.returncode,
                    "status": "PASSED" if passed else "FAILED",
                    "result": sanitized(document),
                }
            )
    return {
        "status": (
            "PASSED_LOCAL"
            if all(c["status"] == "PASSED" for c in checks) and len(checks) == 4
            else "FAILED"
        ),
        "mode": "INSTALLED_PACKAGE_OFFLINE_SYNTHETIC_FIXTURES",
        "checks": checks,
        "live_provider": "NOT_RUN",
        "privileged_automation": "DISABLED",
    }


def main():
    from bootstrap import environment
    from forgestra_safety import strict_json_loads
    from forgestra_safety import Blocked
    from record_pr02_evidence import (
        REQUIRED_CHECKS,
        clean_install,
        digest,
        source_hashes,
        valid_report,
        write_artifact,
    )

    evidence = ROOT / "docs/engineering/evidence/pr-03"
    baseline = strict_json_loads((evidence / "baseline.json").read_text(encoding="utf-8"))

    def snapshot():
        files = source_hashes("pr-03")
        for name in (
            "baseline.json",
            "accepted-pr02-verification.json",
            "accepted-pr02-tested-files.json",
            "review-baseline.json",
            "review-reproduction.json",
        ):
            files["docs/engineering/evidence/pr-03/" + name] = digest(evidence / name)
        return files

    before = snapshot()
    run_id = str(uuid.uuid4())
    write_artifact(
        evidence, "verification.json", json.dumps({"status": "RUNNING", "run_id": run_id}).encode()
    )
    report: dict[str, Any] = {"status": "FAILED", "checks": [], "run_id": run_id}
    clean: dict[str, Any] = {"status": "NOT_RUN"}
    cli: dict[str, Any] = {"status": "NOT_RUN", "checks": []}
    complete = False
    try:
        if not (
            baseline_matches(baseline, before, "accepted_evidence")
            and baseline_matches(baseline, before, "audit_documents")
        ):
            raise Blocked("BLOCKED: accepted evidence baseline incomplete or changed")
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
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        StopIteration,
        subprocess.SubprocessError,
        SyntaxError,
        Blocked,
        zipfile.BadZipFile,
    ):
        complete = False
    after = snapshot()
    preserved = baseline_matches(baseline, after, "accepted_evidence")
    audits = baseline_matches(baseline, after, "audit_documents")
    passed = (
        complete
        and clean["status"] == "PASSED"
        and cli["status"] == "PASSED_LOCAL"
        and before == after
        and preserved
        and audits
    )
    manifest = (json.dumps(after, indent=2, sort_keys=True) + "\n").encode()
    write_artifact(evidence, "tested-files.json", manifest)
    cli.update(run_id=run_id, tested_manifest_sha256=digest(evidence / "tested-files.json"))
    write_artifact(evidence, "installed-cli.json", (json.dumps(cli, indent=2) + "\n").encode())
    checks = report.get("checks", [])
    for check in checks if isinstance(checks, list) else []:
        if (
            isinstance(check, dict)
            and isinstance(check.get("name"), str)
            and check["name"] in REQUIRED_CHECKS
        ):
            name = check["name"] + ".log"
            write_artifact(evidence, name, (ROOT / ".tools/pr02-results" / name).read_bytes())
    report.update(
        status="PASSED_LOCAL" if passed else "FAILED",
        recorded_at_utc=datetime.now(timezone.utc).isoformat(),
        source_unchanged_during_checks=before == after,
        tested_manifest_sha256=digest(evidence / "tested-files.json"),
        baseline_sha256=digest(evidence / "baseline.json"),
        accepted_evidence_unchanged=preserved,
        audit_documents_unchanged=audits,
        clean_install=clean,
        installed_cli={
            "status": cli["status"],
            "checks": len(cli["checks"]),
            "artifact_sha256": digest(evidence / "installed-cli.json"),
        },
        git_commit=None,
        live_provider="NOT_RUN",
        hosted_workflows="NOT_RUN",
        privileged_automation="DISABLED",
        provider_action_release_compatibility="NOT_RUN",
        provider_action_input_contract="STATIC_SUBSET_TESTED",
    )
    write_artifact(evidence, "verification.json", (json.dumps(report, indent=2) + "\n").encode())
    print(
        json.dumps(
            {
                "status": report["status"],
                "source_stable": before == after,
                "accepted_evidence_unchanged": preserved,
            }
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
