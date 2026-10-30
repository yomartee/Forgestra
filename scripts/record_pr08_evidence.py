"""PR 08 local synchronization gate. Preserve accepted PR 01–07 evidence."""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import uuid
import zipfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]


def accepted_matches(baseline, files):
    prefixes = tuple("docs/engineering/evidence/pr-0" + str(i) + "/" for i in (1, 2, 3, 4, 5, 6, 7))
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


def diagnostic_report(candidate, output, run_id):
    """Retain failed child results only when their run ID and logs agree."""
    from record_pr02_evidence import REQUIRED_CHECKS, digest

    try:
        checks = candidate["checks"]
        return (
            candidate["run_id"] == run_id
            and candidate["status"] in {"PASSED_LOCAL", "FAILED"}
            and candidate["privileged_automation"] == "DISABLED"
            and isinstance(checks, list)
            and len(checks) == len(REQUIRED_CHECKS)
            and {c["name"] for c in checks} == REQUIRED_CHECKS
            and all(
                c["status"] in {"PASSED", "FAILED"}
                and type(c["exit_code"]) is int
                and isinstance(c["argv"], list)
                and bool(c["argv"])
                and all(isinstance(a, str) for a in c["argv"])
                and digest(output / (c["name"] + ".log")) == c["log_sha256"]
                for c in checks
            )
        )
    except (KeyError, TypeError, ValueError, OSError):
        return False


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
    from record_pr05_evidence import adoption_acceptance, valid_adoption
    from pr06_web_validation import valid_web
    from pr07_creation_validation import acceptance, valid_acceptance
    from pr08_sync_validation import acceptance as sync_acceptance, valid_sync

    evidence = ROOT / "docs/engineering/evidence/pr-08"
    baseline = strict_json_loads((evidence / "baseline.json").read_text(encoding="utf-8"))

    def snapshot():
        files = source_hashes("pr-08")
        files["docs/engineering/evidence/pr-08/baseline.json"] = digest(evidence / "baseline.json")
        files["docs/engineering/evidence/pr-08/implementation-diagnostics.json"] = digest(
            evidence / "implementation-diagnostics.json"
        )
        for name in ("review-baseline.json", "review-reproduction.json"):
            files["docs/engineering/evidence/pr-08/" + name] = digest(evidence / name)
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
    web: dict[str, Any] = {"status": "NOT_RUN"}
    creation: dict[str, Any] = {"status": "NOT_RUN"}
    sync: dict[str, Any] = {"status": "NOT_RUN"}
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
        if diagnostic_report(candidate, output, run_id):
            report = candidate
        if complete:
            report = candidate
            clean = clean_install()
            cli = installed_cli()
            repair = repair_acceptance()
            adoption = adoption_acceptance()
            creation = acceptance()
            web = creation.pop("web")
            sync = sync_acceptance()
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
        sqlite3.Error,
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
        and valid_web(web)
        and valid_acceptance(creation, web)
        and valid_sync(sync)
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
        ("web-fixture.json", web),
        ("creation-fixture.json", creation),
        ("sync-fixture.json", sync),
    ):
        artifact.update(run_id=run_id, tested_manifest_sha256=manifest_hash)
        write_artifact(evidence, name, (json.dumps(artifact, indent=2) + "\n").encode())
    if web.get("status") == "PASSED_LOCAL":
        write_artifact(
            evidence, "web-browser.png", (ROOT / ".tools/pr06-web-results/browser.png").read_bytes()
        )
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
        web_generator={
            "status": web["status"],
            "artifact_sha256": digest(evidence / "web-fixture.json"),
        },
        creation_fixture={
            "status": creation["status"],
            "artifact_sha256": digest(evidence / "creation-fixture.json"),
        },
        sync_fixture={
            "status": sync["status"],
            "artifact_sha256": digest(evidence / "sync-fixture.json"),
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
                "web_generator": web["status"],
                "creation_fixture": creation["status"],
                "sync_fixture": sync["status"],
            }
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
