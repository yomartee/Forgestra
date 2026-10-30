"""PR 09 authored maintenance acceptance; no customer code or remote transport."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]


def scenario(kind="repair", content=None):
    from forgestra import repair, maintenance as m
    from forgestra_safety import strict_json_loads

    with repair.local_repair_fixture(kind) as control:
        engine = m.FixtureMaintenance(control)
        try:
            observation = engine.observe()
            observed = strict_json_loads(observation.payload)
            event = observed["event"]
            before = repair.files(control.source)
            selected = (
                content
                if content is not None
                else (repair.REFACTOR if kind == "refactor" else repair.FIX)
            )
            plan = control.plan(selected)
            grant = engine.approve(observation, plan)
            result = engine.run(observation, plan, grant)
            engine.close()
            engine = m.FixtureMaintenance(control)
            duplicate = engine.run(observation, plan, grant)
            attempts = engine.db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
            budget = control.journal.execute("SELECT attempts FROM budget").fetchone()[0]
            return {
                "event": event,
                "diagnostic": observed["diagnostic"],
                "original_files": before,
                "result": result,
                "replay": duplicate,
                "journal_rows": attempts,
                "repair_attempts": budget,
                "original_preserved": repair.files(control.source) == before,
            }
        finally:
            engine.close()


def acceptance():
    from forgestra import repair
    from forgestra_safety import Blocked, strict_json_loads

    from bootstrap import environment

    cases = {
        "repair": scenario(),
        "refactor": scenario("refactor"),
        "no_fix": scenario(content=repair.SEED["src/arithmetic.py"]),
        "failed_fix": scenario(content="def add(a, b):\n    return a * b\n"),
    }
    python = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    child = subprocess.run(
        [str(python), "-I", "-m", "forgestra", "maintain"],
        cwd=ROOT,
        env=environment(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )
    document = {
        "status": "PASSED_LOCAL",
        "mode": "AUTHORED_MAINTENANCE_FIXTURE",
        "cases": cases,
        "installed_cli": {"exit_code": child.returncode, "result": strict_json_loads(child.stdout)},
        "privileged_automation": "DISABLED",
        "remote_pr": "NOT_RUN",
        "live_provider": "NOT_RUN",
        "publication": "BLOCKED",
    }
    if not valid_maintenance(document):
        raise Blocked("BLOCKED: maintenance acceptance mismatch")
    return document


def valid_maintenance(document):
    from forgestra import repair, maintenance as m
    from forgestra_safety import Blocked, strict_json_loads

    try:
        cases = document["cases"]
        if (
            document["status"] != "PASSED_LOCAL"
            or document["mode"] != "AUTHORED_MAINTENANCE_FIXTURE"
            or set(cases) != {"repair", "refactor", "no_fix", "failed_fix"}
            or document["privileged_automation"] != "DISABLED"
            or document["remote_pr"] != "NOT_RUN"
            or document["live_provider"] != "NOT_RUN"
            or document["publication"] != "BLOCKED"
            or type(document["installed_cli"]["exit_code"]) is not int
            or document["installed_cli"]["exit_code"] != 1
            or document["installed_cli"]["result"] != m.runtime_maintenance()
        ):
            return False
        for name, case in cases.items():
            event, receipt = case["event"], case["result"]
            if m.review(event)["status"] != "REVIEW_REQUIRED":
                return False
            expected_kind = "refactor" if name == "refactor" else "repair"
            original = {**repair.SEED}
            if expected_kind == "refactor":
                original["src/arithmetic.py"] = repair.FIX
            diagnostic = case["diagnostic"]
            if (
                case["original_files"]
                != {n: repair.digest(v.encode()) for n, v in original.items()}
                or diagnostic["argv"] != [sys.executable, "-I", "-c", m.CHECK]
                or diagnostic["log"] != event["log"]
                or diagnostic["log_sha256"] != event["log_sha256"]
                or diagnostic["check_sha256"] != m.CHECK_SHA
                or diagnostic["result"] != strict_json_loads(event["log"])
                or diagnostic["files_sha256"] != case["original_files"]
                or type(diagnostic["exit_code"]) is not int
                or diagnostic["exit_code"] != (0 if expected_kind == "refactor" else 1)
            ):
                return False
            if (
                event["kind"] != expected_kind
                or event["changes"] != m.DIFF
                or receipt["observation"] != event
                or receipt["failure_fingerprint"] != m.fingerprint(event)
                or receipt["policy_sha256"] != m.policy_hash()
                or receipt["publication"] != "BLOCKED"
                or receipt["remote_pr"] != "NOT_RUN"
                or type(receipt["attempts"]) is not int
                or receipt["attempts"] != 1
                or type(case["journal_rows"]) is not int
                or case["journal_rows"] != 1
                or type(case["repair_attempts"]) is not int
                or case["repair_attempts"] != 1
                or case["original_preserved"] is not True
                or case["replay"]
                != {"status": "DUPLICATE", "receipt": receipt, "execution": "DISABLED"}
            ):
                return False
            result = receipt["repair"]
            if (
                result["publication"] != "BLOCKED"
                or result["remote_pr"] != "NOT_RUN"
                or result["auto_merge"] is not False
                or result["mode"] != "AUTHORED_FIXTURE_ONLY"
                or result["input_commit"] != event["head_sha"]
                or result["policy_sha256"] != repair.policy_hash()
                or result["checks_sha256"] != repair.CHECKS_HASH
                or not isinstance(result["verification_signature"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", result["verification_signature"])
                or not re.fullmatch(r"[0-9a-f]{64}", result["target_id"])
                or not re.fullmatch(r"[0-9a-f]{64}", result["plan_sha256"])
                or result["idempotency_key"] != result["plan_sha256"]
                or str(uuid.UUID(result["run_id"])) != result["run_id"]
                or result["candidate"] != "candidate-" + result["run_id"]
            ):
                return False
            if name in {"no_fix", "failed_fix"}:
                reason, status = (
                    ("NO_FIX", "NO_OP")
                    if name == "no_fix"
                    else ("FAILED_VALIDATION", "VALIDATION_FAILED")
                )
                if (
                    receipt["status"] != "ESCALATED"
                    or receipt["reason_code"] != reason
                    or result["status"] != status
                    or "proposal" in result
                    or "post_commit_check" in receipt
                ):
                    return False
                if name == "no_fix":
                    if result["tests"] != "NOT_RUN" or any(
                        k in result for k in ("check_exit_code", "check_argv", "tested_commit")
                    ):
                        return False
                else:
                    failed = {
                        "status": "FAILED",
                        "collected": 3,
                        "tests": 0,
                        "failures": 1,
                        "errors": 0,
                        "skipped": 0,
                        "expected_failures": 0,
                        "unexpected_successes": 0,
                    }
                    if (
                        result["tests"] != failed
                        or any(type(result["tests"][k]) is not int for k in failed if k != "status")
                        or type(result["check_exit_code"]) is not int
                        or result["check_exit_code"] != 1
                        or result["check_argv"] != [sys.executable, "-I", "-c", repair.CHECK]
                        or "tested_commit" in result
                    ):
                        return False
                continue
            checked = receipt["post_commit_check"]
            before = repair.FIX if name == "refactor" else repair.SEED["src/arithmetic.py"]
            after = repair.REFACTOR if name == "refactor" else repair.FIX
            proposal = result["proposal"]
            expected_files = {
                n: repair.digest((after if n == "src/arithmetic.py" else v).encode())
                for n, v in repair.SEED.items()
            }
            if (
                receipt["status"] != "READY_FOR_LOCAL_REVIEW"
                or receipt["reason_code"] != "VERIFIED_NEW_COMMIT"
                or result["status"] != "VALIDATED_LOCAL"
                or result["diff"] != m.DIFF
                or result["candidate_files"] != expected_files
                or result["input_commit"] != event["head_sha"]
                or result["tested_commit"] == event["head_sha"]
                or not re.fullmatch(r"[0-9a-f]{40}", result["tested_commit"])
                or not m.counts(result["tests"])
                or type(result["check_exit_code"]) is not int
                or result["check_exit_code"] != 0
                or result["checks_sha256"] != repair.CHECKS_HASH
                or result["check_argv"] != [sys.executable, "-I", "-c", repair.CHECK]
                or result["policy_sha256"] != repair.policy_hash()
                or type(result["risk_tier"]) is not int
                or result["risk_tier"] != 1
                or result["auto_merge"] is not False
                or result["publication"] != "BLOCKED"
                or result["remote_pr"] != "NOT_RUN"
                or result["input_commit"] != proposal["base_sha"]
                or proposal
                != {
                    "kind": "OFFLINE_PR_PROPOSAL",
                    "base_sha": event["head_sha"],
                    "head_sha": result["tested_commit"],
                    "remote": "NOT_RUN",
                    "publication": "BLOCKED",
                }
                or before == after
                or checked["head_sha"] != result["tested_commit"]
                or checked["files_sha256"] != expected_files
                or checked["run_id"] == event["run_id"]
                or str(uuid.UUID(checked["run_id"])) != checked["run_id"]
                or not m.counts(checked["result"])
                or type(checked["exit_code"]) is not int
                or checked["exit_code"] != 0
                or checked["check_sha256"] != m.CHECK_SHA
                or checked["argv"] != [sys.executable, "-I", "-c", m.CHECK]
                or strict_json_loads(checked["log"]) != checked["result"]
                or repair.digest(checked["log"].encode()) != checked["log_sha256"]
            ):
                return False
        return True
    except (KeyError, TypeError, ValueError, OSError, Blocked):
        return False


if __name__ == "__main__":
    print(json.dumps(acceptance(), indent=2))
