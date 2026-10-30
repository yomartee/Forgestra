"""Reviewed factory validation, never a target executor. No network acquisition here."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import argparse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

ROOT = Path(__file__).resolve().parents[1]


def regression_failure_diagnostic(stderr):
    """Expose only one finite validated factory diagnostic, never raw stderr."""
    from check_safety import DIAGNOSTIC_PREFIX, factory_test_ids, valid_failure_diagnostic
    from forgestra_safety import Blocked, strict_json_loads

    invalid = {"profile": "FORGESTRA_FACTORY_FAILURE_V1", "status": "INVALID_DIAGNOSTIC"}
    lines = [
        line.removeprefix(DIAGNOSTIC_PREFIX)
        for line in stderr.splitlines()
        if line.startswith(DIAGNOSTIC_PREFIX)
    ]
    if len(lines) != 1 or len(lines[0]) > 12_000:
        return invalid
    try:
        value = strict_json_loads(lines[0])
        return value if valid_failure_diagnostic(value, factory_test_ids()) else invalid
    except OSError, ValueError, TypeError, KeyError, SyntaxError, Blocked:
        return invalid


def scopes():
    from pr01_validation import PYTHON_SCOPE

    return (
        *PYTHON_SCOPE,
        "scripts/forgestra_cli.py",
        "scripts/bootstrap.py",
        "scripts/acquire_tools.py",
        "scripts/ci.py",
        "scripts/record_pr02_evidence.py",
        "scripts/universal/detect_tech_stack.py",
        "tests/test_pr02.py",
        "src/forgestra/__init__.py",
        "src/forgestra/__main__.py",
        "src/forgestra/cli.py",
        "src/forgestra/configuration.py",
        "src/forgestra/workspaces.py",
        "src/forgestra/verification.py",
        "tests/test_pr02_review.py",
        "src/forgestra/providers.py",
        "src/forgestra/assessment.py",
        "tests/test_pr03.py",
        "scripts/record_pr03_evidence.py",
        "tests/test_pr03_review.py",
        "src/forgestra/repair.py",
        "tests/test_pr04.py",
        "scripts/record_pr04_evidence.py",
        "src/forgestra/adoption.py",
        "tests/test_pr05.py",
        "tests/test_pr05_review.py",
        "scripts/record_pr05_evidence.py",
        "src/forgestra/web.py",
        "tests/test_pr06.py",
        "scripts/pr06_web_validation.py",
        "scripts/record_pr06_evidence.py",
        "scripts/record_pr07_evidence.py",
        "scripts/pr07_creation_validation.py",
        "src/forgestra/creation.py",
        "src/forgestra/component_registry.py",
        "tests/test_pr07.py",
        "tests/test_pr08.py",
        "src/forgestra/synchronization.py",
        "src/forgestra/sync_control.py",
        "scripts/pr08_sync_validation.py",
        "scripts/record_pr08_evidence.py",
        "src/forgestra/maintenance.py",
        "scripts/pr09_maintenance_validation.py",
        "scripts/record_pr09_evidence.py",
        "src/forgestra/integrations.py",
        "scripts/pr10_mcp_validation.py",
        "scripts/record_pr10_evidence.py",
        "integrations/mcp/src/forgestra_mcp/__init__.py",
        "integrations/mcp/src/forgestra_mcp/__main__.py",
        "integrations/mcp/src/forgestra_mcp/server.py",
        "mcp-server/repo-operations.py",
        "mcp-server/sales_server.py",
        "tests/test_pr10.py",
        "src/forgestra/release.py",
        "scripts/pr11_release_validation.py",
        "scripts/record_pr11_evidence.py",
        "tests/test_pr11.py",
        "scripts/public_contract.py",
        "scripts/public_checks.py",
        "scripts/private_evidence.py",
        "scripts/build_distribution.py",
        "tests/test_public_candidate.py",
        "scripts/self_heal.py",
        "scripts/autonomous_janitor.py",
        "tests/test_pr09.py",
    )


SCOPE = scopes()


def assess(name, code, stdout):
    from check_safety import valid_regression_result
    from forgestra_safety import strict_json_loads
    from forgestra.verification import ready_offline

    if code != 0:
        return False
    if name == "regressions":
        try:
            return valid_regression_result(strict_json_loads(stdout))
        except TypeError, ValueError:
            return False
    if name in {
        "source-contract",
        "doctor",
        "installed-doctor",
        "offline-inspection",
        "workflow-policy",
    }:
        try:
            document = strict_json_loads(stdout)
            if name in {"source-contract", "doctor", "installed-doctor"}:
                return ready_offline(document)
            if name == "workflow-policy":
                return (
                    document.get("status") == "PASSED"
                    and type(document.get("files")) is int
                    and document["files"] == 19
                    and type(document.get("yaml_files")) is int
                    and document["yaml_files"] == 18
                )
            return (
                document.get("status") == "INSPECTED_LOCAL"
                and document.get("provider") == document.get("remote") == "NOT_RUN"
                and document.get("auto_merge") is False
                and type(document.get("files")) is int
                and document["files"] >= 0
                and type(document.get("risk_tier")) is int
                and document["risk_tier"] in {0, 1, 2}
            )
        except TypeError, ValueError, AttributeError:
            return False
    return name in {
        "build-install",
        "core-install",
        "development-install",
        "black",
        "flake8",
        "mypy",
        "actionlint",
        "shellcheck",
        *("shell-syntax-" + str(i) for i in range(5)),
    }


def main():
    from acquire_tools import native_tools, unlinked
    from bootstrap import environment
    from check_safety import REGRESSION_CANARIES
    from check_workflows import LEGACY_WORKFLOWS, SAFETY_PATH
    from forgestra_safety import redact, strict_json_loads
    from pr01_validation import SHELL_SCOPE
    from record_pr02_evidence import write_artifact

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default=str(uuid.uuid4()), type=uuid.UUID)
    run_id = str(parser.parse_args().run_id)

    output = ROOT / ".tools/pr02-results"
    unlinked(output)
    output.mkdir(parents=True, exist_ok=True)
    write_artifact(
        output, "report.json", json.dumps({"status": "RUNNING", "run_id": run_id}).encode()
    )
    checks = []
    env = environment()
    # Workspace-only tool caches. No home-directory configuration/plugin loading.
    profile = ROOT / ".tools/pr02-user"
    unlinked(profile)
    profile.mkdir(parents=True, exist_ok=True)
    env.update(
        {
            "HOME": str(profile),
            "USERPROFILE": str(profile),
            "APPDATA": str(profile),
            "LOCALAPPDATA": str(profile),
            "WIN_PD_OVERRIDE_LOCAL_APPDATA": str(profile),
            "WIN_PD_OVERRIDE_APPDATA": str(profile),
            "GHC_CHARENC": "UTF-8",
            "MYPYPATH": os.pathsep.join([str(ROOT / "src"), str(ROOT / "scripts")]),
        }
    )
    python = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    def run(name, argv):
        diagnostic = None
        try:
            result = subprocess.run(
                argv,
                cwd=ROOT,
                env=env,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=960 if name == "regressions" else 240,
                check=False,
            )
            passed = assess(name, result.returncode, result.stdout)
            if name == "regressions" and not passed:
                diagnostic = regression_failure_diagnostic(result.stderr)
            log = redact(result.stdout + result.stderr, REGRESSION_CANARIES)
            code = result.returncode
        except OSError, subprocess.SubprocessError:
            passed, log, code = False, "BLOCKED: check unavailable or timed out\n", None
        path = output / (name + ".log")
        unlinked(path)
        write_artifact(output, path.name, log.encode("utf-8"))
        checks.append(
            {
                "name": name,
                "argv": argv,
                "exit_code": code,
                "status": "PASSED" if passed else "FAILED",
                "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
        if name == "regressions" and passed:
            checks[-1]["result"] = strict_json_loads(result.stdout)
        print(name + ": " + checks[-1]["status"], flush=True)
        if name == "regressions" and not passed:
            print(
                json.dumps(
                    diagnostic
                    or {"profile": "FORGESTRA_FACTORY_FAILURE_V1", "status": "INVALID_DIAGNOSTIC"},
                    sort_keys=True,
                ),
                flush=True,
            )
        return passed

    passed = run("regressions", [sys.executable, "-I", "scripts/run_safety_isolated.py"])
    passed = run("workflow-policy", [sys.executable, "-I", "scripts/check_workflows.py"]) and passed
    source_ready = run(
        "source-contract",
        [sys.executable, "-I", "scripts/forgestra_cli.py", "doctor", "--source", "."],
    )
    passed = source_ready and passed
    if python.is_file() and source_ready:
        backend = run(
            "build-install",
            [
                str(python),
                "-I",
                "-m",
                "pip",
                "--isolated",
                "--no-cache-dir",
                "install",
                "--no-index",
                "--find-links",
                str(ROOT / ".tools/wheels"),
                "--force-reinstall",
                "--require-hashes",
                "--only-binary=:all:",
                "--no-compile",
                "-r",
                "requirements/build.lock",
            ],
        )
        if not backend:
            passed = False
        else:
            # Only the statically reviewed backend is used for the local source build.
            passed = (
                run(
                    "core-install",
                    [
                        str(python),
                        "-I",
                        "-m",
                        "pip",
                        "--isolated",
                        "--no-cache-dir",
                        "install",
                        "--no-index",
                        "--no-deps",
                        "--no-build-isolation",
                        "--no-compile",
                        str(ROOT),
                    ],
                )
                and passed
            )
        passed = (
            run("offline-inspection", [str(python), "-I", "-m", "forgestra", "inspect", "."])
            and passed
        )
        ready = run(
            "development-install",
            [
                str(python),
                "-I",
                "-m",
                "pip",
                "--isolated",
                "--no-cache-dir",
                "install",
                "--no-index",
                "--find-links",
                str(ROOT / ".tools/wheels"),
                "--require-hashes",
                "--only-binary=:all:",
                "--force-reinstall",
                "--no-compile",
                "-r",
                "requirements/dev.lock",
            ],
        )
        passed = (
            run(
                "doctor",
                [str(python), "-I", "-m", "forgestra", "doctor", "--development", "--source", "."],
            )
            and passed
        )
        passed = (
            run("installed-doctor", [str(python), "-I", "-m", "forgestra", "doctor"]) and passed
        )
        if ready:
            for name, options in {
                "black": [
                    "--check",
                    "--config",
                    "config/pr01-black.toml",
                    "--no-cache",
                    "--workers",
                    "1",
                ],
                "flake8": ["--isolated", "--jobs", "1", "--max-line-length", "100"],
                "mypy": [
                    "--config-file=",
                    "--check-untyped-defs",
                    "--no-incremental",
                    "--cache-dir",
                    ".tools/pr02-mypy",
                ],
            }.items():
                passed = (
                    run(name, [str(python), "-I", "-B", "-m", name, *options, *SCOPE]) and passed
                )
        passed = ready and passed
    else:
        passed = False
    try:
        tools = native_tools()
        passed = (
            run(
                "actionlint",
                [
                    tools["actionlint"],
                    "-shellcheck=" + tools["shellcheck"],
                    *LEGACY_WORKFLOWS,
                    SAFETY_PATH,
                ],
            )
            and passed
        )
        passed = run("shellcheck", [tools["shellcheck"], *SHELL_SCOPE]) and passed
    except OSError, ValueError, KeyError:
        passed = False
        checks.append({"name": "native-tools", "status": "BLOCKED"})
    bash = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash")
    for index, shell_path in enumerate(SHELL_SCOPE):
        passed = run("shell-syntax-" + str(index), [bash or "bash", "-n", shell_path]) and passed
    report = {
        "status": "PASSED_LOCAL" if passed else "FAILED",
        "checks": checks,
        "python_lint_scope": list(SCOPE),
        "privileged_automation": "DISABLED",
        "hosted_workflows": "NOT_RUN",
        "run_id": run_id,
    }
    path = output / "report.json"
    unlinked(path)
    write_artifact(output, path.name, (json.dumps(report, indent=2) + "\n").encode("utf-8"))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
