"""Verify PR 02 locally and bind its results to the exact snapshot. No remote writes."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile
from typing import Any
import uuid
import re

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

ROOT = Path(__file__).resolve().parents[1]

IGNORED = {".git", ".tools", ".venv", "__pycache__", "node_modules", "build", "dist"}
REQUIRED_CHECKS = frozenset(
    {
        "regressions",
        "source-contract",
        "build-install",
        "core-install",
        "workflow-policy",
        "offline-inspection",
        "development-install",
        "doctor",
        "installed-doctor",
        "black",
        "flake8",
        "mypy",
        "actionlint",
        "shellcheck",
        *("shell-syntax-" + str(i) for i in range(5)),
    }
)


def write_artifact(directory, name, payload):
    from acquire_tools import unlinked

    allowed = {
        "report.json",
        "verification.json",
        "tested-files.json",
        "installed-cli.json",
        "repair-fixture.json",
        "adoption-fixture.json",
        "web-fixture.json",
        "creation-fixture.json",
        "sync-fixture.json",
        "maintenance-fixture.json",
        "mcp-fixture.json",
        "release-fixture.json",
        "snapshot-scan.json",
        "sbom.cdx.json",
        "web-browser.png",
    } | {check + ".log" for check in REQUIRED_CHECKS}
    if name not in allowed or not isinstance(payload, bytes):
        raise ValueError("unsupported evidence artifact")
    unlinked(directory)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / name
    unlinked(destination)
    handle, temporary_name = tempfile.mkstemp(prefix=".verification-", dir=directory)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def valid_report(report, directory, run_id=None):
    from acquire_tools import unlinked
    from ci import SCOPE, assess
    from forgestra_safety import strict_json_loads

    try:
        if (
            not isinstance(report, dict)
            or report.get("status") != "PASSED_LOCAL"
            or report.get("privileged_automation") != "DISABLED"
            or report.get("hosted_workflows") != "NOT_RUN"
            or report.get("python_lint_scope") != list(SCOPE)
            or not isinstance(report.get("run_id"), str)
            or str(uuid.UUID(report["run_id"])) != report["run_id"]
            or (run_id is not None and report["run_id"] != run_id)
        ):
            return False
        checks = report["checks"]
        if (
            not isinstance(checks, list)
            or len(checks) != len(REQUIRED_CHECKS)
            or {c["name"] for c in checks} != REQUIRED_CHECKS
        ):
            return False
        for check in checks:
            if (
                check["status"] != "PASSED"
                or type(check["exit_code"]) is not int
                or check["exit_code"] != 0
                or not isinstance(check.get("argv"), list)
                or not check["argv"]
                or not all(isinstance(a, str) for a in check["argv"])
                or not isinstance(check.get("log_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", check["log_sha256"])
            ):
                return False
            path = directory / (check["name"] + ".log")
            unlinked(path)
            if digest(path) != check["log_sha256"]:
                return False
            first_line = path.read_text(encoding="utf-8").partition("\n")[0]
            if not assess(check["name"], check["exit_code"], first_line):
                return False
            if check["name"] == "regressions" and json.dumps(
                check.get("result"), sort_keys=True
            ) != json.dumps(strict_json_loads(first_line), sort_keys=True):
                return False
        return True
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return False


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes(excluded_evidence="pr-02"):
    from acquire_tools import unlinked

    output = {}
    stack = [ROOT]
    while stack:
        directory = stack.pop()
        for path in sorted(directory.iterdir()):
            if (
                path.name in IGNORED
                or path.name.endswith(".egg-info")
                or path == ROOT / "docs/engineering/evidence" / excluded_evidence
            ):
                continue
            unlinked(path)
            if path.is_dir():
                stack.append(path)
            elif path.is_file():
                output[path.relative_to(ROOT).as_posix()] = digest(path)
    for name in (
        "baseline.json",
        "tool-provenance.json",
        "review-baseline.json",
        "review-reproduction.json",
    ):
        path = ROOT / "docs/engineering/evidence/pr-02" / name
        unlinked(path)
        output[path.relative_to(ROOT).as_posix()] = digest(path)
    return output


def clean_install():
    """Build twice, then install an actual wheel into a fresh external fixture."""
    from bootstrap import environment
    from forgestra_safety import redact, strict_json_loads
    from forgestra.workspaces import plan
    from forgestra.configuration import load
    from forgestra.verification import validate_source, REQUIRED_SOURCE

    validate_source(ROOT)

    env = environment()
    env["SOURCE_DATE_EPOCH"] = "946684800"
    build_python = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    result: dict[str, Any] = {"status": "FAILED", "commands": []}
    with tempfile.TemporaryDirectory(prefix="forgestra-clean-install-") as temporary:
        base = Path(temporary)
        profile = base / "profile"
        profile.mkdir()
        for name in ("user.npmrc", "global.npmrc"):
            (profile / name).write_text("")
        env.update(
            {
                "HOME": str(profile),
                "USERPROFILE": str(profile),
                "NPM_CONFIG_USERCONFIG": str(profile / "user.npmrc"),
                "NPM_CONFIG_GLOBALCONFIG": str(profile / "global.npmrc"),
                "NPM_CONFIG_CACHE": str(profile / "npm-cache"),
                "NPM_CONFIG_UPDATE_NOTIFIER": "false",
                "NPM_CONFIG_AUDIT": "false",
                "NPM_CONFIG_FUND": "false",
                "NPM_CONFIG_IGNORE_SCRIPTS": "true",
            }
        )
        source = base / "source"
        source.mkdir()
        for name in REQUIRED_SOURCE:
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

        def run(argv, name, expected=None, expected_text=None, cwd=None):
            command = subprocess.run(
                argv,
                cwd=cwd or base,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                check=False,
            )
            passed = command.returncode == 0
            if expected_text is not None:
                passed = passed and expected_text in command.stdout.splitlines()
            if passed and expected:
                try:
                    passed = strict_json_loads(command.stdout).get("status") == expected
                except (TypeError, ValueError, AttributeError):
                    passed = False
            # Record commands, results and sanitized output without temporary paths.
            output = redact(command.stdout + command.stderr).replace(str(base), "<fixture>")
            result["commands"].append(
                {
                    "name": name,
                    "argv": [str(argument).replace(str(base), "<fixture>") for argument in argv],
                    "exit_code": command.returncode,
                    "status": "PASSED" if passed else "FAILED",
                    "output": output,
                }
            )
            if not passed:
                raise ValueError("clean install command failed")

        for name in ("wheel-one", "wheel-two"):
            run(
                [
                    str(build_python),
                    "-I",
                    "-m",
                    "pip",
                    "--isolated",
                    "--no-cache-dir",
                    "wheel",
                    "--no-index",
                    "--no-deps",
                    "--no-build-isolation",
                    "--wheel-dir",
                    str(base / name),
                    str(source),
                ],
                name,
            )
        first = next((base / "wheel-one").glob("*.whl"))
        second = next((base / "wheel-two").glob("*.whl"))
        if digest(first) != digest(second):
            raise ValueError("wheel build is not reproducible")
        with zipfile.ZipFile(first) as archive:
            files = archive.namelist()
            expected_files = (
                {"forgestra_safety.py", "inspect_local.py"}
                | {
                    "forgestra/" + name.removeprefix("src/forgestra/")
                    for name in REQUIRED_SOURCE
                    if name.startswith("src/forgestra/")
                }
                | {
                    "forgestra-0.2.0.dev0.dist-info/" + name
                    for name in ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD")
                }
            )
            if len(files) != len(expected_files) or set(files) != expected_files:
                raise ValueError("unexpected wheel payload")
            metadata = archive.read("forgestra-0.2.0.dev0.dist-info/METADATA").decode()
            if any(
                line.startswith("Requires-Dist:") and 'extra == "dev"' not in line
                for line in metadata.splitlines()
            ):
                raise ValueError("unexpected runtime dependency")
            result["wheel_files"] = files
        run(
            [
                sys.executable,
                "-I",
                str(source / "scripts/bootstrap.py"),
                "--wheelhouse",
                str(ROOT / ".tools/wheels"),
            ],
            "documented-source-bootstrap",
            "INSTALLED_LOCAL",
        )
        run([sys.executable, "-I", "-m", "venv", str(base / "environment")], "fresh-venv")
        python = base / "environment" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        console = python.parent / ("forgestra.exe" if os.name == "nt" else "forgestra")
        run(
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
                str(first),
            ],
            "offline-wheel-install",
        )
        run([str(console), "--help"], "console-help")
        run([str(python), "-I", "-m", "forgestra", "doctor"], "doctor", "READY_OFFLINE")
        run(
            [str(python), "-I", "-m", "forgestra", "inspect", str(source)],
            "inspection",
            "INSPECTED_LOCAL",
        )
        run([str(python), "-I", "-m", "pip", "--isolated", "check"], "dependency-check")
        # Only this authored inert fixture is executed; never a candidate target.
        node = shutil.which("node")
        npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
        if not node or not npm:
            raise ValueError("mixed fixture requires the pinned Node toolchain")
        run([node, "--version"], "node-version", expected_text="v24.14.0")
        run([npm, "--version"], "npm-version")
        mixed = base / "mixed"
        mixed.mkdir()
        (mixed / "requirements.txt").write_text("# Incidental factory Python tooling\n")
        (mixed / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{"":{}}}\n')
        (mixed / "package.json").write_text(
            json.dumps(
                {
                    "name": "trusted-fixture",
                    "private": True,
                    "scripts": {
                        name: "node -e \"console.log('fixture-" + name + "')\""
                        for name in ("build", "test", "lint")
                    },
                }
            )
        )
        workspace = plan(mixed, load())["workspaces"][0]
        if workspace["manager"] != "npm":
            raise ValueError("mixed fixture selected incorrect toolchain")
        for name, argv in workspace["commands"].items():
            run([npm, *argv[1:]], "mixed-" + name, expected_text="fixture-" + name, cwd=mixed)
        result["mixed_fixture"] = {
            "status": "PASSED",
            "manager": "npm",
            "commands": workspace["commands"],
            "dependency_install": "NOT_RUN",
        }
        result.update(
            {
                "status": "PASSED",
                "wheel_sha256": digest(first),
                "reproducible_wheel": True,
                "optional_dependencies_installed": False,
            }
        )
    return result


def main():
    from acquire_tools import unlinked
    from bootstrap import environment
    from forgestra_safety import strict_json_loads, Blocked

    output = ROOT / ".tools/pr02-results"
    unlinked(output)
    output.mkdir(parents=True, exist_ok=True)
    before = source_hashes()
    run_id = str(uuid.uuid4())
    write_artifact(
        output, "report.json", json.dumps({"status": "RUNNING", "run_id": run_id}).encode()
    )
    try:
        result = subprocess.run(
            [sys.executable, "-I", "scripts/ci.py", "--run-id", run_id],
            cwd=ROOT,
            env=environment(),
            check=False,
            timeout=600,
        )
        report = strict_json_loads((output / "report.json").read_text(encoding="utf-8"))
        complete = result.returncode == 0 and valid_report(report, output, run_id)
        if not isinstance(report, dict):
            report = {"status": "BLOCKED", "checks": [], "run_id": run_id}
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        report = {"status": "BLOCKED", "checks": [], "run_id": run_id}
        complete = False
    clean = {"status": "BLOCKED", "reason": "Required local checks did not pass"}
    if complete:
        try:
            clean = clean_install()
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            SyntaxError,
            Blocked,
            StopIteration,
            subprocess.SubprocessError,
            zipfile.BadZipFile,
        ):
            clean = {"status": "FAILED", "reason": "Clean installation validation incomplete"}
    after = source_hashes()
    baseline = strict_json_loads(
        (ROOT / "docs/engineering/evidence/pr-01/baseline.json").read_text()
    )
    # The supplied historical audits must remain byte-identical to PR 01's accepted snapshot.
    accepted = strict_json_loads(
        (ROOT / "docs/engineering/evidence/pr-01/tested-files.json").read_text()
    )
    accepted_baseline = strict_json_loads(
        (ROOT / "docs/engineering/evidence/pr-02/baseline.json").read_text(encoding="utf-8")
    )
    pr01_unchanged = all(
        digest(ROOT / "docs/engineering/evidence/pr-01" / name) == accepted_baseline[key]
        for name, key in (
            ("verification.json", "pr01_verification_sha256"),
            ("tested-files.json", "pr01_tested_manifest_sha256"),
        )
    )
    audits = all(
        digest(ROOT / name) == accepted[name] for name in accepted if name.startswith("docs/audit/")
    )
    passed = (
        complete and clean["status"] == "PASSED" and before == after and audits and pr01_unchanged
    )
    manifest = json.dumps(after, indent=2, sort_keys=True) + "\n"
    write_artifact(output, "tested-files.json", manifest.encode("utf-8"))
    report.update(
        {
            "status": "PASSED_LOCAL" if passed else "FAILED",
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "source_base": {
                "git": "ABSENT",
                "head": None,
                "pr01_baseline_sha256": digest(
                    ROOT / "docs/engineering/evidence/pr-01/baseline.json"
                ),
            },
            "source_unchanged_during_checks": before == after,
            "audit_documents_unchanged": audits,
            "accepted_pr01_evidence_unchanged": pr01_unchanged,
            "tested_manifest_sha256": digest(output / "tested-files.json"),
            "clean_install": clean,
            "live_required_checks": "NOT_RUN",
            "baseline_available": bool(baseline),
            "privileged_automation": "DISABLED",
            "hosted_workflows": "NOT_RUN",
        }
    )
    payload = (json.dumps(report, indent=2) + "\n").encode("utf-8")
    write_artifact(output, "report.json", payload)
    evidence = ROOT / "docs/engineering/evidence/pr-02"
    checks = report.get("checks", [])
    for check in checks if isinstance(checks, list) else []:
        if isinstance(check, dict) and check.get("name") in REQUIRED_CHECKS:
            path = output / (check["name"] + ".log")
            unlinked(path)
            if path.is_file():
                write_artifact(evidence, path.name, path.read_bytes())
    write_artifact(evidence, "tested-files.json", manifest.encode("utf-8"))
    # Write the index last: a passing report never precedes its referenced files.
    write_artifact(evidence, "verification.json", payload)
    print(
        json.dumps(
            {
                "status": report["status"],
                "source_stable": before == after,
                "clean_install": clean["status"],
                "audits_unchanged": audits,
            }
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
