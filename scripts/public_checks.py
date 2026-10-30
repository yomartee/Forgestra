"""Public product acceptance. Private archives, providers and publication absent."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import uuid
import zipfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]


def packages():
    from bootstrap import environment
    from forgestra_safety import private_output_workspace
    from public_contract import source_paths, inspect_distributions
    from forgestra.verification import validate_source

    validate_source(ROOT)
    env = environment()
    env.update(SOURCE_DATE_EPOCH="946684800", PIP_NO_INDEX="1", PIP_NO_CACHE_DIR="1")
    result: dict[str, Any] = {"commands": [], "files": {}}
    with private_output_workspace() as parent:
        source = parent / "source"
        for name in source_paths(ROOT):
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
        profile = parent / "profile"
        profile.mkdir()
        env.update(
            HOME=str(profile),
            USERPROFILE=str(profile),
            APPDATA=str(profile),
            LOCALAPPDATA=str(profile),
        )

        def run(name, argv, cwd=source):
            child = subprocess.run(
                [str(a) for a in argv],
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=180,
                check=False,
            )
            result["commands"].append(
                {
                    "name": name,
                    "exit_code": child.returncode,
                    "stdout_sha256": hashlib.sha256(child.stdout.encode()).hexdigest(),
                    "stderr_sha256": hashlib.sha256(child.stderr.encode()).hexdigest(),
                }
            )
            from acquire_tools import unlinked
            from forgestra_safety import redact

            logs = ROOT / ".tools/public-results/private"
            unlinked(logs)
            logs.mkdir(parents=True, exist_ok=True)
            unlinked(logs / (name + ".log"))
            (logs / (name + ".log")).write_text(
                redact(child.stdout + child.stderr).replace(str(parent), "<fixture>"),
                encoding="utf-8",
            )
            if child.returncode:
                raise ValueError("distribution check failed")

        build = parent / "build-env"
        run("fresh-build-env", [sys.executable, "-I", "-m", "venv", "--copies", build])
        python = build / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        run(
            "locked-backend",
            [
                python,
                "-I",
                "-m",
                "pip",
                "--isolated",
                "--no-cache-dir",
                "install",
                "--no-index",
                "--find-links",
                ROOT / ".tools/wheels",
                "--require-hashes",
                "--only-binary=:all:",
                "-r",
                source / "requirements/build.lock",
            ],
        )
        run(
            "documented-source-bootstrap",
            [
                sys.executable,
                "-I",
                source / "scripts/bootstrap.py",
                "--wheelhouse",
                ROOT / ".tools/wheels",
            ],
        )
        for label in ("one", "two"):
            run(
                "wheel-" + label,
                [
                    python,
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
                    parent / label,
                    source,
                ],
            )
        wheels = [next((parent / label).glob("*.whl")) for label in ("one", "two")]
        assert wheels[0].read_bytes() == wheels[1].read_bytes()
        run("sdist", [python, "-I", source / "scripts/build_distribution.py"])
        sdist = next((source / ".tools/distributions").glob("*.tar.gz"))
        result.update(inspect_distributions(ROOT, wheels[0], sdist))
        for label, artifact in (("wheel", wheels[0]), ("sdist", sdist)):
            target = parent / (label + "-install")
            run(
                label + "-fresh-install-env",
                [sys.executable, "-I", "-m", "venv", "--copies", target],
            )
            interpreter = target / (
                "Scripts/python.exe" if sys.platform == "win32" else "bin/python"
            )
            if label == "sdist":
                run(
                    "sdist-locked-backend",
                    [
                        interpreter,
                        "-I",
                        "-m",
                        "pip",
                        "--isolated",
                        "--no-cache-dir",
                        "install",
                        "--no-index",
                        "--find-links",
                        ROOT / ".tools/wheels",
                        "--require-hashes",
                        "--only-binary=:all:",
                        "-r",
                        source / "requirements/build.lock",
                    ],
                )
            run(
                label + "-install",
                [
                    interpreter,
                    "-I",
                    "-m",
                    "pip",
                    "--isolated",
                    "--no-cache-dir",
                    "install",
                    "--no-index",
                    "--no-deps",
                    "--no-build-isolation",
                    artifact,
                ],
            )
            run(label + "-doctor", [interpreter, "-I", "-m", "forgestra", "doctor"])
            run(label + "-help", [interpreter, "-I", "-m", "forgestra", "--help"])
            run(
                label + "-dependency-check", [interpreter, "-I", "-m", "pip", "--isolated", "check"]
            )
        output = ROOT / ".tools/public-results/distributions"
        output.mkdir(parents=True, exist_ok=False)
        for name, path in (("core.whl", wheels[0]), ("source.tar.gz", sdist)):
            shutil.copyfile(path, output / name)
            result["files"][name] = {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size,
            }
    return result


FAILURE_PROFILE = "FORGESTRA_PUBLIC_FAILURE_V1"
FAILURE_STAGES = frozenset(
    {
        "OUTPUT",
        "SOURCE",
        "INNER_CI",
        "PACKAGES",
        "INSTALLED_CLI",
        "REPAIR",
        "ADOPTION",
        "WEB_CREATION",
        "SYNC",
        "MAINTENANCE",
        "MCP",
        "RELEASE",
        "LINKS",
        "SOURCE_DRIFT",
        "SBOM",
    }
)


def failure_diagnostic(stage, error):
    """Only fixed factory metadata; exception text/args are never rendered."""
    from forgestra_safety import Blocked

    categories = {
        FileNotFoundError: "MISSING_FILE",
        FileExistsError: "ALREADY_EXISTS",
        PermissionError: "PERMISSION_DENIED",
        NotADirectoryError: "PATH_ERROR",
        OSError: "OS_ERROR",
        Blocked: "POLICY_BLOCKED",
        subprocess.TimeoutExpired: "TIMEOUT",
        subprocess.CalledProcessError: "CHILD_FAILED",
        subprocess.SubprocessError: "PROCESS_ERROR",
        ValueError: "VALUE_ERROR",
        TypeError: "TYPE_ERROR",
        KeyError: "KEY_ERROR",
        StopIteration: "MISSING_RESULT",
        IndexError: "INDEX_ERROR",
        AssertionError: "ASSERTION_ERROR",
        tarfile.TarError: "TAR_ERROR",
        zipfile.BadZipFile: "ZIP_ERROR",
    }
    value: dict[str, Any] = {
        "profile": FAILURE_PROFILE,
        "stage": stage if type(stage) is str and stage in FAILURE_STAGES else "UNKNOWN",
        "category": next(
            (category for kind, category in categories.items() if type(error) is kind), "UNKNOWN"
        ),
    }
    # Unknown subclasses may override attribute access; do not inspect them.
    if value["category"] != "UNKNOWN" and isinstance(error, OSError):
        for field in ("errno", "winerror"):
            number = getattr(error, field, None)
            if type(number) is int and 0 <= number <= 65535:
                value[field] = number
    return value


def emit_failure(stage, error):
    print(json.dumps(failure_diagnostic(stage, error), sort_keys=True), flush=True)


def main():
    from bootstrap import environment
    from forgestra_safety import Blocked
    from public_contract import (
        PUBLIC,
        CHECKS,
        canonical,
        containment,
        inventory,
        source_paths,
        absent_private,
        links,
        export,
    )
    from forgestra.verification import validate_source
    from record_pr02_evidence import valid_report
    from record_pr03_evidence import installed_cli
    from record_pr04_evidence import repair_acceptance, valid_repair
    from record_pr05_evidence import adoption_acceptance, valid_adoption
    from pr07_creation_validation import acceptance as creation, valid_acceptance
    from pr06_web_validation import valid_web
    from pr08_sync_validation import acceptance as sync, valid_sync
    from pr09_maintenance_validation import acceptance as maintenance, valid_maintenance
    from pr10_mcp_validation import acceptance as mcp, valid_mcp
    from pr11_release_validation import acceptance as release, valid_release
    from forgestra.release import sbom

    output = ROOT / ".tools/public-results"
    from acquire_tools import unlinked

    try:
        unlinked(output)
        output.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError) as error:
        emit_failure("OUTPUT", error)
        print(
            json.dumps(
                {
                    "profile": PUBLIC,
                    "status": "FAILED",
                    "reason": "OUTPUT_UNAVAILABLE",
                    "publication": "BLOCKED",
                }
            )
        )
        return 1
    summary: dict[str, Any] = {
        "profile": PUBLIC,
        "status": "FAILED",
        "source_sha256": "0" * 64,
        "tests": 0,
        "checks": [],
        "publication": "BLOCKED",
        "private_replay": "NOT_RUN",
        "live": "NOT_RUN",
        "reason": "PUBLIC_CHECK_FAILED",
    }
    artifacts: dict[str, Any] = {"profile": PUBLIC, "files": {}, "license_approval": "PENDING"}
    stage = "SOURCE"
    try:
        absent_private(ROOT)
        containment(ROOT)
        validate_source(ROOT)
        before = inventory(ROOT)
        summary["source_sha256"] = hashlib.sha256(canonical(before)).hexdigest()
        stage = "INNER_CI"
        run_id = str(uuid.uuid4())
        child = subprocess.run(
            [sys.executable, "-I", "scripts/ci.py", "--run-id", run_id],
            cwd=ROOT,
            env=environment(),
            timeout=1200,
            check=False,
        )
        report = json.loads((ROOT / ".tools/pr02-results/report.json").read_text(encoding="utf-8"))
        (output / "inner-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        # A failed suite still executed tests. Preserve its typed count without
        # mistaking that count or a claimed status for successful acceptance.
        stats = json.loads(
            (ROOT / ".tools/pr02-results/regressions.log")
            .read_text(encoding="utf-8")
            .splitlines()[0]
        )
        fields = {
            "tests",
            "collected",
            "failures",
            "errors",
            "skipped",
            "expected_failures",
            "unexpected_successes",
        }
        if (
            isinstance(stats, dict)
            and set(stats) == fields | {"status"}
            and all(type(stats[f]) is int and stats[f] >= 0 for f in fields)
            and stats["tests"] == stats["collected"]
        ):
            summary["tests"] = stats["tests"]

        def check(name, passed):
            summary["checks"].append({"name": name, "status": "PASSED" if passed else "FAILED"})
            print(name + ": " + ("PASSED" if passed else "FAILED"), flush=True)
            if not passed:
                raise ValueError("public check failed")

        check(
            "inner-ci",
            child.returncode == 0 and valid_report(report, ROOT / ".tools/pr02-results", run_id),
        )
        summary["tests"] = next(
            c["result"]["tests"] for c in report["checks"] if c["name"] == "regressions"
        )
        stage = "PACKAGES"
        built = packages()
        artifacts["files"] = built["files"]
        (output / "packages.json").write_text(json.dumps(built, indent=2), encoding="utf-8")
        check("packages", True)

        def receipt(name, value, passed):
            # Detailed current receipts are private; only finite status/digest
            # schemas may enter the separate upload directory.
            path = output / (name + "-fixture.json")
            unlinked(path)
            path.write_bytes(canonical(value) + b"\n")
            check(name, passed(value))

        stage = "INSTALLED_CLI"
        receipt("installed-cli", installed_cli(), lambda r: r["status"] == "PASSED_LOCAL")
        stage = "REPAIR"
        receipt("repair", repair_acceptance(), valid_repair)
        stage = "ADOPTION"
        receipt("adoption", adoption_acceptance(), valid_adoption)
        stage = "WEB_CREATION"
        generated = creation()
        web = generated.pop("web")
        receipt(
            "web-creation",
            {"web": web, "creation": generated},
            lambda r: valid_web(r["web"]) and valid_acceptance(r["creation"], r["web"]),
        )
        stage = "SYNC"
        receipt("sync", sync(), valid_sync)
        stage = "MAINTENANCE"
        receipt("maintenance", maintenance(), valid_maintenance)
        stage = "MCP"
        receipt("mcp", mcp(), valid_mcp)
        stage = "RELEASE"
        receipt("release", release(), valid_release)
        stage = "LINKS"
        link_result = links(ROOT, source_paths(ROOT))
        (output / "links.json").write_text(json.dumps(link_result, indent=2), encoding="utf-8")
        check("links", link_result["status"] == "PASSED")
        stage = "SOURCE_DRIFT"
        if before != inventory(ROOT) or {c["name"] for c in summary["checks"]} != set(CHECKS):
            raise ValueError("public source drift")
        summary.update(status="PASSED_LOCAL", reason="NONE")
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        StopIteration,
        IndexError,
        AssertionError,
        Blocked,
        subprocess.SubprocessError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:
        emit_failure(stage, error)
        summary.update(status="FAILED", reason="PUBLIC_CHECK_FAILED")
    try:
        bom = sbom(ROOT)
    except (OSError, ValueError, TypeError, KeyError, Blocked) as error:
        emit_failure("SBOM", error)
        from public_contract import EMPTY_BOM

        bom = EMPTY_BOM
        summary.update(status="FAILED", reason="PUBLIC_CHECK_FAILED")
    export(output / "upload", summary, artifacts, bom)
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["status"] == "PASSED_LOCAL" else 1


if __name__ == "__main__":
    sys.exit(main())
