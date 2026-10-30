"""Rerun reviewed PR 01 checks and bind sanitized evidence to actual file hashes.

No target builds, package installation, credentials, SDKs or remote calls. Does
not inspect arbitrary environment values or Git history. See engineering status.
"""

import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs/engineering/evidence/pr-01"
sys.path.insert(0, str(ROOT / "scripts"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    output = {}
    stack = [ROOT]
    while stack:
        directory = stack.pop()
        for path in sorted(directory.iterdir()):
            if (
                path.name in {".git", "__pycache__", ".tools", ".venv", "node_modules"}
                or path == EVIDENCE
            ):
                continue
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                raise ValueError("source links are unsupported for verification")
            if path.is_dir():
                stack.append(path)
            elif path.is_file():
                output[path.relative_to(ROOT).as_posix()] = digest(path)
    for name in [
        "baseline.json",
        "containment.json",
        "review-baseline.json",
        "review-reproduction.json",
        "validation-baseline.json",
        "local-tools.json",
    ]:
        path = EVIDENCE / name
        if path.is_symlink():
            raise ValueError("evidence input links are unsupported")
        if path.exists():
            output[path.relative_to(ROOT).as_posix()] = digest(path)
    return output


def assess_check(name, exit_code, stdout):
    """An exit code alone is not a successful verification contract."""
    from check_safety import valid_regression_result
    from forgestra_safety import strict_json_loads

    if exit_code != 0:
        return {"status": "FAILED"}
    if name.startswith("syntax-") or name in {
        "actionlint",
        "shellcheck",
        "black",
        "flake8",
        "mypy",
    }:
        return {"status": "PASSED"}
    try:
        document = strict_json_loads(stdout)
    except (ValueError, TypeError):
        return {"status": "FAILED", "reason": "invalid check result"}
    if name == "regressions":
        valid = valid_regression_result(document)
    elif name == "workflow-json-yaml":
        valid = (
            isinstance(document, dict)
            and document.get("status") == "PASSED"
            and type(document.get("files")) is int
            and document["files"] == 19
            and type(document.get("yaml_files")) is int
            and document["yaml_files"] == 18
        )
    elif name == "offline-inspection":
        valid = (
            isinstance(document, dict)
            and document.get("status") == "INSPECTED_LOCAL"
            and document.get("provider") == document.get("remote") == "NOT_RUN"
            and document.get("auto_merge") is False
            and type(document.get("files")) is int
            and document["files"] >= 0
            and type(document.get("risk_tier")) is int
            and document["risk_tier"] in {0, 1, 2}
        )
    else:
        valid = False
    if not valid:
        return {"status": "FAILED", "reason": "check contract failed"}
    return {"status": "PASSED", "result": document}


def write_evidence(path, content):
    """Fixed workspace outputs; do not follow existing evidence-file links."""
    if path.parent != EVIDENCE or path.is_symlink():
        raise ValueError("unsupported evidence destination")
    handle, temporary_name = tempfile.mkstemp(prefix=".verification-", dir=EVIDENCE)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    from check_safety import REGRESSION_CANARIES
    from forgestra_safety import redact, strict_json_loads

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    for ancestor in [EVIDENCE, *EVIDENCE.parents]:
        if ancestor.is_symlink() or (hasattr(ancestor, "is_junction") and ancestor.is_junction()):
            raise ValueError("evidence directory links are unsupported")
    before = source_hashes()
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper()
        in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"}
    }
    commands = []
    artifacts = {}

    def run(argv, name):
        try:
            result = subprocess.run(
                argv,
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                check=False,
            )
            path = EVIDENCE / (name + ".log")
            write_evidence(path, redact(result.stdout + result.stderr, REGRESSION_CANARIES))
            artifacts[path.name] = digest(path)
            report = {
                "name": name,
                "argv": argv,
                "exit_code": result.returncode,
                **assess_check(name, result.returncode, result.stdout),
            }
            commands.append(report)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            commands.append({"name": name, "argv": argv, "status": "BLOCKED", "exit_code": None})

    run([sys.executable, "-I", "scripts/run_safety_isolated.py"], "regressions")
    run([sys.executable, "-I", "scripts/check_workflows.py"], "workflow-json-yaml")
    run([sys.executable, "-I", "scripts/inspect_local.py", "."], "offline-inspection")
    bash_path = Path("C:/Program Files/Git/bin/bash.exe")
    bash = str(bash_path) if bash_path.exists() else shutil.which("bash")
    for path in sorted(ROOT.glob("scripts/**/*.sh")):
        relative = path.relative_to(ROOT).as_posix()
        if bash:
            run([bash, "-n", relative], "syntax-" + path.stem)
        else:
            commands.append({"name": "syntax-" + path.stem, "status": "BLOCKED", "exit_code": None})
    python_paths = [
        path
        for path in ROOT.rglob("*.py")
        if not any(
            part in {".tools", ".venv", "node_modules", "__pycache__"} for part in path.parts
        )
    ]
    syntax_ok = bool(python_paths)
    for path in python_paths:
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path.relative_to(ROOT)))
        except (OSError, SyntaxError, UnicodeError):
            syntax_ok = False
    baseline_path = EVIDENCE / "baseline.json"
    from pr01_validation import PYTHON_SCOPE, SHELL_SCOPE, verified_native, verified_python_tools

    tools: dict[str, str | None] = {"docker": shutil.which("docker")}
    python_tools = None
    try:
        python_tools = verified_python_tools()
    except (OSError, ValueError, KeyError, TypeError):
        pass
    for name in ["actionlint", "shellcheck", "black", "flake8", "mypy"]:
        try:
            tools[name] = (
                verified_native(name) if name in {"actionlint", "shellcheck"} else python_tools
            )
        except (OSError, ValueError, KeyError, TypeError):
            tools[name] = None
        argv = [sys.executable, "-I", "scripts/pr01_validation.py", name]
        if tools[name]:
            run(argv, name)
        else:
            commands.append({"name": name, "argv": argv, "status": "BLOCKED", "exit_code": None})
    baseline = strict_json_loads(baseline_path.read_text(encoding="utf-8"))["files"]
    changed = {
        name: {"before": value, "after": before.get(name)}
        for name, value in baseline.items()
        if before.get(name) != value
    }
    added = {name: value for name, value in before.items() if name not in baseline}
    after = source_hashes()
    stable = before == after
    audits = [
        "docs/audit/Factory_Production_Open_Source_Audit.md",
        "docs/audit/Factory_Remediation_Roadmap.md",
    ]
    audits_unchanged = all(before.get(name) == baseline[name] for name in audits)
    passed = (
        stable and audits_unchanged and syntax_ok and all(c["status"] == "PASSED" for c in commands)
    )
    manifest_path = EVIDENCE / "tested-files.json"
    write_evidence(manifest_path, json.dumps(before, indent=2) + "\n")
    report = {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_base": {
            "git": "PRESENT_NOT_AUDITED" if (ROOT / ".git").exists() else "ABSENT",
            "head": None,
            "baseline_manifest_sha256": digest(baseline_path),
        },
        "status": "PASSED_LOCAL" if passed else "FAILED_OR_BLOCKED",
        "source_unchanged_during_checks": stable,
        "audit_documents_unchanged": audits_unchanged,
        "tested_manifest_sha256": digest(manifest_path),
        "artifact_sha256": artifacts,
        "python_syntax": {
            "status": "PASSED" if syntax_ok else "FAILED",
            "files": len(python_paths),
        },
        "local_lint_scope": {
            "python": list(PYTHON_SCOPE),
            "shell": list(SHELL_SCOPE),
            "quarantined_legacy_python": (
                "Syntax and actual denial paths tested; " "full lint/type cleanup remains PR 02+"
            ),
            "quarantined_shell_recipes": "Comments only; no executable legacy commands remain",
        },
        "commands": commands,
        "changed_original_files": changed,
        "added_files": added,
        "live_checks": {
            "github_workflows": "NOT_RUN",
            "required_checks_branch_rules": "NOT_RUN",
            "providers": "NOT_RUN",
            "backend_authorization": "NOT_RUN",
            "build_browser_bundle_image": "NOT_RUN",
            "full_history_tags_assets_logs_review": "BLOCKED",
        },
        "tool_availability": tools,
        "unavailable_tools": [name for name, executable in tools.items() if not executable],
        "activity": {
            "providers": "NOT_RUN",
            "remote_publication": "NOT_RUN",
            "package_installation": "NOT_RUN",
            "credentialed_services": "NOT_RUN",
        },
        "isolation": (
            "Environment filtered; host filesystem/network sandbox only; no target code executed"
        ),
    }
    write_evidence(EVIDENCE / "verification.json", json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "status": report["status"],
                "regressions": commands[0],
                "python_files": len(python_paths),
                "source_stable": stable,
                "audit_unchanged": audits_unchanged,
            },
            indent=2,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError):
        print(
            json.dumps(
                {
                    "status": "BLOCKED",
                    "reason": "verification inputs or evidence destination unavailable",
                }
            )
        )
        sys.exit(1)
