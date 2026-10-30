"""Local static validation of the PR 01 safety layer; no tool acquisition here.

Tools must already exist in .tools and match the recorded integrity manifest.
This does not install factory dependencies or run target code (PR 02+ work).
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PYTHON_SCOPE = (
    "scripts/forgestra_safety.py",
    "scripts/local_generation.py",
    "scripts/inspect_local.py",
    "scripts/check_safety.py",
    "scripts/check_workflows.py",
    "scripts/run_safety_isolated.py",
    "scripts/record_pr01_evidence.py",
    "scripts/pr01_validation.py",
    "tests/test_safety.py",
    "tests/test_pr01_review.py",
    "tests/test_pr01_validation.py",
    "tests/blocked_entry_probe.py",
)
SHELL_SCOPE = (
    "scripts/init_factory.sh",
    "scripts/install_to_voxguard.sh",
    "scripts/install_transformation_kit.sh",
    "scripts/transform/setup_sync.sh",
    "scripts/validate-trinity.sh",
)
PYTHON_TOOLS = {"black", "flake8", "mypy"}
BLACK_CONFIG = "[tool.black]\nline-length = 100\n"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_path(relative):
    if (
        not isinstance(relative, str)
        or not relative.startswith(".tools/")
        or ".." in Path(relative).parts
    ):
        raise ValueError("invalid local tool path")
    path = ROOT / relative
    if not path.is_file() or any(
        p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
        for p in [path, *path.parents]
    ):
        raise ValueError("local tool path unavailable or linked")
    return path


def load_provenance():
    sys.path.insert(0, str(ROOT / "scripts"))
    from forgestra_safety import strict_json_loads

    return strict_json_loads(
        (ROOT / "docs/engineering/evidence/pr-01/local-tools.json").read_text(encoding="utf-8")
    )


def verified_native(name):
    tool = load_provenance()["native"][name]
    path = checked_path(tool["executable"])
    if digest(path) != tool["executable_sha256"]:
        raise ValueError("local tool hash mismatch")
    return str(path)


def verified_python_tools():
    tool = load_provenance()["python"]
    manifest = checked_path(tool["installed_manifest"])
    if digest(manifest) != tool["installed_manifest_sha256"]:
        raise ValueError("local Python tool manifest mismatch")
    entries = json.loads(manifest.read_text(encoding="utf-8"))
    for relative, expected in entries.items():
        if digest(checked_path(relative)) != expected:
            raise ValueError("local Python tool hash mismatch")
    actual = {
        p.relative_to(ROOT).as_posix() for p in (ROOT / ".tools/python").rglob("*") if p.is_file()
    }
    if actual != set(entries):
        raise ValueError("unexpected local Python tool file")
    return str(ROOT / ".tools/python")


def command(name, format_python=False):
    if name == "actionlint":
        # Import only the reviewed static workflow inventory, never an action.
        sys.path.insert(0, str(ROOT / "scripts"))
        from check_workflows import LEGACY_WORKFLOWS, SAFETY_PATH

        return [
            verified_native(name),
            "-shellcheck=" + verified_native("shellcheck"),
            *LEGACY_WORKFLOWS,
            SAFETY_PATH,
        ]
    if name == "shellcheck":
        return [verified_native(name), *SHELL_SCOPE]
    if name not in PYTHON_TOOLS:
        raise ValueError("unknown local validator")
    if name == "black":
        content = (ROOT / "config/pr01-black.toml").read_text(encoding="utf-8")
        if content != BLACK_CONFIG:
            raise ValueError("unexpected formatter configuration")
    library = verified_python_tools()
    arguments = {
        "black": ([] if format_python else ["--check"])
        + ["--config", "config/pr01-black.toml", "--no-cache", "--workers", "1", *PYTHON_SCOPE],
        "flake8": ["--isolated", "--jobs", "1", "--max-line-length", "100", *PYTHON_SCOPE],
        "mypy": [
            "--config-file=",
            "--check-untyped-defs",
            "--no-incremental",
            "--cache-dir",
            ".tools/mypy-cache",
            *PYTHON_SCOPE,
        ],
    }
    bootstrap = (
        "import runpy,sys; library=sys.argv[1]; sys.argv=sys.argv[2:]; "
        'sys.path.insert(0,library); runpy.run_module(sys.argv[0],run_name="__main__")'
    )
    return [sys.executable, "-I", "-B", "-c", bootstrap, library, name, *arguments[name]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=["actionlint", "shellcheck", "black", "flake8", "mypy"])
    parser.add_argument(
        "--format", action="store_true", help="Apply Black to the fixed PR 01 scope"
    )
    args = parser.parse_args()
    if args.format and args.tool != "black":
        parser.error("--format is only supported for Black")
    try:
        argv = command(args.tool, args.format)
        environment = {
            key: value
            for key, value in os.environ.items()
            if key.upper()
            in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"}
        }
        environment["BLACK_CACHE_DIR"] = str(ROOT / ".tools/black-cache")
        environment["LOCALAPPDATA"] = str(ROOT / ".tools/user-local")
        environment["APPDATA"] = str(ROOT / ".tools/user-data")
        environment["USERPROFILE"] = str(ROOT / ".tools/user-data")
        environment["WIN_PD_OVERRIDE_LOCAL_APPDATA"] = str(ROOT / ".tools/user-local")
        environment["WIN_PD_OVERRIDE_APPDATA"] = str(ROOT / ".tools/user-data")
        environment["GHC_CHARENC"] = "UTF-8"
        return subprocess.run(argv, cwd=ROOT, env=environment, check=False, timeout=120).returncode
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        print(
            json.dumps(
                {"status": "BLOCKED", "reason": "local validator unavailable, changed or invalid"}
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
