"""Install the reviewed local core into a fresh workspace .venv, offline only.

Acquire the hash-locked build wheels separately. No target dependencies, optional
integrations, global install, activation hooks or publisher credentials are used.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import platform

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))


def environment():
    allowed = {
        "SYSTEMROOT",
        "WINDIR",
        "PATH",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_ARCHITEW6432",
        "FORGESTRA_KILL_SWITCH",
    }
    return {k: v for k, v in os.environ.items() if k.upper() in allowed}


def bootstrap(wheelhouse):
    from forgestra.verification import validate_source, ready_offline
    from forgestra_safety import strict_json_loads

    destination = ROOT / ".venv"
    if (
        sys.version_info[:2] != (3, 14)
        or platform.python_implementation() != "CPython"
        or os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0"
        or not wheelhouse.is_dir()
        or destination.exists()
        or destination.is_symlink()
    ):
        raise ValueError("unsupported runtime, missing wheels or existing environment")
    for path in [ROOT, *ROOT.parents, wheelhouse, *wheelhouse.parents]:
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ValueError("linked bootstrap paths unsupported")
    validate_source(ROOT)
    python = destination / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    commands = [
        [sys.executable, "-I", "-m", "venv", str(destination)],
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
            str(wheelhouse.resolve()),
            "--require-hashes",
            "--only-binary=:all:",
            "--no-compile",
            "-r",
            str(ROOT / "requirements/build.lock"),
        ],
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
            str(ROOT),
        ],
        [str(python), "-I", "-m", "forgestra", "doctor"],
    ]
    for index, argv in enumerate(commands):
        result = subprocess.run(
            argv,
            cwd=ROOT,
            env=environment(),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode or (
            index == len(commands) - 1 and not ready_offline(strict_json_loads(result.stdout))
        ):
            # Do not serialize package/subprocess errors or potentially secret paths.
            raise ValueError("bootstrap failed; partial .venv requires manual review")
    return {
        "status": "INSTALLED_LOCAL",
        "doctor": "READY_OFFLINE",
        "privileged_automation": "DISABLED",
    }


def main():
    from forgestra_safety import Blocked

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(bootstrap(args.wheelhouse)))
        return 0
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        SyntaxError,
        Blocked,
        subprocess.SubprocessError,
    ):
        print(json.dumps({"status": "BLOCKED", "reason": "Offline bootstrap incomplete"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
