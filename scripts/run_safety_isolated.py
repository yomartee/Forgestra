"""Run reviewed offline regressions without inherited publishing credentials.

Environment filtering is not filesystem/network process isolation. Do not use
this launcher for arbitrary customer tests; those require the later sandbox.
"""

import os
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def main():
    allowed = {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    from forgestra_safety import private_output_workspace, Blocked

    try:
        with private_output_workspace() as parent:
            environment["TEMP"] = environment["TMP"] = environment["TMPDIR"] = str(parent)
            result = subprocess.run(
                [sys.executable, "-I", str(ROOT / "scripts/check_safety.py")],
                cwd=ROOT,
                env=environment,
                timeout=900,
                check=False,
            )
            return result.returncode
    except (OSError, subprocess.SubprocessError, Blocked):
        print(
            json.dumps({"status": "FAILED", "reason_code": "FACTORY_TEST_UNAVAILABLE_OR_TIMEOUT"})
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
