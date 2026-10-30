"""Compatibility entry for read-only workspace proposals; execution stays blocked."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts")]


def detect_tech_stack(repo_path):
    from forgestra.configuration import load
    from forgestra.workspaces import plan

    return plan(Path(repo_path), load())


def main():
    from forgestra_safety import Blocked

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, default=Path("."))
    parser.add_argument("--format", choices=["json"], default="json")
    args = parser.parse_args()
    try:
        print(json.dumps(detect_tech_stack(args.path), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, Blocked):
        print(json.dumps({"status": "BLOCKED", "reason": "Invalid or unsupported workspace"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
