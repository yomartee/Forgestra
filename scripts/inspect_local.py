"""Read-only offline inspection; JSON changes are data, never shell source."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))


def inspect(root, changes=None):
    from forgestra_safety import Blocked, classify_diff, validate_diff

    root = Path(root)
    if (
        not root.is_dir()
        or root.is_symlink()
        or (hasattr(root, "is_junction") and root.is_junction())
    ):
        raise Blocked("BLOCKED: inspection root unavailable")
    if changes is not None:
        validate_diff(changes)
    # No target code, hooks, package managers, providers or subprocesses execute.
    count = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        for path in directory.iterdir():
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                continue
            if path.name in {".git", ".venv", "node_modules", "__pycache__", ".tools"}:
                continue
            if path.is_dir():
                stack.append(path)
            elif path.is_file():
                count += 1
    return {
        "status": "INSPECTED_LOCAL",
        "files": count,
        "risk_tier": classify_diff(changes),
        "auto_merge": False,
        "provider": "NOT_RUN",
        "remote": "NOT_RUN",
    }


def main():
    from forgestra_safety import Blocked, strict_json_loads, validate_diff

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument(
        "--changes-json", type=Path, help="Complete typed diff manifest, including rename sources"
    )
    args = parser.parse_args()
    try:
        changes = (
            validate_diff(strict_json_loads(args.changes_json.read_text(encoding="utf-8")))
            if args.changes_json
            else None
        )
        print(json.dumps(inspect(args.root, changes), sort_keys=True))
        return 0
    except (OSError, ValueError, Blocked):
        print(
            json.dumps({"status": "BLOCKED", "reason": "Invalid or unavailable inspection input"})
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
