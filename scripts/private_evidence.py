"""Private maintainer byte-preservation replay, never public CI or rights approval."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]

PROFILE = "FORGESTRA_PRIVATE_MAINTAINER_V1"
REQUIRED = {
    f"docs/engineering/evidence/pr-{i:02}/{n}"
    for i in range(1, 12)
    for n in ("verification.json", "tested-files.json")
} | {
    "docs/audit/Factory_Production_Open_Source_Audit.md",
    "docs/audit/Factory_Remediation_Roadmap.md",
}


def replay(root, manifest):
    from forgestra_safety import Blocked
    from forgestra.verification import bounded_file
    from public_contract import canonical, relative

    if (
        set(manifest) != {"profile", "files"}
        or manifest["profile"] != PROFILE
        or not isinstance(manifest["files"], dict)
        or not REQUIRED <= set(manifest["files"])
        or len(manifest["files"]) > 4096
    ):
        raise Blocked("BLOCKED: required private inputs")
    for name, expected in manifest["files"].items():
        relative(name)
        if (
            not name.startswith(("docs/audit/", "docs/engineering/evidence/"))
            or hashlib.sha256(bounded_file(Path(root) / name, 8_000_000)).hexdigest() != expected
        ):
            raise Blocked("BLOCKED: private evidence mismatch")
    return {
        "profile": PROFILE,
        "status": "VERIFIED_BYTES",
        "files": len(manifest["files"]),
        "inventory_sha256": hashlib.sha256(canonical(manifest)).hexdigest(),
        "owner_decisions": "PENDING",
        "publication": "BLOCKED",
        "historical_scope": "EXACT_SUPPLIED_PRIVATE_BASELINE_ONLY",
    }


def main():
    from forgestra_safety import Blocked, strict_json_loads
    from forgestra.verification import bounded_file

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = strict_json_loads(bounded_file(args.inventory, 2_000_000).decode())
        print(json.dumps(replay(args.root, value), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, Blocked):
        print(
            json.dumps(
                {
                    "profile": PROFILE,
                    "status": "BLOCKED",
                    "reason": "PRIVATE_INPUTS_MISSING_OR_INVALID",
                    "publication": "BLOCKED",
                }
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
