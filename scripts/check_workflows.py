"""Enforce the PR 01 disabled-workflow boundary and strict JSON/YAML subset.

This is not actionlint or a general GitHub schema validator. Unknown workflows,
either YAML extension, extra steps, privileges and alternate service manifests
fail closed. Repository evidence files cannot change this policy.
"""

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

LEGACY_WORKFLOWS = (
    ".github/workflows/auditor-loop.yml",
    ".github/workflows/bidirectional-sync.yml",
    ".github/workflows/claude.yml",
    ".github/workflows/factory-clock.yml",
    ".github/workflows/frontend-lifecycle.yml",
    ".github/workflows/growth-engine.yml",
    ".github/workflows/hunter-loop.yml",
    ".github/workflows/install-to-repo.yml",
    ".github/workflows/marketing_agent.yml",
    ".github/workflows/monorepo-to-polyrepo.yml",
    ".github/workflows/repository-assessment.yml",
    ".github/workflows/self-healing.yml",
    "templates/workflows/universal-ci.yml",
    "growth-engine-workflow.yml",
)
SAFETY_PATH = ".github/workflows/safety-regressions.yml"
BLOCKED_WORKFLOW = {
    "name": "Forgestra legacy operation BLOCKED",
    "on": {"workflow_dispatch": None},
    "permissions": {},
    "jobs": {
        "blocked": {
            "runs-on": "ubuntu-latest",
            "steps": [
                {
                    "name": "Unsupported capability",
                    "run": (
                        "echo 'BLOCKED: legacy automation requires reviewed safety "
                        "prerequisites.'\n"
                        "exit 1\n"
                    ),
                }
            ],
        }
    },
}
SAFETY_WORKFLOW = {
    "name": "Forgestra public product checks",
    "on": {"push": None, "pull_request": None, "workflow_dispatch": None},
    "permissions": {"contents": "read"},
    "jobs": {
        "public-product": {
            "strategy": {"fail-fast": False, "matrix": {"os": ["ubuntu-24.04", "windows-2025"]}},
            "runs-on": "${{ matrix.os }}",
            "timeout-minutes": 90,
            "defaults": {"run": {"shell": "bash"}},
            "steps": [
                {
                    "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                    "with": {"persist-credentials": False},
                },
                {
                    "uses": "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
                    "with": {"python-version": "3.14.3", "check-latest": False},
                },
                {
                    "name": "Reviewed public tool acquisition",
                    "run": "python -I scripts/acquire_tools.py --download",
                },
                {
                    "name": "Offline factory bootstrap",
                    "run": "python -I scripts/bootstrap.py --wheelhouse " ".tools/wheels",
                },
                {
                    "uses": "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1",
                    "with": {
                        "node-version": "24.14.0",
                        "check-latest": False,
                        "package-manager-cache": False,
                    },
                },
                {
                    "name": "Acquire integrity-locked web test tools",
                    "run": "python -I scripts/pr06_web_validation.py --acquire " "--download",
                },
                {
                    "name": "Acquire integrity-locked optional MCP SDK",
                    "run": "python -I scripts/pr10_mcp_validation.py --acquire " "--download",
                },
                {
                    "name": "Public product checks; private evidence absent",
                    "env": {
                        "TEMP": "${{ runner.temp }}",
                        "TMP": "${{ runner.temp }}",
                        "TMPDIR": "${{ runner.temp }}",
                    },
                    "run": "python -I scripts/public_checks.py",
                },
                {
                    "uses": "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
                    "if": "always()",
                    "with": {
                        "name": "public-product-${{ matrix.os }}",
                        "path": ".tools/public-results/upload/summary.json\n"
                        ".tools/public-results/upload/artifacts.json\n"
                        ".tools/public-results/upload/sbom.json",
                        "if-no-files-found": "error",
                        "include-hidden-files": False,
                        "retention-days": 7,
                    },
                },
            ],
        }
    },
}
AUXILIARY = {
    ".github/dependabot.yml": {"version": 2, "updates": []},
    ".github/copilot-setup-steps.yml": {
        "setup": [],
        "test": [
            {
                "name": "Forgestra reviewed offline regressions",
                "run": "python -I scripts/run_safety_isolated.py",
            }
        ],
        "validate": [
            {
                "name": "Strict workflow JSON/YAML subset",
                "run": "python -I scripts/check_workflows.py",
            }
        ],
    },
    ".coderabbit.yaml": {"reviews": {"auto_review": {"enabled": False}}},
    "mcp.json": {"mcpServers": {}},
}


def read_document(path):
    from forgestra_safety import strict_json_loads

    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise ValueError("workflow/config link unsupported")
    return strict_json_loads(path.read_text(encoding="utf-8"))


def same_document(document, expected):
    # Python dict equality treats 0 == False and 1 == True; policy must not.
    return json.dumps(document, sort_keys=True) == json.dumps(expected, sort_keys=True)


def validate(path):
    path = Path(path)
    document = read_document(path)
    expected = SAFETY_WORKFLOW if path == ROOT / SAFETY_PATH else BLOCKED_WORKFLOW
    if not same_document(document, expected):
        raise ValueError("workflow exceeds PR 01 safety boundary")
    return document


def validate_inventory():
    for alias in [".coderabbit.yml", ".github/dependabot.yaml", ".github/copilot-setup-steps.yaml"]:
        if (ROOT / alias).exists() or (ROOT / alias).is_symlink():
            raise ValueError("ambiguous automatic integration configuration")
    expected = {
        name for name in (*LEGACY_WORKFLOWS, SAFETY_PATH) if name.startswith(".github/workflows/")
    }
    discovered = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / ".github/workflows").iterdir()
        if path.suffix.lower() in {".yml", ".yaml"}
    }
    if discovered != expected:
        raise ValueError("unknown or missing workflow")
    paths = [ROOT / name for name in (*LEGACY_WORKFLOWS, SAFETY_PATH)]
    for path in paths:
        validate(path)
    for relative, expected_document in AUXILIARY.items():
        path = ROOT / relative
        if not same_document(read_document(path), expected_document):
            raise ValueError("automatic service integration is not disabled")
        paths.append(path)
    return paths


def main():
    try:
        paths = validate_inventory()
    except (OSError, ValueError):
        print(
            json.dumps(
                {
                    "status": "FAILED",
                    "reason": "invalid, ambiguous or unapproved workflow/configuration",
                }
            )
        )
        return 1
    print(
        json.dumps(
            {
                "status": "PASSED",
                "files": len(paths),
                "yaml_files": sum(path.suffix in {".yaml", ".yml"} for path in paths),
                "format": "JSON subset of YAML",
                "actionlint": "NOT_RUN",
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
