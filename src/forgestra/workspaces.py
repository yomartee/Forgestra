"""Propose visible workspace contracts without running or installing target code."""

from pathlib import Path
from typing import Any
import tomllib
import re

from forgestra_safety import Blocked, strict_json_loads
from forgestra.configuration import safe_directory
from forgestra.verification import plain_file, lock_entries


def read_package(path: Path) -> dict[str, Any]:
    document = strict_json_loads(plain_file(path, 1_000_000))
    if not isinstance(document, dict):
        raise Blocked("BLOCKED: invalid package manifest")
    scripts = document.get("scripts", {})
    if not isinstance(scripts, dict) or any(
        not isinstance(v, str) or not v.strip() for v in scripts.values()
    ):
        raise Blocked("BLOCKED: invalid package scripts")
    manager = document.get("packageManager")
    if manager is not None and (
        not isinstance(manager, str) or not re.fullmatch(r"npm@[0-9]+\.[0-9]+\.[0-9]+", manager)
    ):
        raise Blocked("BLOCKED: unsupported declared package manager")
    return scripts


def node_workspace(root: Path, relative: str) -> dict[str, Any]:
    directory = safe_directory(root, relative)
    scripts = read_package(directory / "package.json")
    locks = [
        (m, name)
        for m, names in {
            "npm": ("package-lock.json", "npm-shrinkwrap.json"),
            "pnpm": ("pnpm-lock.yaml",),
            "yarn": ("yarn.lock",),
        }.items()
        for name in names
        if (directory / name).is_file()
    ]
    if len(locks) != 1:
        raise Blocked("BLOCKED: Node workspace needs one unambiguous lockfile")
    manager, lock = locks[0]
    if manager != "npm":
        raise Blocked("BLOCKED: package manager requires a separately verified toolchain")
    # A lock's presence is a proposal input, never evidence of dependency installation.
    lock_document = strict_json_loads(plain_file(directory / lock))
    if (
        not isinstance(lock_document, dict)
        or type(lock_document.get("lockfileVersion")) is not int
        or lock_document["lockfileVersion"] != 3
        or not isinstance(lock_document.get("packages"), dict)
        or not isinstance(lock_document["packages"].get(""), dict)
    ):
        raise Blocked("BLOCKED: unsupported or invalid npm lockfile")
    setup = {
        "npm": ["npm", "ci"],
        "pnpm": ["pnpm", "install", "--frozen-lockfile"],
        "yarn": ["yarn", "install", "--immutable"],
    }[manager]
    return {
        "path": relative,
        "language": "javascript",
        "manager": manager,
        "lockfile": lock,
        "setup": setup,
        "commands": {k: [manager, "run", k] for k in ("build", "test", "lint") if k in scripts},
    }


def plan(root: Path, configuration: dict[str, Any]) -> dict[str, Any]:
    if (
        not root.is_dir()
        or root.is_symlink()
        or (hasattr(root, "is_junction") and root.is_junction())
    ):
        raise Blocked("BLOCKED: workspace root unavailable")
    workspaces = []
    explicit = configuration["workspaces"]
    if explicit:
        for item in explicit:
            directory = safe_directory(root, item["path"])
            if item["language"] == "javascript":
                detected = node_workspace(root, item["path"])
                if detected["manager"] != item["manager"]:
                    raise Blocked("BLOCKED: configured manager conflicts with lockfile")
                if "lockfile" in item and item["lockfile"] != detected["lockfile"]:
                    raise Blocked("BLOCKED: configured lockfile conflicts with detection")
                scripts = read_package(directory / "package.json")
                if any(argv[2] not in scripts for argv in item["commands"].values()):
                    raise Blocked("BLOCKED: configured npm script missing")
            else:
                validate_python(directory)
                detected = {"setup": None, "lockfile": None}
                if "lockfile" in item:
                    lock_entries(directory / item["lockfile"])
                    detected = {
                        "lockfile": item["lockfile"],
                        "setup": [
                            "python",
                            "-m",
                            "pip",
                            "install",
                            "--require-hashes",
                            "--only-binary=:all:",
                            "-r",
                            item["lockfile"],
                        ],
                    }
            workspaces.append({**detected, **item, "source": "explicit"})
    elif (root / "package.json").is_file():
        workspaces.append({**node_workspace(root, "."), "source": "proposal"})
    elif (root / "pyproject.toml").is_file() or (root / "requirements.txt").is_file():
        validate_python(root)
        workspaces.append(
            {
                "path": ".",
                "language": "python",
                "manager": "pip",
                "setup": None,
                "lockfile": None,
                "commands": {},
                "source": "proposal",
                "reason": "Explicit Python commands and dependency lock required",
            }
        )
    else:
        raise Blocked("BLOCKED: unsupported workspace; explicit configuration required")
    return {
        "status": "PLANNED_LOCAL",
        "execution": "BLOCKED",
        "remote": "NOT_RUN",
        "workspaces": workspaces,
    }


def validate_python(directory: Path) -> None:
    manifest = directory / "pyproject.toml"
    requirements = directory / "requirements.txt"
    if manifest.exists():
        if not tomllib.loads(plain_file(manifest)):
            raise Blocked("BLOCKED: empty Python project")
    elif requirements.exists():
        plain_file(requirements)
    else:
        raise Blocked("BLOCKED: Python workspace manifest missing")
