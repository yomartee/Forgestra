"""Strict offline configuration; neither commands nor policy grant execution authority."""

from pathlib import Path
import os
import re
from typing import Any

from forgestra_safety import Blocked, Policy, strict_json_loads, relative_path
from forgestra.verification import plain_file

DEFAULT = {"version": 1, "capabilities": {}, "targets": [], "workspaces": []}


def validate_relative(relative: str) -> None:
    if relative == ".":
        return
    relative_path(relative)


def safe_directory(root: Path, relative: str) -> Path:
    validate_relative(relative)
    if relative == ".":
        return root
    path = root
    for part in relative.split("/"):
        path /= part
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise Blocked("BLOCKED: linked workspace unsupported")
    if not path.is_dir():
        raise Blocked("BLOCKED: workspace unavailable")
    return path


def load(path: Path | None = None) -> dict[str, Any]:
    document: Any
    if path is None:
        document = {"version": 1, "capabilities": {}, "targets": [], "workspaces": []}
    else:
        document = strict_json_loads(plain_file(path))
    return validate(document)


def validate(document: Any) -> dict[str, Any]:
    """Use the same authority/command schema for files and direct Python callers."""
    if not isinstance(document, dict) or set(document) != set(DEFAULT):
        raise Blocked("BLOCKED: invalid configuration schema")
    Policy({key: document[key] for key in ("version", "capabilities", "targets")})
    # There is deliberately no supported enabling flag in PR 02.
    if any(document["capabilities"].values()) or document["targets"]:
        raise Blocked("BLOCKED: privileged configuration unsupported")
    if not isinstance(document["workspaces"], list):
        raise Blocked("BLOCKED: invalid workspaces")
    seen = set()
    for workspace in document["workspaces"]:
        required = {
            "path",
            "language",
            "manager",
            "commands",
        }
        if not isinstance(workspace, dict) or set(workspace) not in (
            required,
            required | {"lockfile"},
        ):
            raise Blocked("BLOCKED: invalid workspace schema")
        relative = workspace["path"]
        if not isinstance(relative, str) or relative.casefold() in seen:
            raise Blocked("BLOCKED: duplicate or invalid workspace")
        validate_relative(relative)
        if "lockfile" in workspace:
            if not isinstance(workspace["lockfile"], str) or workspace["lockfile"] == ".":
                raise Blocked("BLOCKED: invalid workspace lockfile")
            validate_relative(workspace["lockfile"])
        seen.add(relative.casefold())
        language, manager = workspace["language"], workspace["manager"]
        if (
            not isinstance(language, str)
            or not isinstance(manager, str)
            or (language, manager)
            not in {
                ("python", "pip"),
                ("javascript", "npm"),
            }
        ):
            raise Blocked("BLOCKED: unsupported workspace toolchain")
        commands = workspace["commands"]
        if not isinstance(commands, dict) or set(commands) - {"build", "test", "lint"}:
            raise Blocked("BLOCKED: invalid command schema")
        for argv in commands.values():
            if (
                not isinstance(argv, list)
                or not argv
                or len(argv) > 32
                or any(
                    not isinstance(a, str) or not a or len(a) > 240 or any(ord(c) < 32 for c in a)
                    for a in argv
                )
            ):
                raise Blocked("BLOCKED: commands must be bounded argument lists")
            expected = "python" if language == "python" else manager
            if argv[0] != expected or len(argv) < 3:
                raise Blocked("BLOCKED: command does not match workspace toolchain")
            if language == "python":
                if argv[1] != "-m" or not re.fullmatch(
                    r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", argv[2], re.ASCII
                ):
                    raise Blocked("BLOCKED: Python module command required")
            elif argv[1] != "run" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:_-]*", argv[2]):
                raise Blocked("BLOCKED: named npm script required")
    if os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0":
        raise Blocked("BLOCKED: kill switch active")
    return document
